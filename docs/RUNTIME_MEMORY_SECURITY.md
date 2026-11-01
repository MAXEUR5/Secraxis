# Runtime Memory Security

How Secraxis handles secrets in process memory, and — honestly — the limits of
that handling.

## 1. SecureBuffer: the only long-lived home for secrets

Every secret (master password, KEK, VMK, subkeys, page keys, A2ONT seed,
canonical plaintext, entry secrets, clipboard scratch, export plaintext) lives
in `SecureBuffer` (`src/platform/secure_buffer.cpp`), backed by libsodium's
guarded allocator:

- placed right before a **guard page**, with a canary in front: an overflow
  faults at once, and an underflow is caught by the canary when the buffer
  is freed, instead of corrupting memory silently;
- **best-effort locked** (`sodium_mlock` → `mlock`/`VirtualLock`; §7 says
  how far that goes) and flagged no-dump (`MADV_DONTDUMP`) where available;
- **zeroized on free** (`sodium_free` wipes before unmapping);
- **move-only**, no implicit copy (only an explicit `clone()`, each call of
  which is an audit point), no stream/serialize operators, no implicit
  `std::string` conversion;
- **constant-time** equality via `sodium_memcmp`.

`std::string`/`std::vector<uint8_t>` (`Bytes`) hold **non-secret** data only
(ciphertext, display metadata). Mutation scratch that briefly holds metadata
is explicitly `secure_wipe`d. Copies of secrets outside SecureBuffers are
transient: the KDF arena (§3), the drawing path and the clipboard (§6), and
the crypto libraries' own working state during a call.

## 2. Process hardening (startup, before any secret)

`apply_process_hardening()`:
- **Linux**: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS`.
- **Windows**: `SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX)`;
  DEP + ASLR + high-entropy-VA at link (`--nxcompat --dynamicbase
  --high-entropy-va`); libraries load from System32 only
  (`SetDefaultDllDirectories`, `SetDllDirectory("")`); image-load policy:
  no remote or low-integrity images, System32 copies preferred; legacy
  extension-point DLLs refused. The binary imports only Windows DLLs (the
  GCC runtime is linked in with `-static`), so a DLL planted in the current
  folder or on PATH is never loaded into the process that reads the master
  password. The program's own folder is another matter: Windows looks there
  first for `bcrypt.dll` and `crypt32.dll` at process start (`THREAT_MODEL.md`,
  DLL planting).

All best-effort: a step that fails is skipped without a message; it is
never fatal.

## 3. KDF arena

The Argon2id arena (up to 1 GiB) is allocated separately, best-effort locked +
no-dump, and **wiped on release** (in addition to Argon2's own clearing).
Lock failure is the rule at default limits (Linux's `RLIMIT_MEMLOCK` and
Windows' default working set are far smaller than the arena); it is not
fatal and not shown, and the arena is still marked no-dump where available
and wiped. The arena is never exposed to the UI thread.

The unlock runs on a worker thread that owns the typed master password (a
SecureBuffer moved to it). Esc while unlocking abandons that run: the UI
returns to the prompt at once, and the worker, which may still be blocked
reading a vault on a stalled drive, keeps the password until the read
returns; then it skips the KDF (and, when creating, the write), wipes the
password and its result, and ends. If the program quits first, it waits up
to 2 s for such a run and then ends the process without exit-time cleanup
running under the thread; the password's pages go with the process.
Only one KDF runs at a time (a process-wide lock in `argon2id_raw`): a run
abandoned during its KDF finishes it before the next starts, so retrying
never holds two arenas at once, and the arena's locked/unlocked record,
which the Argon2 callbacks keep process-wide, always belongs to the one
running.

## 4. Runtime sealed store (post-unlock)

After unlock, Secraxis does **not** keep the full canonical vault as a
long-lived object tree (agenda §12). The flow: decrypt pages → A2ONT inverse →
short-lived canonical buffer → parse → **seal each entry** into per-entry
AEAD segments → **wipe the canonical buffer**. Long-lived runtime state is only
sealed metadata + sealed secret segments per entry, keyed from a runtime root
derived from the VMK and a **fresh per-session process nonce**, plus the keys
themselves (the VMK and its PRK, kept for saving, and the runtime root), each
in a SecureBuffer until the vault locks. The runtime PRK's salt carries the
second line of Secraxis's verse ("Nothing that rests goes unseen, so the
keys never rest."), a public constant in memory only. A re-seal or edit
seals into fresh regions first and wipes the old ones only once the new ones
exist, so a seal that fails (no secure memory, no random numbers) leaves the
entry as it was.

The random-number generator's working buffer (both sources' bytes, its PRK
and stream seed; `CRYPTO_PROFILES.md` §5) is a SecureBuffer too, wiped after
every draw.

Metadata and secrets are sealed **separately**: overview/query decrypt only
metadata; secret segments open only for entry-scoped actions (reveal/copy/
edit/save/export).

## 5. Moving-target re-sealing (agenda §12.4)

Sealed segments are re-encrypted, periodically and on events, under a fresh
reseal epoch into freshly allocated regions, with the old regions wiped and
freed. Triggers: access-count threshold (every 4 secret opens), after
reveal/copy, after edit, after save, on manual refresh (`r`), and every 60 s
while a vault is open. This reduces stable-address exposure and secret
density over the session lifetime.

## 6. UI exposure control

Reveal is entry-scoped and TTL-limited (10 s; hides on timeout, Esc, any
key, selection/mode change) with the plaintext in one machine-owned
SecureBuffer that is wiped on hide. Clipboard copy uses a TTL (20 s) +
clear-if-still-ours + (Windows) "exclude from history/cloud" hints. "Still
ours" is decided by a fingerprint of the copy: BLAKE2b keyed with a random
key that never leaves secure memory, so the fingerprint, which sits in
ordinary memory, says nothing about the copied secret without it. The
master password is never echoed, never passed via argv/env, and the
alternate screen keeps secrets out of scrollback (it is left, and the
terminal restored, on every exit and hangup, though not after a crash:
`THREAT_MODEL.md` §2.1). The render model carries the secret only in the
explicit reveal field (checked by
`no_secret_in_render_model_outside_reveal`), and, while the add/edit form's
passwords are shown (`Ctrl+R`), in the form fields' `reveal` views: views
into the form editors' own SecureBuffers, never copies, cleared from the
model when the form hides them (TTL 10 s without typing) or closes
(`form_secret_appears_only_when_shown`). Hidden form passwords expose only
character counts.

Clipboard paths that carry secrets stay in secure memory up to the clipboard
itself: Ctrl+V reads the clipboard's text straight into a SecureBuffer
(bounded at 64 KiB; on POSIX the clipboard tool's output is read into one,
with no growing string left behind) and wipes it after feeding the field; a
copy is written from secure memory straight into the clipboard's own memory
block (Windows; zeroed when the program clears its copy) or into the
clipboard tool's pipe (POSIX); a copy through the terminal (OSC 52) is
base64-encoded into a SecureBuffer, written, and wiped. What the clipboard,
its tool or the terminal then holds is outside the process.

A search opens every entry's metadata segment (never the secrets). It
reuses one key buffer and one plaintext buffer, both SecureBuffers, for the
whole search, wiping each after every entry, instead of allocating two
guard-paged buffers per entry: the same protection, a quarter of the time.

While a secret is shown it also passes through the drawing path: the
renderer writes it straight from the machine's buffer into canvas cells (no
intermediate strings), the frame writer keeps a mirror of the screen, and the
bytes for the terminal sit in an output buffer. The canvas and mirror are
wiped whenever they are reset, resized or released; the output buffer
(`WipeBuffer`) wipes every block it truncates or outgrows; the input decoder
wipes consumed bytes (a paste may carry a password). The terminal emulator's
own memory is outside the process and out of scope (`THREAT_MODEL.md` §2.2).

## 7. Honest limitations

- **Best-effort, not guaranteed.** `mlock`/`VirtualLock` can fail, and the
  system caps how much a process may lock.
  - **Windows.** `VirtualLock` locks no more than the minimum working set
    allows. Windows' default (200 KB) let it lock only 44 pages (measured
    on Windows 11), so until the 0.9.1 release review all but a few dozen
    secure buffers went unlocked. At startup the program now raises the minimum
    working set to 64 MiB (`apply_process_hardening`), room for the secure
    memory of about 8,000 entries at two locked pages each. Measured: 4,000
    of 4,000 buffers locked; the test
    `secure_memory_is_locked_beyond_the_default_quota` checks 600 of 600.
    The running release program reports a 64 MiB minimum.
  - **Linux** applies `RLIMIT_MEMLOCK` (often 8 MiB), which an unprivileged
    program cannot raise past its hard limit.

  Secure memory past the cap is still guarded and wiped, but can be paged
  out. The OS may also page or snapshot memory (hibernation writes even
  locked pages); guard pages catch overflow, not reads by a privileged
  observer.
- **No defense against in-machine privileged adversaries.** A malicious
  kernel, rootkit, DMA device, debugger with `ptrace`/`ReadProcessMemory`, or
  code executing inside the Secraxis process can read secrets regardless of
  any of the above. Moving-target sealing raises the effort/precision needed;
  it does not create a boundary against such an adversary.
- **No garbage collector, but not leak-proof by construction.** We rely on
  disciplined ownership + RAII + explicit wipes; the fuzzing and sanitizer
  runs (ASan with LSan, UBSan, MemorySanitizer, ThreadSanitizer) reported no
  leak, use-after-free, uninitialized read or data race, but memory safety in
  C++ is a property maintained by review and testing, not guaranteed by the
  language.
- **Wipe elision.** Wipes go through calls compilers cannot optimize away:
  libsodium's `sodium_memzero`; in the A2ONT C code `SecureZeroMemory`
  (Windows) or `explicit_bzero` (Linux); in the Windows clipboard code
  `SecureZeroMemory`.

The correct claim: Secraxis **reduces plaintext residency time, secret
density, and stable-address exposure, and limits UI/clipboard leakage**. It
does not guarantee secrecy once the execution environment is compromised.
