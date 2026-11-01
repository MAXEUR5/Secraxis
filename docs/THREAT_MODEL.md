# Secraxis Vault Manager — Threat Model

This is an honest statement of what Secraxis defends against, what it reduces,
and what it explicitly does **not** protect against. Overclaiming is treated
as a defect.

## 1. Assets

- Entry secrets: passwords, TOTP seeds, recovery codes, secret notes.
- The master password (never stored; only transiently in secure memory).
- The VMK (vault master key); derived subkeys.
- Secondarily: entry display metadata (names, usernames, URLs, tags) and
  structural facts (entry count, sizes).

## 2. Adversaries and what Secraxis does about them

### 2.1 Reduced / defended

| Adversary | Defense | Residual |
|---|---|---|
| **Offline attacker with the stolen `.seis` file** | Argon2id (384 MiB–1 GiB) over the master password and the vault's own random 32-byte salt, drawn at creation and again at every password or key change, so no precomputed table or guessing work carries from one vault to another; AES-256-GCM-SIV / XChaCha20-Poly1305 under 256-bit keys derived from a 512-bit VMK. Confidentiality+integrity rest entirely on AEAD. | Only as strong as the master password × the KDF cost. A weak master password is still guessable; Argon2id raises the per-guess cost, it does not add entropy. On POSIX a saved vault is mode 0600; on Windows it takes its folder's permissions, which on a drive other than the system's usually let every local user read it (an offline guessing target) or replace it: keep vaults under your user profile or in a folder only you can read. |
| **A weak, compromised or cloned OS random generator** (a copied virtual machine resumed twice) | Every random byte mixes the OS generator with the CPU's RDSEED (HKDF-SHA-512, both drawn fresh per call): the result is unpredictable if either source is. RDSEED is health-checked (start-up self-test, every word, repetitions), and without it nothing that needs random numbers runs. A counter, the time-stamp counter and the process id make clones of a process diverge even if both sources repeated. | RDSEED is trusted to be independent of the OS; a hostile processor is out of scope (2.2). A computer or virtual machine without a working RDSEED cannot open, create or save vaults. |
| **Tampering with a stolen file** (bit flips, region swaps, downgrade, rollback within a save) | Every crypto-affecting header field is AEAD-authenticated (AAD); manifest welds envelope+page tags; page reorder/deletion/truncation all fail. | Whole-file rollback to an *older, internally-consistent* vault the attacker previously saw is not detectable without external state (see 3). |
| **Parser-oracle / error-oracle attacker** | Verify-before-parse; wrong password, corruption, tamper, A2ONT mismatch, padding error, and canonical-parse failure ALL return one generic error. | Timing of Argon2id itself is uniform per profile; no fake sleeps. A wrong magic or format version, or an AEAD profile this build cannot run, is refused as unsupported before the KDF runs (the screen still shows the one generic message); those are public header fields. After the KDF, the time to the error shows how far the unlock got: a wrong password fails at the VMK envelope, a correct password with a damaged file only after the manifest and pages are decrypted. That tells someone timing an unlock whether the password opened the envelope, never anything about the password itself. |
| **Structure/length inference on the file** | A2ONT pre-encryption transform reduces locality; bucketed padding (64 KiB to 8 MiB, doubling, then 4 MiB steps) hides exact size/entry-count; exact password length never stored (coarse buckets). | The bucket still shows the size to within a factor of two (to within 4 MiB above 8 MiB); A2ONT is not a size oracle defense by itself (padding is). The public header also shows when the vault was created and last saved, and how many times it was saved (`epoch`). |
| **Casual memory scraping of the running process** | Secrets only in guarded, best-effort locked, wipe-on-free `SecureBuffer`s (on Windows the minimum working set is raised at startup, so the locking actually holds; `RUNTIME_MEMORY_SECURITY.md` §7); full plaintext vault wiped right after unlock; per-entry runtime sealing; moving-target re-sealing; short reveal windows. | Reduces residency/density/stable-address exposure — does NOT defeat a privileged in-machine attacker (see 2.2). |
| **Clipboard lingering** | TTL (20 s) + clear-if-still-ours; on Windows excluded from the clipboard history and the cloud clipboard. On Linux (with coreutils' `timeout`, standard there) the clipboard tool's serving process ends with the terminal and 5 s after the TTL at the latest, even if Secraxis is killed or crashes; inside tmux the paste buffers tmux keeps of a copy are deleted. Over SSH (or with no clipboard tool) the copy goes through the terminal (OSC 52) and the TTL clears it with an empty OSC 52, unconditionally, since it cannot be read back; terminals known to ignore OSC 52 get no copy and a message saying so. | The OS/other apps (clipboard managers) may snapshot the clipboard before the TTL clears it. If Secraxis is killed outright, an OSC 52 copy (over SSH) stays on the user's machine until something else is copied. An OSC 52 clear may also erase something the user copied within those 20 s. A terminal that logs session output (PuTTY/MobaXterm logging, `script`) records the OSC 52 sequence, i.e. the base64 of the copied password; do not log sessions in which you copy secrets. |
| **Clipboard read (Ctrl+V)** | The clipboard's text is read straight into a SecureBuffer (at most 64 KiB), fed through the bracketed-paste filter to the focused field only, and wiped; nothing is logged. Over SSH the program does not reach the user's clipboard at all and says how to paste instead. | Whatever was on the clipboard (possibly another secret) passes through the process while being pasted, like any typed input. |
| **Terminal scrollback / shell history leakage** | Alternate screen, no echo of the master password, no secret to argv/env, reveal cleared on timeout/mode-change, the terminal restored on every exit and hangup; on Windows QuickEdit is off so a stray mouse selection cannot freeze the screen (and the reveal timeout). | A malicious terminal emulator / screen recorder sees whatever is drawn (see 2.2). A crash (a bug: a guard-page hit, an uncaught exception) restores nothing: the alternate screen with whatever it showed, a revealed password included, and the mouse and paste modes stay until the terminal is reset (`reset`) or closed. |
| **Terminal injection through vault text** (an imported entry named `ESC ] 52 ; ...`, C1 `CSI`, bidi overrides that reorder what is shown) | All vault text passes one sanitizer before reaching a cell: controls, bidi controls, invisible format characters and ill-formed UTF-8 are drawn as placeholders. Frames are replayed in tests through a strict emulated terminal that rejects any sequence the writer did not emit; the `tui` fuzz target feeds hostile metadata at every size. | Right-to-left text is shown in logical order (the TUI does not apply bidi). |
| **Paste-triggered actions** (a pasted string containing `d`, `y`, newlines) | Bracketed paste marks pasted input; it reaches text fields only, with CR/LF/Tab/Esc removed, and can never run a command or confirm a deletion. Mouse clicks map to the same events as keys, and a marked paste cannot forge them: ESC is removed from pasted text, so it cannot carry a key or mouse report. | On Windows the console runs in VT input mode. Paste detection works in Windows Terminal on Windows 11 and in the classic console from Windows 11 24H2: both mark pastes like a POSIX terminal. The classic console's paste is tested on Windows 11 25H2 (build 26200, which shares 24H2's code base): a pasted `dy` in the list deletes nothing. Windows Terminal's own paste cannot be triggered from outside, so the drivers do not exercise it; its support comes from Windows Terminal's bracketed paste. The classic console of earlier Windows releases (Windows 10 included) cannot mark pastes (it gained bracketed paste in April 2023, microsoft/terminal #15155): there its paste arrives as typing and acts as keys (a pasted `dy` deletes the selected entry, saved at once with "save automatically"; pasted escape sequences are not removed). In a POSIX terminal without bracketed paste, pasted bytes likewise act as typed keys or mouse reports. |
| **Onlookers while a password is on screen** (reveal, show-while-typing in the entry form) | Both are explicit (`s`, or `Ctrl+R`/the `show` pill in the form), hide by themselves after 10 s (the form's after 10 s without typing) and when leaving the screen; the form shows only what is being typed, never the stored password. | Whoever sees the screen while a password is shown sees it. |
| **Someone reading the user's config folder** (`recent.json`, e.g. through a backup or sync) | The start page's history holds absolute vault paths and last-opened times only: no entry names, metadata or secrets. `x` forgets an entry and `--no-history` neither reads nor writes the file. Its parser is strict and bounded (fuzzed); a file it rejects is ignored. | It reveals where vaults are and when they were last opened. Someone who can write that folder can list any path; opening it still needs that vault's own password, and a vault the user did not create fails to unlock with theirs. |
| **Crash/torn write during save** | verify-before-rename + atomic rename; the previous file always remains valid (tested in 0.9.1 with 1,400 random kills during saves: 400 on Windows, 1,000 on Linux). Temp files left by interrupted saves (old copies, openable with the password they had) are removed by the next save. Creating a vault never replaces a file. | A filesystem that lies about durability can still lose the *latest* save; the old vault survives. |
| **Lost updates** (two windows on one vault, a sync tool replacing the file) | A save writes only over the save it loaded or last wrote; otherwise nothing is written and the user chooses: save a copy (both versions kept, the window goes on in the copy) or overwrite. If the vault's master password or keys were changed elsewhere (`passwd`, `rekey`, `upgrade`), no save of a window holding the old keys is written at all, not even as a copy: that would bring the old, perhaps leaked, password back (for an overwrite the user chose, checked again under the replace lock, so a key change that finished meanwhile is not undone). A vault reached through a symbolic link is saved in the file the link points to (resolved at each save); the link stays. The check and the rename run under a replace lock other Secraxis processes honor (POSIX `flock` on the vault; Windows an exclusive, delete-on-close `<name>.lock`), so two windows saving at the same moment cannot both "succeed" (before the lock they did, in every test round on Windows). | A sync tool does not take the lock: a version it puts in place between the check and the rename (the temporary file's write and flush, tens of ms) can still be overwritten. The lock is advisory between Secraxis processes; Windows and POSIX processes sharing one network folder do not see each other's. Saves through a symbolic link are tested on Linux only. |
| **Losing work when the terminal goes away or the screen locks** | Locking with unsaved changes asks: save and lock, discard and lock, or cancel. "Save changes automatically" (Settings) saves each change as it is made. When nobody can be asked, the user's setting decides: save (the default; to a copy beside the vault if it changed on disk or cannot take the save in place) or discard. That covers the idle lock and the terminal going away: SIGHUP, SIGTERM and an outside SIGINT; on Windows, closing the console, Ctrl+Break, log-off and shut-down (the last two reach a program that loads user32 only as window messages, so a hidden window listens for them). Either way the clipboard is cleared and the terminal restored; such a copy is listed among the recent vaults. Keys typed ahead of the save/discard question cannot answer it. | VTE-based terminals (GNOME Terminal and others) send SIGKILL 0.07 ms after SIGHUP when their window is closed: changes not yet saved are lost there unless "save automatically" is on (tested: then nothing is lost). If not even a copy can be written before the idle lock, that is reported, and the lock happens anyway. Windows gives a program about 5 s when the session ends: a save slower than that (a stalled drive) is cut off. The log-off path is tested by sending the program the session's end messages, not by logging off. |
| **Someone writing the user's config folder** (`settings.json`) | The settings file holds two choices (how changes are saved; what happens to unsaved ones when nobody can be asked), read by a strict, bounded, fuzzed parser; a file it rejects means the defaults. | Whoever can write it can choose "discard" for the user, so that an idle lock drops unsaved work (the lock screen says so), or "automatically". It holds no secret and cannot make the program write anywhere else. |
| **A vault on a stalled network drive** | The key is derived, and the file read, on a worker thread: Esc stops waiting, back to the password prompt, and the program can quit at once (an abandoned run gives up before the KDF and before putting anything in place, and wipes what it holds when its read returns). One KDF runs at a time, so retries never pile up Argon2 arenas. Going back to the start page from a vault that never opened does not re-check the listed files. | Other file checks still run on the interface thread (opening a vault from the start page, the list when the start page first shows, saving, locking), and wait as long as the drive does. The abandoned run keeps the typed master password in its SecureBuffer until its read returns or the program ends. |
| **DLL planting (Windows)** | The binary imports only Windows DLLs (the GCC runtime is linked in); at startup, library loading is limited to System32, images from remote shares or low-integrity files are refused, and so are legacy extension-point DLLs (AppInit_DLLs, Winsock LSPs). | Someone who can write System32 or the program's own folder is out of scope (2.2). Mind what that folder is: `bcrypt.dll` and `crypt32.dll` are not KnownDLLs and load at process start, before any startup code, from the program's folder first; on a drive other than the system's every user may create files in a new folder by default. Install Secraxis where only you and administrators can write. |
| **Malicious import/export files** | CSV/JSON parsers are total, bounded, capped, and fuzzed under ASan+UBSan (hundreds of millions of libFuzzer executions on each, most of them on the code before the 0.9.1 parser fixes, 0 findings; the minimized corpora are replayed by every test run). A CSV row of more than 64 fields, or a quote never closed, fails the import; field text is sized before it is filled and wiped after use; an import that cannot store a secret fails as a whole. The plaintext export is written only as a new file that only the user can read (0600; on Windows a protected DACL for the user alone), never over an existing file or through a link, and nothing of it stays behind if the write fails. | Import content itself is user-trusted data: fuzzing found no file that crashes the parsers or escapes their bounds, but garbage-in is stored as-is. A plaintext export is plaintext: anyone who can read it as that user (or as an administrator), or a backup of it, has every password. |
| **Very large vaults** (resource limits) | Each entry is held in two guarded allocations; when the system has no more to give, adding, opening or saving fails and says "not enough secure memory" (never "wrong password"), and the vault file is unchanged. | An open vault takes 8 memory maps per entry, and a save about 12 (15 with a TOTP secret), since it decrypts every entry at once. So on Linux, with the default `vm.max_map_count` (65530), a vault can be saved with up to about 5,500 entries (about 4,200 with TOTP secrets) and opened with up to about 8,000 (`sysctl vm.max_map_count=262144` raises the limit). Each entry also commits a few pages of memory, locked only within the system's lock limit (`RUNTIME_MEMORY_SECURITY.md` §7). |

### 2.2 NOT defended (explicit non-goals)

Secraxis does **not** claim protection against:

- A **malicious kernel**, hypervisor, or DMA-capable device.
- A **kernel-mode rootkit** or any code with the privilege to read process
  memory (`ptrace`, `/proc/pid/mem`, `ReadProcessMemory`).
- **Arbitrary code execution inside the Secraxis process** — once an attacker
  runs in-process, secure memory and moving-target sealing are moot.
- **Keyloggers** capturing the master password as it is typed.
- **Screen recorders / malicious terminal emulators** capturing revealed
  secrets or the rendered UI.
- **Cold-boot / bus-sniffing / co-located microarchitectural side-channels.**
- The **A2ONT seed resisting a cache side-channel adversary** co-located
  during the brief pre-AEAD window (A2ONT is not constant-time; out of scope
  per its own spec).

The correct one-line claim (agenda §3.2): *Secraxis reduces plaintext
residency time, secret density, stable-address exposure, accidental leakage,
parser-oracle leakage, and ordinary user-space scraping opportunities. It does
not create an absolute secrecy boundary once the execution environment is
fully compromised.*

## 3. Rollback / deletion durability boundary

Deleting an entry (and saving) removes it from the live model and the newly
written file, but **cannot** erase copies that already left Secraxis's
control: filesystem snapshots (VSS/APFS/btrfs/ZFS), journals, CoW remnants,
freed blocks of prior atomic-save generations (SSDs make scrubbing
unreliable), backups, cloud-sync copies, swap/hibernation from past sessions,
or anything exported/copied out. Old copies of the vault file remain
protected by the encryption they were written under; plaintext exports,
clipboard copies, and memory written to swap or a hibernation file may hold
plaintext. Secraxis also cannot tell an old, internally consistent copy from
the current file: someone who puts one back in its place (a whole-file
rollback) is not detected without external state.

Correct responses: rotate the real credential if a secret is exposed. If the
master password is compromised, change it (`passwd`) and then rekey (`rekey`,
a fresh VMK): `passwd` alone keeps the VMK, which anyone with the leaked
password and an old copy of the file can recover. Treat old file copies as
crackable under the old password. Full detail in `ENTRY_LIFECYCLE.md` §3.1.

## 4. Trust assumptions

- At least one of the two random sources is sound: the OS CSPRNG (libsodium
  `randombytes_buf`) or the CPU's RDSEED, mixed by HKDF-SHA-512 on every draw
  (`CRYPTO_PROFILES.md` §5). RDSEED must be present and pass its health
  checks; otherwise nothing that needs random numbers runs. (A2ONT's seed,
  which carries no security, comes from the OS generator alone.)
- The vetted libraries (libsodium, OpenSSL/AWS-LC libcrypto, Argon2 reference)
  are correct; we pin them by hash and gate them with official KATs.
- The machine is not already compromised at or above the Secraxis process's
  privilege level at the time of use.
- A2ONT is a reversible pre-encryption transform, **not** encryption; AEAD is
  the sole confidentiality/integrity boundary.
