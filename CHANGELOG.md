# Changelog

All notable changes to Secraxis Vault Manager. Dates are absolute.

## [0.9.1] — 2026-11-01

Everything since 0.1.0, for Windows 11 and Linux. `RELEASE_NOTES.md` has
the summary and the binaries' checksums. Below, the first section is the
release review; the sections after it are the rounds that led up to it.

### Release review (2026-10-31)
Three independent AI code reviews (crypto and format; parsers and CLI;
terminal, clipboard and platform), the release gates, a final check of
every document against the code, and a last review of the security design
found the issues below. Each fix has a test that fails without it (each was
put back once to check: 40 of 40 caught),
on Windows and Linux, plus MemorySanitizer and ThreadSanitizer.

**Your data**
- Editing an entry with a new password dropped its TOTP seed, recovery codes
  and secret note (an import can store a TOTP seed). They are kept now.
- Saves and key changes through a symbolic link to the vault replaced the
  link with a new file (the TUI on Windows; `passwd`, `rekey`, `upgrade` and
  `import` everywhere), leaving the real vault, in a synced folder say, with
  the old password while the command reported success. The file the link
  points to is what is changed now.
- After `passwd`, `rekey` or `upgrade` in another program, a window still
  holding the old keys could write them back (on save, at the idle lock, or
  into a conflict copy), restoring the old, perhaps leaked, password. Such a
  save is now refused and the window says why. An overwrite chosen in the
  save-conflict dialog could still undo a key change that finished while the
  new file was being built; it is now checked again under the replace lock.
- On Windows almost none of the secure memory was locked: `VirtualLock` can
  lock only as much as the minimum working set allows, 200 KB by default (44
  pages, measured), and the program never raised it, so secrets beyond the
  first few dozen buffers could be paged out to disk. The minimum working set
  is now raised to 64 MiB at startup (4,000 of 4,000 buffers locked,
  measured; the running release program reports the 64 MiB minimum).
- Out of secure memory, an import dropped secrets silently, an entry could be
  stored without its password, and creating a vault could go ahead with an
  empty master password. Each now fails and says so. It is no longer
  reported as "wrong password" either. The core refuses to create a vault
  with an empty master password, and `passwd` refuses an empty new one (or
  one longer than the vault screen accepts).
- On Windows, logging off or shutting down lost unsaved work: the console
  sends those events only to programs that do not load user32, and this one
  does. A hidden window now hears them, so the work is saved (or discarded,
  as set) and the clipboard cleared, as when the console is closed.
- Very large vaults on Linux: an open vault takes 8 memory maps per entry,
  and a save about 12 (15 with a TOTP secret), because it decrypts every
  entry at once (measured). So the default `vm.max_map_count` (65530) lets a
  vault be saved with up to about 5,500 entries (4,200 with TOTP secrets) and
  opened with up to about 8,000. Beyond that the screen now says "Not enough
  secure memory", for a save "Not saved: not enough secure memory" (it said
  only "Save failed"), never "wrong password"; the file is unchanged
  (documented in `THREAT_MODEL.md` and `MANUAL.md`).

**Exports and backups**
- `export-plaintext` wrote through an existing file (the vault itself, or a
  link), kept that file's permissions, and on Windows the new file took the
  folder's (readable by every user on most non-system drives). It now writes
  a new file only: mode 0600, or on Windows a protected DACL that grants the
  current user alone. A failed write leaves nothing behind, and the body is
  built in secure memory (a growing buffer left copies of every password in
  freed memory).
- `backup` read the vault twice: the copy written could differ from the one
  checked against the password. It also replaced any existing file. It now
  writes exactly the bytes it checked, and only to a new file.

**Import parsers**
- A CSV file that starts with a UTF-8 byte-order mark (Excel and many
  password managers write one) lost its first column without a word, often
  the entry names: the mark hid the column's name. Both importers now skip
  the mark.
- A CSV row with more than 64 fields was split, and the rest was read as the
  next row, out of step with the columns. A quote never closed took the rest
  of the file into one field. Both now fail the import.
- Header names with a long run of spaces took quadratic time (minutes for a
  large file).
- CSV fields and JSON values (passwords among them) are sized before they
  are filled and wiped after use, so no copies stay behind in freed memory.
- The canonical decoder no longer reserves room for an entry count that the
  bytes cannot hold.

**Terminal, mouse and clipboard**
- A click read together with keys waited for the next frame, but then acted
  there even if that frame showed something else. A dialog that opened
  meanwhile (`d`, then a click where its Delete button appears) could be
  answered unseen. The click now acts only if it means the same there as on
  the frame the user clicked; otherwise it is dropped.
- Linux (and the macOS code, not built for this release): if the
  clipboard's owner never answered (a hung program, a
  stuck VM or remote-desktop bridge), reading the clipboard waited forever,
  freezing the screen with the vault open, also at each clear and the idle
  lock. Reads now give up after 2 s.
- Windows: a clipboard another program held open made the timed clear give
  up after one try while saying "Clipboard cleared." The clear is now
  retried every second, also after the vault locks, and the screen says it
  is waiting. A copy Windows did not take is no longer reported as copied.
- The hidden password prompt of the subcommands left echo off when it was
  interrupted (Ctrl+C or Ctrl+Break, the console closing, SIGTERM, SIGHUP);
  it now gives it back. On Windows it requires a real console, as on Linux.
- The fingerprint by which the clipboard recognizes its own copy of a
  password (to clear it only while it is still there) was BLAKE2b under a
  fixed key, kept in ordinary memory: in effect a fast hash of the
  password, so one written to swap or a dump let anyone test guesses of a
  weak password offline. Its key is now random and kept in secure memory,
  and a copy whose fingerprint cannot be made is refused.

**Cryptography and format robustness**
- AES-256-GCM-SIV availability is checked at run time: an OpenSSL older than
  3.2 links but cannot provide it. Such vaults are now refused as unsupported
  before the key derivation (the screen shows its one generic message), and
  new vaults use XChaCha20-Poly1305 there.
- Creating a vault now opens the envelope it just sealed. `rekey` proves the
  new file opens with the password before it replaces the old one (as
  `passwd` and `upgrade` already did).
- The test builds' weak-KDF marker string survives optimization now, so the
  release check that shipped binaries lack it can actually fail.
- Random numbers come from two independent sources: every draw mixes 64
  bytes from the operating system's generator with 64 from the processor's
  RDSEED through HKDF-SHA-512, so a weak, compromised or cloned system
  generator (a copied virtual machine) no longer decides a key alone. The
  extract salt carries a line of Secraxis's own verse, "Every watcher lies
  alone; two liars cannot lie as one."; a counter, the time-stamp counter
  and the process id enter only HKDF's `info`, so clones diverge. RDSEED is
  health-checked (a start-up self-test, every word, repetitions) and there
  is no fallback: without a working RDSEED, opening, creating, changing and
  saving vaults are refused, before any password is tried
  (`CRYPTO_PROFILES.md` §5). The in-memory keys' salt carries the verse's
  second line, "Nothing that rests goes unseen, so the keys never rest."
- A failed re-seal or edit of an entry in memory (out of secure memory, or
  now without random numbers) wiped its old sealed copy before the new one
  existed, so the open session lost the entry's secrets. The old copy is now
  kept until the new one exists.

**Platforms and documentation**
- 0.9.1 is released for Windows 11 and Linux. Windows 10 and macOS are out
  of scope for this release: Windows 10 was only checked statically, and the
  macOS code paths are neither built nor tested.
- Paste detection, stated precisely: the classic Windows console supports
  it starting with Windows 11 24H2, and Windows Terminal supports it on
  Windows 11. The classic console gained bracketed paste only in April 2023
  (microsoft/terminal #15155), so in older ones, Windows 10's included, a
  pasted `dy` in the list deletes the selected entry. `THREAT_MODEL.md`,
  `TUI_SPEC.md`, the README and a code comment had said the classic console
  marks pastes everywhere. The classic console's paste is tested on Windows
  11 25H2 (24H2 shares its code base), now also in the default hidden-console
  runs and on the release `.exe`. Windows Terminal's paste cannot be
  triggered by the test drivers.
- A documentation check against the code corrected, among others: the
  format spec's save order and checks, the advice for a leaked master
  password (`passwd`, then `rekey`: `passwd` alone keeps the vault key), the
  install folder on Windows (Windows searches the program's folder first for
  two system libraries), the unconditional clipboard clear over SSH, and
  build reproducibility (the Linux build is bit-for-bit reproducible; the
  Windows `.exe` is not).
- New user documentation: a short `README.md`, the user manual `MANUAL.md`
  (installation, everyday use, the command-line tools, troubleshooting), and
  `RELEASE_NOTES.md`. The Linux build instructions now build the pinned
  libsodium and OpenSSL. The old `-DSECRAXIS_OPENSSL_ROOT=/usr` line failed
  on Debian and Ubuntu (multiarch library folders), and their packages are
  too old: libsodium 1.0.18, where 1.0.19 or later is needed, and on Ubuntu
  24.04 OpenSSL 3.0, which lacks AES-256-GCM-SIV. The new recipe was run in
  a fresh folder: 0 warnings, 21 of 21 tests.
- How to report a vulnerability: through GitHub Issues, as `SECURITY.md`
  now describes; the README and the manual name the same channel. Issues
  are public, so a report leaves out passwords, vault files and other
  secrets.
- `THREAT_MODEL.md` now also says that the public header shows when a vault
  was created and last saved and how often it was saved, and that after the
  key derivation the time an unlock takes to fail shows how far it got
  (never anything about the password). `CRYPTO_PROFILES.md` writes the page
  keys out exactly, and says that an AES-256-GCM-SIV vault opened on a CPU
  without AES-NI/CLMUL runs OpenSSL's software AES, which is not guaranteed
  constant-time.
- The Secraxis logo, banner and brand sheet (`docs/assets/`, SVG, designed
  with GPT-6). The identity is flat and geometric: the wordmark's rounded
  corners are cut at 45 degrees like the brackets', and the brand sheet's
  panels are square. The README opens with the banner, and on dark pages
  with `secraxis-horizontal-dark.svg` (the banner recolored the way the
  designer recolored the dark icon). The Windows program carries an icon
  made from the logo: the mark on an Ink square with the same 45-degree
  corner cuts, so it reads on light and dark backgrounds
  (`secraxis-app-icon.svg`, rendered at 16 to 256 pixels into
  `src/secraxis.ico`).
- The terminal interface follows the same language: panels have square
  corners in every glyph set, and the "unsaved" and two-step confirmation
  markers are squares (`■ □`) instead of circles.

**Tests added**
- Unit tests for each fix above.
- Header reserved bytes with a valid CRC, header timestamps bound to the
  ciphertext, `rekey` drawing a fresh VMK and `passwd` keeping it.
- A fresh KDF salt for every vault and every key change (`passwd`,
  `rekey`, `upgrade`): one password in two vaults derives two different
  keys, so no precomputed table or guessing work carries between vaults.
- Byte-exact CSV and JSON export bodies, and fuzz-corpus replay tests
  (`fuzz_replay_*`).
- New end-to-end steps:
  - `win_prompt`: the prompt's echo after Ctrl+Break.
  - `win_hangup` part 3: the session ending.
  - The scenarios now start from default settings, and the hangup scenarios
    check that autosave is off before trusting the save they test.
- New `console_drive` commands: `end-session` and `expect-echo`. Script
  lines can name several hosts (`[conhost,hidden]`), so the classic
  console's own paste is checked in hidden runs too.
- The `canonical` fuzz target now checks that every accepted input
  re-encodes to the same bytes (the codec's one-encoding rule).

**Checked** (details in `docs/TESTING_AND_FUZZING.md`)
- 21 of 21 tests on Windows and Linux, and on Linux under ASan+UBSan,
  ThreadSanitizer and MemorySanitizer (instrumented libc++, libsodium and
  OpenSSL); no report.
- libFuzzer: 2.5 hours on all eight targets (17.51 billion executions) and
  20 minutes after the review's parser fixes (2.38 billion), then 15 minutes
  each on the final `canonical`, `csv` and `json` targets (223 million): no
  crash or out-of-memory. Five `tui` inputs that save 25 to 46 times in a
  row passed the 30 s limit under the sanitizers; replayed, they finish. The
  minimized corpora (3,466 inputs) are now in the repository and replayed by
  every test run.
- End to end on the final code: Windows 222 of 222 checks in 7 scenarios
  (and the release `.exe` itself 60 of 60, the classic console's own paste
  included); Linux 214 of 214 in 7.
- Random kills while saving, on the final code: 400 on Windows, 1,000 on
  Linux (and 2,800 on the code before); nothing lost.
- clang-tidy (482 warnings) and cppcheck (7) on the final code: no defect.
- The Clang Static Analyzer and CodeQL on the final code: the same results
  as before the random-number mixer, apart from one CodeQL maintainability
  note (the clipboard fingerprint's 32-byte array parameter); nothing in
  the mixer.
- Building from source as `MANUAL.md` says, in a fresh folder on Ubuntu
  24.04: 0 warnings, 21 of 21 tests. Two Linux release builds in different
  folders are bit-for-bit identical.
- Static analysis replacing Coverity, on the Linux and Windows code (the
  Windows code through a MinGW cross build): the Clang Static Analyzer's
  stable and alpha checkers, CodeQL 2.27.3 (`security-and-quality`,
  `security-experimental`) and GCC's `-fanalyzer` on the A2ONT C code, re-run
  on the final code with the same results. No defect: every finding is a
  false positive or a style note (triaged in `TESTING_AND_FUZZING.md`).
- The program under the sanitizers in real terminals: the Linux end-to-end
  scenarios with the ASan+UBSan build (192 of 192 checks) and the TSan build
  (173 of 173). No report.
- Windows 10 (out of scope), statically only: every function the release
  `.exe` imports exists there. It has not been run on Windows 10.

### Saving: your choice, and nothing lost by accident (2026-10-31, round 5)
Owner direction: both automatic and explicit saving; closing with unsaved
changes asks. Each change below has a test that fails without it.

**Added**
- Locking a vault with unsaved changes (`q`) asks: save and lock, discard and
  lock, or cancel. `Enter` saves (the choice that loses nothing); a paste or
  a second `q` chooses nothing. Before, `q` `q` locked without saving.
  Saving into a vault that changed on disk opens the conflict dialog first,
  and the vault locks only once something was saved.
- Settings (`o` in a vault), kept in `settings.json` in the config folder
  (strict parser, fuzzed): "Save changes" when you press `w` (default) or
  automatically, every added, edited or deleted entry saved at once; and
  what happens to unsaved changes when nobody can be asked (the idle lock,
  the terminal going away): save them (default) or discard them. With
  "automatically", closing a GNOME Terminal (VTE) window, which kills the
  program at once, loses nothing (tested).
- `Esc` while unlocking stops waiting (a vault on a stalled network drive
  could block the read for minutes): back to the password prompt, and the
  program can quit at once. The abandoned run skips the key derivation and
  any write, and wipes what it holds when its read returns.

**Fixed**
- Two windows saving the same vault at the same moment could both "succeed":
  each passed the unchanged-check before either renamed, and one window's
  reported save vanished (measured: in 12 of 12 test rounds on Windows, 6 of
  12 on Linux; the window was the temporary file's write and flush, not
  milliseconds as documented before). The check and the rename now hold a
  replace lock other Secraxis processes honor (POSIX `flock` on the vault;
  Windows an exclusive, delete-on-close `<name>.lock` that never deletes a
  file it did not make). Exactly one of the two saves writes; the other is
  told the vault changed.
- After "save a copy" the window showed the copy, but locking and unlocking
  again opened the original file (and later saves went there): introduced
  in the previous round, found in this round's review. The window now
  unlocks, saves and records in the history the file it is on.
- The end-to-end driver on Linux crashed now and then after closing a VTE
  widget (an event delivered to the destroyed widget; found with gdb).
- Over SSH to a busy host the program sometimes started in its plain ASCII
  look, or drew Chinese names as `?`: the startup probe matched the
  terminal's cursor reports to its questions by order alone, so one late
  answer shifted every later measurement. Each probe step now asks on a row
  of its own and sets aside answers from other rows, stops trusting answers
  after a timeout, and waits longer over SSH (6 of 11 test runs failed
  before under load, 0 of 8 after; local terminals unchanged).

**Fixed after an independent review of this round's code** (each fix put
back once to show its test catches it)
- Short windows (40x12 and the like) cut the Settings dialog's second item,
  which the keys could still change unseen. Items now always show; only
  explanations give way.
- Keys typed ahead of the unsaved-changes question could answer it: `q` and
  `d` arriving together discarded the changes before the question was ever
  drawn. Keys read together with that `q` are now dropped.
- An unattended save that could not go in place (for example another save of
  the vault stuck for more than the 3 s a save waits) dropped the work. It
  now goes to a copy beside the vault, as for a vault changed on disk.
- A copy made for the user (conflict, idle lock, hangup) never appeared on
  the start page, so after a hangup nobody saw, the work was hard to find.
  Copies are now added to the recent vaults.
- Esc during the write of a new vault (a stalled drive) could still create
  it: the write now stops before anything is put in place. If a vault does
  appear (another program), creating says so and offers to unlock it.
- Each Esc-and-retry could start another key derivation beside one still
  running (up to 1 GiB each). Derivations now run one at a time.
- An Esc pressed as an unlock finished could become an Esc on the lock
  screen (leave): the result is now taken after the keys, so it cancels.
- Leaving a vault that never opened made the start page re-check every file
  it lists, which a stalled drive would hold up; it now does so only after
  a vault was open.
- Before writing, leftovers of interrupted saves are now removed (after the
  rename, another save could already be writing its temporary file there).
- A lock file of ours left by a power loss is now deleted through the
  handle that checked it, so no other file can take its place in between.

**Checked**
- clang-tidy 18 and cppcheck 2.13 over all product sources: no defects
  (472 and 7 warnings on the final code, triaged in `TESTING_AND_FUZZING.md`).

### Deep testing: work never lost, input, clipboard, Windows hardening (2026-10-31)
Found by new tests, an independent code review, fuzzing and experiments on
both platforms. Each is fixed and covered by a test that fails without the fix.

**Your work**
- A save no longer silently overwrites a vault that another window or a sync
  tool saved meanwhile: nothing is written, and the TUI asks: save a copy next
  to the vault (both versions kept; the window goes on in the copy),
  overwrite, or back. `passwd`/`rekey`/`upgrade`/`import` say so instead of
  "wrong password", and also report a failed write as one.
- The idle lock (5 minutes) dropped unsaved changes without a word. It now
  saves them first (to a copy if the vault changed on disk) and says so.
- Closing the terminal, a dropped SSH connection, SIGTERM/SIGHUP, and on
  Windows closing the console or Ctrl+Break ended the program on the spot:
  unsaved changes were lost and a copied password stayed on the clipboard.
  Now the work is saved, the clipboard cleared and the terminal restored
  (within 5 s). VTE terminals (GNOME Terminal and kin) kill the program
  0.07 ms after the hangup when their window is closed (measured), so
  nothing can be saved there; documented.
- Interrupted saves left their temporary file behind (5 per 200 kills on
  Windows): whole copies of the vault, still openable with an old master
  password after it was changed. The next save now removes them.
- Creating a vault could replace a file that appeared while the key was
  derived; creation never replaces a file now.

**Input and mouse** (independent review)
- Terminals without SGR mouse mode send old-style reports whose bytes were
  read as keys: one click could open the delete dialog and confirm it, and
  the release did it again to the next entry. They are decoded as clicks.
- A timeout inside an escape sequence broke it apart: a paste's start marker
  split by the network ran the paste as commands, a split end marker left
  input stuck in paste mode (POSIX), and a split UTF-8 character was
  dropped. Incomplete sequences now wait for their rest; a lone ESC still
  resolves at once.
- A click read together with keys was matched against the previous frame:
  `d` and a click could delete an entry without the dialog ever being drawn.
  The click now waits for the next frame.
- A double-click on a form field pressed Enter and committed the form; only
  list rows open on double-click.
- Editing an imported entry cut its remark, URL and tags to 256 bytes,
  possibly inside a character; each editor now holds its field's limit.
- After a failed folder listing the browser could act on stale filtered rows.

**Clipboard**
- Inside tmux (`set-clipboard on`) a copied password stayed in tmux's paste
  buffers after the timeout and after exit (tmux ignores an empty OSC 52).
  The clear now sends a blank and deletes those buffers.
- On Linux the clipboard tool now serves a copy in the foreground under
  `timeout`: the copy is gone 5 s after the clipboard timeout at the latest,
  even if Secraxis is killed or crashes (before, it stayed until something
  else was copied).
- Windows copies are also flagged not to go to the cloud clipboard.

**Windows release**
- The executable needed MinGW's `libstdc++-6.dll` and `libgcc_s_seh-1.dll`:
  it would not start without MinGW, and Windows looks for such DLLs in the
  current folder before PATH, so a planted DLL could run inside the program
  that reads the master password. The GCC runtime is now linked in (only
  Windows DLLs are imported), and at startup library loading is limited to
  System32, refusing images from remote shares or low-integrity files and
  legacy extension-point DLLs.

**Testing**
- `exp_crashsave` kills a saving process at random moments: 1000 times on
  Linux and 400 on Windows, no acknowledged save lost, no torn vault, no
  temporary file left. Hangup and conflict scenarios on both platforms.
  Property tests: every split point of every escape sequence, with timeouts
  in between; every old-style mouse report. A mutation check put each of six
  input bugs back, one at a time: every one was caught.
- libFuzzer builds now instrument all the code (the libraries had no
  coverage counters: 881 counters before, 21,212 after); a race between
  fuzzers sharing a folder was fixed. Static analysis: clang 18's analyzer
  over all 47 project files, one finding (a harmless dead store).

### Paste, Windows look, Linux and SSH (2026-10-31)
- **Ctrl+V pastes** into every text field (the search, the entry form, the
  master-password prompt, the start page's path and name fields): from the
  Windows clipboard, from `wl-paste`/`xclip`/`xsel`/`pbpaste` on a local
  display, and over SSH the status line says how to paste with the terminal.
  The text goes through the bracketed-paste filter (newlines and tabs
  dropped) and lives only in secure memory.
- **Fixed (security): on Windows a paste in the list acted as typed
  commands.** Pasting "dy" deleted the selected entry. The console now runs
  in VT input mode, where Windows Terminal and the classic console (from
  Windows 11 24H2) mark pastes, and pasted text reaches text fields only, as
  on Linux.
- **The classic Windows console looks like the rest.** Its default font on
  Chinese, Japanese and Korean systems (新宋体 and kin) drew accented letters
  and most symbols two cells wide, so the app used ASCII stand-ins and
  accented text spread apart. The console now switches to Consolas for the
  session (its font comes back on exit; `--keep-font` keeps it) and uses the
  full symbol set. Where the font cannot be changed (SSH into such a
  console) the first screen says how to get the full look.
- **Linux and SSH:**
  - The probe asks the terminal what it is (XTVERSION, DA2), so SSH sessions,
    where no environment variable crosses, get the same symbols, 24-bit
    colour and emoji as local ones. Every UTF-8 terminal gets the full set
    (still measured glyph by glyph); the Linux text console and PuTTY the
    plain one; xterm gets 256 colours although it says `TERM=xterm`.
  - Copy works over SSH: the terminal's own clipboard through OSC 52
    (verified into the Windows clipboard from Windows Terminal and the
    classic console), cleared after 20 s. Terminals that ignore OSC 52 (GNOME
    Terminal's VTE, xterm's defaults) get a clear "cannot copy" with what
    would help, never a false "copied"; inside tmux the note says it needs
    `set-clipboard on`.
  - A C/POSIX locale (common on SSH logins) no longer forces ASCII when the
    terminal decodes UTF-8 (measured).
  - A glyph the terminal draws too wide falls back to its plainer form
    before ASCII (a lozenge for the diamond, square corners for rounded).
- **Smoother:**
  - Everything already typed or pasted is handled before the next frame.
  - Live search narrows as the needle grows, runs after the keystroke's
    frame on large vaults, and opens entries with reused secure buffers:
    20 ms instead of 88 ms per search on 5,000 entries, with the typed
    character on screen in under 1 ms.
- Fixed: the 16-colour theme drew the primary button's key grey on blue.
- Tests and tools:
  - The `launcher` and `tui_machine` suites gain Ctrl+V tests, and
    `tui_text` an identification test on recorded terminal answers.
  - The `tui` fuzz target also feeds the identification parser.
  - `console_drive` became a script-driven driver for real Windows consoles
    (classic, Windows Terminal, SSH) with screenshots.
  - New: `linux_drive` (C; VTE and xterm under Xvfb, real X input) and
    `bench_tui`.

### Added: start page, mouse, show-while-typing (2026-10-30)
- Start page when `secraxis` runs without a vault path: a fixed-size
  block-letter logo with an info block (it never changes size with the
  window), recently opened vaults, a folder browser to
  open any `.seis` file, and a new-vault form (name, folder, KDF profile).
  `Esc` on a vault's lock screen goes back to it.
- Recent vaults are kept by the app in `recent.json` in its config folder
  (paths and last-opened times only, at most 12, written atomically, read by
  a strict parser). `x` forgets an entry without touching the file;
  `--no-history` turns the file off.
- Mouse: click to select a row or focus a field, double-click to open, wheel
  to scroll; key hints, dialog buttons and the show/hide pill are
  clickable. Clicks map to the same events as keys. `--no-mouse` turns it
  off.
- Add/edit form: `Ctrl+R` (or a click on `show`) shows the password and
  confirm fields as typed; they hide again after 10 s without typing and
  when the form closes.
- Entry badges: on terminals that draw emoji (Rich tier, probe-verified) a
  kind icon guessed from the URL, tags and name (server, mail, bank, code,
  chat, ...); elsewhere a tinted tile with two initials or one CJK
  character. The badge also heads the details pane.
- Windows Terminal started through the Windows 11 default-terminal handoff
  (no `WT_SESSION`) is recognized by its ConPTY window and gets the Rich
  tier.
- `--version`.

### Fixed (2026-10-30, second pass)
- Wide characters in badges: a CJK monogram sat off-center in a three-cell
  chip; badges are four cells with their two-cell content centered.
- Dialogs keep a clear margin over the faded screen, and a word the card
  cuts is wiped whole; a stray letter could touch the dialog border.
- Start-page tips were cut off at the logo width; each now fits one line
  (checked by a test).
- New-vault names that Windows maps to devices (`CON`, `NUL`, `COM1`, ...)
  are refused.

### Changed: TUI rebuilt (2026-10-30)
- New rendering pipeline: the renderer draws into a cell canvas and a frame
  writer sends only changed cells (no flicker, no output when idle, clean
  repaint on resize, synchronized updates, auto-wrap off).
- Refined visual design: restrained palette with one accent and dark/light
  themes (24-bit with ANSI-16/256 fallbacks, attribute-only monochrome),
  typographic hierarchy, monogram badges, sectioned details pane with tag
  pills, centered lock screen, rounded dialogs with pill buttons on a faded
  backdrop, toast messages, live countdowns for reveal and clipboard.
- Responsive layouts: list + details at 100+ columns; adaptive columns and a
  details sheet (Enter) below; a size notice under 40x12; the list scrolls
  with the selection and pages by the visible height.
- Unicode and other scripts: UTF-8 everywhere, generated width tables
  (Unicode 15.0), CJK/emoji/combining marks laid out correctly, width-aware
  truncation and wrapping, IME and surrogate-pair input, caret editing,
  search highlighting. Editing an entry keeps the other fields' bytes
  verbatim; previously, editing an imported non-ASCII entry replaced its
  non-ASCII bytes with '?'.
- The startup probe measures every glyph on the live terminal and falls back
  to ASCII per glyph (glyph tiers Rich/Basic/ASCII); ambiguous-width text
  follows the measurement (legacy consoles with CJK fonts).
- Usability: search filters as you type once opened with '/', results can
  be picked with arrows, Esc backs out one level, Ctrl+S saves, Ctrl+U
  clears a field, j/k navigation, contextual hints, a full shortcuts sheet,
  Caps Lock warning on Windows, live password-match indicator.
- Options: `--ascii`, `--no-color` (and `NO_COLOR`), `--theme dark|light`,
  `--glyphs basic|rich`.

### Security (2026-10-30)
- Terminal-injection hardening: vault text (e.g. from an imported file) can
  no longer carry escape sequences, C1 controls, bidi overrides or other
  invisible controls to the terminal; they are drawn as placeholders.
- Bracketed paste: pasted text reaches text fields only and can never press
  Enter, trigger a command or confirm a deletion.
- Windows: QuickEdit is disabled while the TUI runs (a mouse selection used
  to freeze output, and with it the reveal timeout).
- Frame buffers that may hold a revealed secret (canvas, screen mirror,
  output buffer, input decoder) are wiped when reused or released.
- The master password is printable ASCII in the TUI (with a notice) and in
  `passwd` for new passwords; Unicode passphrases can encode differently
  across input methods and lock the user out. Current passwords are accepted
  as typed.
- Windows clipboard copies use `CF_UNICODETEXT`, so non-ASCII secrets paste
  correctly (ill-formed bytes keep the raw `CF_TEXT` path).
- Entry and vault timestamps written from the TUI now use the wall clock;
  they used the monotonic clock (seconds since boot).

### Fixed (2026-10-30)
- Windows: non-ASCII vault paths (e.g. a Chinese file name) were created
  under a garbled name, and existing files with such names could not be
  opened: `main()` received the path in the ANSI code page while the file
  layer expects UTF-8. Arguments are now rebuilt as UTF-8 from the UTF-16
  command line; plaintext export also opens its output by UTF-16 name.

### Changed (2026-10-30)
- A2ONT is now a built-in component instead of a vendored third-party
  library behind a bridge. The sources live in `src/a2ont` and compile into
  `secraxis_core` under the project's `-Werror` flags; the header is
  `include/secraxis/a2ont.h`. The algorithm is byte-identical to A2ONT
  `5ac22b5`; only the include lines changed.
- `a2ont_bridge` was removed. Its profile whitelist, context binding, sizing,
  memory policy and error collapsing moved unchanged into
  `seis_container.cpp`; `seis_a2ont_decode()` is exposed for the fuzz target.
  **`.seis` format unchanged:** vaults written before and after the change
  open in both directions (both A2ONT profiles, both AEAD profiles).
- A2ONT spec and design/security notes are imported into `docs/a2ont/`, and
  its vectors into `tests/vectors/a2ont/`.
- Tests: renamed `a2ont_vendored_*` to `a2ont_vectors`/`a2ont_roundtrip`;
  added `a2ont_fuzz`, `a2ont_cpp`,
  `a2ont_stage_context_binding_and_profile_whitelist` (pins the context
  layout and the refusal of ablation profiles) and
  `container_roundtrip_strong_a2ont_profile`.

## [0.1.0] — v1 engineering candidate (2026-07)

First complete engineering build of the local TUI password manager.

### Cryptography
- Argon2id KDF (PHC reference), profiles Floor/Default/Strong (384 MiB–1 GiB).
- KEK/VMK/subkey hierarchy: Argon2id → KEK_512 → HKDF-SHA-512 wrap key →
  AEAD-unwrap VMK_512 → domain-separated subkeys bound to
  vault/epoch/save_salt/index.
- AEAD: **AES-256-GCM-SIV** default (OpenSSL ≥ 3.2 backend; AWS-LC
  alternative — swappable, byte-identical wire format, proven by cross-backend
  interop), **XChaCha20-Poly1305** portable fallback. Both KAT-gated (RFC 8452,
  draft-xchacha), authenticated in the header, no silent downgrade.
- Nonce-misuse made structurally impossible: unique key + nonce per
  (vault, epoch, per-save random salt, page).

### Format & vault
- `.seis` v1: 256-byte authenticated public header, VMK envelope, encrypted
  manifest (welds envelope + page tags), page-level AEAD; verify-before-parse;
  one generic error for all auth/parse failures.
- A2ONT bridge: vendored liba2ont (pinned `5ac22b5`) used directly; fresh seed
  per save; context-bound to vault identity.
- Canonical codec (SEIS-CANON-v1): deterministic, strict, single valid
  encoding; bucket padding (CSPRNG-filled) for length control.
- Atomic, crash-safe save with **verify-before-rename** (decrypt+compare the
  assembled container before replacing the old file).
- `seis_validate` full-integrity check.

### Runtime & lifecycle
- Runtime sealed entry store: per-entry metadata/secret AEAD segments,
  fresh-per-session runtime root, moving-target re-sealing.
- Formal CRUD lifecycle (`ENTRY_LIFECYCLE.md`) enforced by `VaultSession`:
  confirmation-gated delete, dirty-state, consume-and-wipe inputs, computed
  password buckets, identity preservation on edit, reseal triggers, honest
  deletion boundary.

### TUI & app
- Headless-testable state machine (16 states); ASCII-safe width-adaptive
  renderer; Win32/POSIX raw-mode terminal with panic restore; platform
  clipboard with TTL + clear-if-ours; hidden password input; reveal TTL;
  idle auto-lock; KDF worker thread.
- CLI subcommands: validate, passwd, rekey, upgrade, import, backup,
  export-plaintext (gated). Password only via hidden prompt.

### Export/import & key management
- CSV/JSON import (total, bounded, fuzzed); encrypted backup; gated plaintext
  export (owner-only perms); change master password; full rekey; KDF upgrade
  with no-downgrade.

### Testing
- 9 ctest suites, all green on Windows/MinGW-GCC-14 and Linux/GCC-11.
- **On dot8 (Linux):** full suite under ASan+UBSan (0 findings); OpenSSL
  GCM-SIV backend under ASan (34 tests); ~2.52 M fuzz executions across 6
  targets under ASan+UBSan (0 findings); Argon2id cost sweep.

### Known gaps
- Full memory-dump secret-search experiment: scripted, not yet run.
- External static-analysis pass: not yet run (compiler `-Werror` clean).
- A2ONT structural-classifier re-run inside Secraxis (A2ONT ships its own v2
  results).
- MSan/TSan; deep multi-hour libFuzzer campaigns with corpus minimization.
