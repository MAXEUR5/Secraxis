# Secraxis 0.9.1 Release Notes

Released 2026-11-01.

Secraxis is a password manager for the terminal that keeps your passwords in
one encrypted file on your own computer. This is the first release since the
0.1.0 engineering build. See [MANUAL.md](MANUAL.md) for how to use it and
[CHANGELOG.md](CHANGELOG.md) for every change.

## Platforms

| | Supported |
|---|---|
| Windows | Windows 11, x64 (`secraxis.exe`) |
| Linux | x86-64 with glibc 2.38 or later (`secraxis`), for example Ubuntu 24.04, Debian 13, Fedora 39 or newer |
| Processor | one with RDSEED: every processor Windows 11 supports; on Linux, Intel since 2014 or AMD since 2017. A virtual machine must pass RDSEED through. |

Windows 10 and macOS are not supported in this release.

Paste detection (pasted text never acts as a command) works in Windows
Terminal on Windows 11, in the classic console from Windows 11 24H2, and in
current Linux terminals.

## Highlights

- **A new terminal interface.** A start page with recent vaults, a folder
  browser and a new-vault form; mouse support; a details pane beside the
  list in wide windows; full Unicode, including Chinese, Japanese and Korean
  text and emoji. The look adapts to what each terminal can draw. It works
  the same in Windows Terminal, the classic Windows console, Linux terminals,
  tmux and over SSH.
- **Your work is not lost.** Save manually or automatically. Locking with
  unsaved changes asks first. When nobody is there (the idle lock, the
  terminal closing, signing out of Windows), unsaved work is saved or
  discarded as you choose. If another window or a sync tool saved the vault
  meanwhile, Secraxis asks before it writes, and can save a copy.
- **Saves that cannot break the vault.** Each save is checked by decrypting
  it, then swapped in atomically. Two windows cannot save over each other.
  Random kills during saves (4,200 in this release's testing) never lost an
  acknowledged save or damaged a vault.
- **Two independent random sources.** Every key, salt and nonce mixes the
  operating system's random generator with the processor's RDSEED
  (HKDF-SHA-512), so a weak or cloned system generator (a copied virtual
  machine) no longer decides them alone. RDSEED is health-checked, and
  without it Secraxis refuses to work rather than fall back.
- **A careful clipboard.** A copied password is cleared after 20 seconds,
  unless you copied something else since (over SSH the clear cannot check,
  so it is unconditional). On Windows, copies stay out of the clipboard
  history and the cloud clipboard. Over SSH, copies go to your own
  terminal's clipboard (OSC 52). `Ctrl+V` pastes into any field wherever
  Secraxis can read the clipboard.
- **The Secraxis logo**, also as the Windows program icon, drawn to stay
  clear on light and dark backgrounds.
- **Hardening.**
  - Text from imported files can no longer send control sequences to your
    terminal.
  - The Windows program imports only Windows' own libraries, and its secure
    memory is now really locked (see below).
  - Plaintext exports go only to a new file that only you can read.
  - A window never writes back keys that were changed elsewhere.

## Fixed in the release review

The last review before release found and fixed these, each with a test that
fails without the fix:

- Editing an entry's password dropped its TOTP secret (from an import).
- Saving or changing the password through a symbolic link replaced the link,
  leaving the real vault unchanged while reporting success.
- After the master password was changed in another program, a window still
  open could save the old keys back; an overwrite chosen in the save-conflict
  dialog could still do so if the change finished at the same moment.
- On Windows, almost none of the secure memory was actually locked: by
  default Windows lets a program lock only 200 KB, and Secraxis did not ask
  for more, so secrets could be paged out to disk. The limit is now raised
  at startup.
- Running out of secure memory could store an entry without its password, or
  create a vault with an empty master password. A save that runs out now
  says so ("Not saved: not enough secure memory").
- On Windows, signing out or shutting down lost unsaved work.
- `export-plaintext` could write through an existing file, and on Windows
  took the folder's permissions. `backup` could replace an existing file.
- A CSV or JSON file starting with a byte-order mark (Excel and many
  exporters write one) lost its first column, usually the entry names. A
  CSV row with more than 64 fields was misread, and an unclosed quote
  swallowed the rest of the file. Both now fail the import.
- A click made just before a dialog opened could answer that dialog.
- On Linux, a clipboard owner that never answered could freeze the screen.
- On Windows, a busy clipboard made the timed clear give up while reporting
  success.
- The clipboard recognized its own copy of a password by a fingerprint that
  anyone who found it could test password guesses against (a hash under a
  fixed key, kept in ordinary memory). Its key is now random and kept in
  secure memory.
- A failed re-seal or edit of an entry in memory (for example, out of secure
  memory) could drop the entry's secrets from the open session. The old
  sealed copy is now kept until the new one exists.

## Upgrading from 0.1.0

The vault file format is unchanged (format version 1). Make a backup before
you first save a vault with 0.9.1:
`secraxis backup my.seis my-backup.seis`.

The vault screen now accepts master passwords in printable ASCII only, so
that every password can be typed in any terminal. If your master password
contains other characters, change it before you upgrade, with 0.1.0's
`secraxis passwd`.

## Known limitations

- Not audited by an authority reviewer.
- Secraxis needs a working RDSEED: on a processor without one, in a virtual
  machine that hides it, or after it fails its checks, it refuses to open,
  create or save vaults (`MANUAL.md`, Troubleshooting).
- With Linux's default `vm.max_map_count`, a vault can be saved with up to
  about 5,500 entries (about 4,200 if they have TOTP secrets) and opened with
  up to about 8,000. Beyond that, Secraxis reports that it has not enough
  secure memory and changes nothing ([MANUAL.md](MANUAL.md#limits)).
- On Windows, keep the program in a folder only you can write to (Windows
  looks in the program's folder first for two of its system libraries), and
  keep vaults inside your user profile (a vault file takes the permissions
  of its folder).
- The classic Windows console before Windows 11 24H2 cannot mark pastes:
  there pasted text acts as typing. Windows Terminal marks them.
- Over SSH, the clipboard clear also erases anything copied in the 20
  seconds after the password.
- After a crash, the terminal is not restored.
- GNOME Terminal and other VTE terminals end the program as soon as their
  window closes. Turn on automatic saving there.
- TOTP secrets can be imported and are kept, but the vault screen does not
  show them yet.

## Quality

- All 21 tests (13 suites and 8 fuzz-corpus replays) pass on Windows and
  Linux, and on Linux also under AddressSanitizer+UBSan, ThreadSanitizer and
  MemorySanitizer.
- Scripted sessions in real terminals: Windows 222 of 222 checks, including
  the classic console's own paste (the release `.exe` itself 60 of 60);
  Linux 214 of 214. The program's sanitizer builds ran the Linux sessions
  too: 192 of 192 and 173 of 173.
- About 19.9 billion fuzzing executions under the sanitizers, plus 223
  million on the final parsers: no crash.
- Static analysis on the final code: CodeQL and the Clang Static Analyzer
  on the Linux and Windows code, GCC's analyzer on the A2ONT C code, and
  clang-tidy and cppcheck on the Linux build: no defect.
- Every fix in the release review has a test that fails without it (40 of
  40 checked).

Details: [docs/TESTING_AND_FUZZING.md](docs/TESTING_AND_FUZZING.md).

## Checksums

| File | Platform | Size | SHA-256 |
|---|---|---|---|
| `secraxis.exe` | Windows 11 x64 | 7,732,367 bytes | `b283efc6f942a154b75903266a9c3b783c010934e3d5e51685740024f6e7ecbe` |
| `secraxis` | Linux x86-64 | 7,170,104 bytes | `4cd8d0b4c18c9739fbb7d31f7af4511992c5d56f95383e450a4cf149308a470a` |

Check a download before its first run:

```powershell
Get-FileHash .\secraxis.exe -Algorithm SHA256      # Windows (PowerShell)
```

```sh
sha256sum secraxis                                  # Linux
```

The binaries are not code-signed. The Linux build is reproducible: two
builds of this source in different folders, with the same toolchain and the
same dependency builds, gave identical files. The Windows `.exe` is not,
because the link time is stamped into it. Both checksums are those of the
tested files.
