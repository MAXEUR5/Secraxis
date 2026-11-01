# Secraxis 0.9.2 Release Notes

Released 2026-11-01.

Secraxis is a password manager for the terminal that keeps your passwords in
one encrypted file on your own computer. 0.9.2 adds a way to see the master
password you are typing and fixes letter keys that did nothing in capitals.
See [MANUAL.md](MANUAL.md) for how to use it and
[CHANGELOG.md](CHANGELOG.md) for every change; the 0.9.1 release notes give
the overview of the 0.9 series.

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

## New: see the master password you are typing

When unlocking a vault and in both steps of creating one, `Ctrl+R` or a
click on **show** at the end of the password field shows what you have
typed, so you can check it before pressing `Enter`; **hide** or `Ctrl+R`
hides it again.

It follows the same rules as a shown entry password:

- The password is hidden whenever a prompt opens.
- It hides again by itself after 10 seconds without typing, and when you
  press `Enter` or `Esc` or move on to confirm a new password, so it is
  never on screen while the key is derived.
- A paste cannot turn it on.
- It reaches the terminal only through buffers that are wiped after use; a
  scan of the running program found no copy of it once the key was derived.

Anyone who can see your screen can read the password while it is shown.

## Fixed: capital letters

With Caps Lock on or Shift held, the vault's keys (`A` to add, `S` to show,
`Q` to lock, `J`/`K` to move, …), Settings and the start page did nothing;
only the three confirmation dialogs accepted both cases. Every command
letter now works in either case. Text you type into a field keeps its case,
and pasted text still never acts as a command.

## Upgrading

From 0.9.1: replace the program. The vault file format is unchanged (format
version 1) and nothing needs converting.

From 0.1.0: make a backup before you first save a vault with 0.9.2
(`secraxis backup my.seis my-backup.seis`). The vault screen accepts master
passwords in printable ASCII only; if yours contains other characters,
change it first with 0.1.0's `secraxis passwd`.

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

What was run for 0.9.2, on the final code:

- All 21 tests (13 suites and 8 fuzz-corpus replays) pass on Windows and
  Linux. The three suites 0.9.2 changes (the state machine, the renderer and
  the start page) also pass under AddressSanitizer+UBSan, ThreadSanitizer
  and MemorySanitizer.
- Each new test was checked by putting the fault it guards against back
  into the code: 7 of 7 caught.
- Scripted sessions in real terminals: on Windows the memory, vault and
  start-page sessions (39, 28 and 21 checks) and the release `.exe` itself
  (60 of 60); on Linux the memory and vault sessions (25 and 27 checks).
  The memory sessions show the master password while creating the vault and
  then check that it is gone from the program's memory.
- The `tui` fuzz target, which drives the interface with random keys, ran
  10 minutes under AddressSanitizer+UBSan: no crash.

The cryptography, file format and saving are unchanged from 0.9.1, whose
testing still stands: details in
[docs/TESTING_AND_FUZZING.md](docs/TESTING_AND_FUZZING.md).

## Checksums

| File | Platform | Size | SHA-256 |
|---|---|---|---|
| `secraxis.exe` | Windows 11 x64 | 7,736,907 bytes | `97d030f815cfd461774a4bccb6a227a602d636f75815f3fe3e3d1cf336f29819` |
| `secraxis` | Linux x86-64 | 7,174,712 bytes | `6d0da5fb0c2a18b9bef749ca53daf18ab98f254c3b01778e333e31f8567cc7e1` |

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
