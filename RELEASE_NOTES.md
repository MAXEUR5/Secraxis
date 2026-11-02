# Secraxis 0.9.3 Release Notes

Released 2026-11-02.

Secraxis is a password manager for the terminal that keeps your passwords in
one encrypted file on your own computer. 0.9.3 replaces the entry icons with
colored letter tiles and lets you choose each entry's color. To store the
colors it saves vaults in a new format: **read "Upgrading" before you save a
vault with it.** See [MANUAL.md](MANUAL.md) for how to use it and
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

## New: colored tiles instead of icons

Every entry is marked by a tile with its initials (`GW` for GitHub Work,
`GH` for GitHub, `工` for 工作邮箱) on a colored background, in the list,
the details and the entry form, in every terminal. The emoji icons are
gone, here and on the start page: emoji fonts drew them about two pixels
off the character grid, so they never lined up with the text.

## New: entry colors

The entry form has a new **Color** field, between Tags and Password. Auto
picks a color from the entry's name, always the same one; or choose Red,
Amber, Green, Teal, Blue, Violet, Pink or Grey with `←` `→` or `Space`, or
by clicking the arrows. The color is stored in the vault.

## Fixed

- In a window too short for the whole entry form, the password fields
  could be out of sight while you typed into them. The form now scrolls to
  the field you are in.

## Upgrading

Replace the program. 0.9.3 opens vaults made by 0.9.1 and 0.9.2 as they
are, every entry on Auto.

**The first save converts a vault to the 0.9.3 format, and from then on
Secraxis 0.9.2 and older cannot open it** (they say "Wrong password or
corrupted vault."). Secraxis tells you once, when it happens: "Saved in the
0.9.3 vault format: Secraxis 0.9.2 and older can no longer open this
vault." Saving from the vault screen and `secraxis import` convert;
`passwd`, `rekey` and `upgrade` keep the format as it is. If you might go
back to an older version, or open the vault with one elsewhere, back it up
before the first save:

```
secraxis backup my.seis my-backup-0.9.2.seis
```

The backup is an exact copy and opens in the version that made it.

A vault a later Secraxis has saved in a format 0.9.3 does not know is
refused with "This vault was saved by a newer version of Secraxis. Update
Secraxis to open it." This appears only after the right master password; a
wrong one still gives the generic message.

From 0.1.0: make the backup above in any case. The vault screen accepts
master passwords in printable ASCII only; if yours contains other
characters, change it first with 0.1.0's `secraxis passwd`.

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

What was run for 0.9.3, on the final code:

- All 21 tests (13 suites and 8 fuzz-corpus replays) pass on Windows and
  Linux, built with no warnings. The six suites 0.9.3 changes (the state
  machine, the renderer, the start page, the contents codec, the container
  and the vault session) also pass under AddressSanitizer+UBSan,
  ThreadSanitizer and MemorySanitizer.
- Each new test was checked by putting the fault it guards against back
  into the code: 15 of 15 caught.
- Vaults that the released 0.9.2 and 0.9.1 programs made, in a real
  console: 0.9.3 opens them and converts them on save; the earlier version
  then refuses the file and leaves it unchanged, and a copy taken before
  still opens there (40 of 40 checks against each version).
- Scripted sessions in real terminals, all passing: on Windows, against the
  release `.exe` itself, the vault, start-page, hangup, saving, conflict and
  prompt sessions (29, 21, 32, 59, 43 and 4 checks), and the memory session
  (39) on the test build; on Linux the memory, vault, saving, conflict and
  hangup sessions (25, 28, 47, 44 and 55), the release binary's vault and
  hangup sessions again, and xterm by its screenshots.
- Fuzzing under AddressSanitizer+UBSan, 15 minutes per target with 4
  workers: the contents decoder (185 million inputs), the unlock path (515
  million) and the interface (629,000): no crash, leak or timeout.

The cryptography, key derivation and file container are unchanged from
0.9.1, whose testing still stands: details in
[docs/TESTING_AND_FUZZING.md](docs/TESTING_AND_FUZZING.md).

## Checksums

| File | Platform | Size | SHA-256 |
|---|---|---|---|
| `secraxis.exe` | Windows 11 x64 | 7,738,330 bytes | `cc5c21dd30f5d201fece1c906e620163118331f22a90e481d7eaddc31d1958bb` |
| `secraxis` | Linux x86-64 | 7,179,072 bytes | `81c973d36140faf9a666bf5bb7eaad40f4efd1c0f5b8ffb280e786ff683f7fc3` |

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
