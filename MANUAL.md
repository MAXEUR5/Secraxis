# Secraxis User Manual

Version 0.9.2 · Windows 11 and Linux

This manual covers installing Secraxis, the vault screen, the command-line
tools, and what to do when something goes wrong. For a short overview, see
[README.md](README.md). For the security design, see
[docs/SECURITY.md](docs/SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contents

1. [Before you start](#before-you-start)
2. [Installing](#installing)
3. [Quick start](#quick-start)
4. [The start page](#the-start-page)
5. [Unlocking and locking](#unlocking-and-locking)
6. [Working with entries](#working-with-entries)
7. [Saving your work](#saving-your-work)
8. [Copy and paste](#copy-and-paste)
9. [Command-line tools](#command-line-tools)
10. [Command-line options](#command-line-options)
11. [Files Secraxis uses](#files-secraxis-uses)
12. [Keeping your vault safe](#keeping-your-vault-safe)
13. [Limits](#limits)
14. [Troubleshooting](#troubleshooting)
15. [Keyboard reference](#keyboard-reference)

## Before you start

- A **vault** is a single file with the `.seis` extension. Each entry has a
  name, username, URL, tags, a remark and a password. The whole vault,
  names included, is encrypted under your master password.
- **A forgotten master password cannot be recovered.** Nobody can open the
  vault without it. Remember it, and keep encrypted backups
  ([Backups](#backups)).
- Secraxis works offline. It has no network features and no cloud sync. To
  use a vault on several computers, copy the file or keep it in a synced
  folder. If another program or a sync tool changed the file while it was
  open, Secraxis notices when it next saves, and asks before it writes
  ([When the vault changed on disk](#when-the-vault-changed-on-disk)).
- Secraxis stores the passwords you give it. By design it has no password
  generator.

## Installing

### Requirements

| | Windows | Linux |
|---|---|---|
| System | Windows 11, x64 | x86-64 with glibc 2.38 or later (for example Ubuntu 24.04, Debian 13, Fedora 39 or newer) |
| Processor | one with RDSEED: every processor Windows 11 supports | one with RDSEED: Intel since 2014 (Broadwell), AMD since 2017 (Zen) |
| Terminal | Windows Terminal (recommended) or the classic console | any terminal with UTF-8, such as GNOME Terminal, Konsole, xterm, or tmux inside one |
| Copying | built in | `wl-clipboard` (Wayland) or `xclip` or `xsel` (X11); over SSH, a terminal that accepts OSC 52 |
| Memory | up to 1 GiB free while a vault unlocks | the same |

Unlocking deliberately takes a few seconds and up to 1 GiB of memory,
depending on the vault's security profile. That work is what makes each
password guess expensive for an attacker.

Secraxis makes every key, salt and nonce from two random sources together:
the operating system's generator and the processor's RDSEED instruction. It
never uses the system's generator alone, so on a computer without a working
RDSEED it cannot open, create or save vaults. In a virtual machine, the host
must pass RDSEED through to it.

### Release binaries

Each release provides `secraxis.exe` (Windows) and `secraxis` (Linux) on
the [releases page](https://github.com/MAXEUR5/Secraxis/releases). Their
SHA-256 checksums are in [RELEASE_NOTES.md](RELEASE_NOTES.md). The
binaries are not code-signed, so check the checksum before the first run:

```powershell
Get-FileHash .\secraxis.exe -Algorithm SHA256      # Windows (PowerShell)
```

```sh
sha256sum secraxis                                  # Linux
```

- **Windows:** put `secraxis.exe` in a folder that only you (and
  administrators) can write to, such as `%LOCALAPPDATA%\Programs\Secraxis`,
  rather than a new folder on another drive such as `D:\Tools`. Windows
  looks in the program's own folder first for two of the system libraries
  it loads, so whoever can add files there could plant one. The program
  needs no other files. Run it from Windows Terminal, or double-click it to
  open it in your default terminal.
- **Linux:** make it executable (`chmod +x secraxis`) and put it in a folder
  on your `PATH`, such as `~/.local/bin`.

### Building from source

You need the source (the release's source archive, or a clone of
<https://github.com/MAXEUR5/Secraxis>), CMake 3.16 or later and a C99 and
C++17 compiler: MinGW-w64 GCC with Ninja on Windows (tested with GCC 14.2),
GCC 11 or later, or clang 18, on Linux, with `make`, `perl` and `curl` for
the dependencies. Run the commands below from the top of the source folder.

**Linux.** Ubuntu and Debian package older versions than Secraxis needs:
libsodium 1.0.18 (1.0.19 or later is required) and, on Ubuntu 24.04,
OpenSSL 3.0 (3.2 or later is needed for AES-256-GCM-SIV). Build both
pinned versions first:

```sh
# libsodium 1.0.20 (checksum from third_party/PIN.md)
curl -LO https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
echo "ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19  libsodium-1.0.20.tar.gz" | sha256sum -c -
tar xzf libsodium-1.0.20.tar.gz
(cd libsodium-1.0.20 && ./configure --prefix=$HOME/secraxis-deps/sodium --disable-shared && make -j && make install)

# OpenSSL 3.5.1, libcrypto only (the script checks the download's SHA-256)
sh scripts/build_openssl.sh $HOME/secraxis-deps

# Secraxis
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSECRAXIS_BUILD_TESTS=OFF \
  -DSECRAXIS_OPENSSL_ROOT=$HOME/secraxis-deps/openssl-install \
  -DSECRAXIS_SODIUM_ROOT=$HOME/secraxis-deps/sodium
cmake --build build -j
```

The program is `build/secraxis`.

**Windows.** libsodium comes with the source (`third_party/libsodium-win64`).
OpenSSL is built once with the same script, run from Git Bash with MinGW's
`gcc` on the `PATH`. Its configure step needs MSYS2 with `perl` and `make`
(`pacman -S perl make`); point `SECRAXIS_MSYS2_BASH` at MSYS2's `bash.exe`.

```sh
SECRAXIS_MSYS2_BASH=/c/msys64/usr/bin/bash.exe sh scripts/build_openssl.sh /c/secraxis-deps
cmake -S . -B build -G Ninja -DSECRAXIS_BUILD_TESTS=OFF -DSECRAXIS_OPENSSL_ROOT=C:/secraxis-deps/openssl-install
cmake --build build
```

The program is `build\secraxis.exe`.

**Build options**

| Option | Effect |
|---|---|
| `SECRAXIS_OPENSSL_ROOT=<dir>` | Uses OpenSSL 3.2 or later for AES-256-GCM-SIV, which new vaults use on processors with AES-NI and CLMUL (otherwise XChaCha20-Poly1305). |
| `SECRAXIS_AWSLC_ROOT=<dir>` | Uses AWS-LC instead (`scripts/build_awslc.sh`). Set one of the two, never both. |
| neither | A portable build with XChaCha20-Poly1305 only. It cannot open vaults that use AES-256-GCM-SIV, and reports them as "Wrong password or corrupted vault." |
| `SECRAXIS_BUILD_TESTS=OFF` | Leaves out the tests and their test-only code. The public source has no tests, so this is always its setting. |
| `SECRAXIS_WERROR=OFF` | Stops a newer compiler's new warnings from failing the build. |

The test suites, fuzz targets and test drivers belong to the development
tree, which is not part of the public source;
[docs/TESTING_AND_FUZZING.md](docs/TESTING_AND_FUZZING.md) describes them
and their results.

## Quick start

1. Run `secraxis`. The start page opens.
2. Press `n` for a new vault. Type a name; `Tab` moves to the folder
   (`Ctrl+O` chooses one) and then to the security profile (`←` `→` change
   it; Default is recommended). Press `Ctrl+S`.
3. Choose a master password and type it again. Creating the vault takes a
   few seconds.
4. Press `a` to add an entry. Fill in the fields and press `Ctrl+S`.
5. Press `w` to save the vault. To save every change automatically instead,
   press `o` for Settings.
6. Press `q` to lock. Next time, the vault is listed on the start page:
   select it and press `Enter`.

On the start page and in a vault, `?` lists the keys. All keys are also in
the [Keyboard reference](#keyboard-reference).

## The start page

Running `secraxis` without a vault file opens the start page.

- **Recent vaults** shows each vault's name, folder and when it was last
  opened. `Enter` or a double-click opens one. A vault whose file is gone is
  marked `missing`.
- **New vault** (`n`): a name, a folder (`Ctrl+O` chooses one) and a
  security profile. `Ctrl+S` creates the vault. The profile sets how much
  work each unlock costs:

  | Profile | Cost per unlock | Use |
  |---|---|---|
  | Floor | 384 MiB, 3 passes | the quickest unlock |
  | Default | 512 MiB, 4 passes | recommended |
  | Strong | 1 GiB, 5 passes, 8 lanes | the slowest to attack |

  A profile can be raised later with [`secraxis upgrade`](#upgrade).
- **Open a vault** (`o`): a folder browser showing folders and `.seis`
  files. Type to filter, or type a path such as `~/vaults` or `D:\Vaults`
  and press `Enter`. `Backspace` on an empty filter goes up one folder.
- **Forget** (`x` or `Del`) removes the selected vault from the list. The
  file itself is not touched.
- `q` or `Esc` quits.

The list is kept in `recent.json` ([Files](#files-secraxis-uses)). It holds
paths and times only. `--no-history` turns the list off.

You can also open a vault directly: `secraxis path/to/vault.seis`. If the
file does not exist, Secraxis creates it, with the Default profile unless
you add `--kdf floor` or `--kdf strong`.

## Unlocking and locking

**Unlocking.** Type the master password and press `Enter`. Each character
shows as a dot. `Ctrl+V` pastes and `Ctrl+U` clears. While the key is being
derived, `Esc` stops waiting.

**Showing the master password.** `Ctrl+R`, or a click on **show** at the
end of the field, shows the characters you have typed, so you can check
them; `Ctrl+R` or **hide** hides them again. This works when unlocking and
in both steps of creating a vault. The password is hidden whenever a prompt
opens, and hides again by itself after 10 seconds without typing, when you
press `Enter` or `Esc`, and when you move on to confirm a new password.
Anyone who can see your screen can read it while it is shown.

**A wrong password** and a damaged or altered file
give the same message, "Wrong password or corrupted vault.": by design,
Secraxis does not tell an attacker which one it is.

**Master passwords** use printable ASCII only: letters, digits, punctuation
and space. That way the same password can be typed in any terminal and
keyboard layout. A master password must not be empty and can be up to 512
characters long. A long passphrase is easier to remember than a short,
complex password, and harder to guess.

**Locking.** `q` locks the vault. If there are unsaved changes, Secraxis
asks first:

| Key | Action |
|---|---|
| `s` or `Enter` | save, then lock |
| `d` | discard the changes, then lock |
| `Esc` or `c` | go back to the vault |

Locking erases the entries and keys from memory. Two things happen without
you:

- **After 5 minutes without input**, the vault locks (the idle lock).
- **When the terminal goes away** (its window closes, the SSH connection
  drops, or on Windows you sign out or shut down), Secraxis ends.

In both cases nobody is there to answer a question. Unsaved changes are then
saved or discarded, as set in [Settings](#settings).

GNOME Terminal and other terminals built on VTE end the program immediately
when their window closes, so nothing can be saved at that moment. If you use
them, turn on automatic saving.

## Working with entries

### The vault screen

The vault screen lists your entries. In windows at least 100 columns wide
and 16 rows high, the selected entry's details appear beside the list; in
smaller windows, `Enter` opens them. The details show the name, username, URL, tags, remark,
the password's approximate length (never the password) and when the entry
was created and last changed.

Move with `↑` `↓` (or `j` `k`), `PgUp` `PgDn`, `Home` and `End`. With the
mouse, a click selects, a double-click opens, and the wheel scrolls. Key
hints and buttons can be clicked too. `--no-mouse` leaves the mouse to the
terminal, for example to select text.

### Adding and editing

`a` adds an entry; `m` edits the selected one. The form has the fields
Name, Remark, Username, URL, Tags, Password and Confirm. A new entry needs a
name and a password. When you edit an entry, leaving Password empty keeps
its current password.

| Key | Action |
|---|---|
| `Tab`, `Shift+Tab`, `↑` `↓` | next or previous field |
| `Ctrl+A`, `Ctrl+E` | start or end of the field |
| `Enter` | next field; on the last field, save the entry |
| `Ctrl+S` | save the entry |
| `Ctrl+R` | show or hide the password you are typing |
| `Ctrl+U` | clear the field |
| `Ctrl+V` | paste |
| `Esc` | cancel |

A password shown with `Ctrl+R` hides again when you turn it off, close the
form, or stop typing for 10 seconds. Editing keeps an entry's creation time
and everything the form does not show, such as an imported TOTP secret.

### Deleting

`d` asks for confirmation. `y` or `Enter` deletes; any other key cancels.
The entry leaves the open vault at once, and the vault file when you save.
Older copies and backups of the file still contain it.

### Searching

`/` opens the search. Type to filter the list; in a vault of more than 5,000
entries the list filters when you press `Enter`. The search matches names,
usernames, URLs, tags and remarks, ignoring the case of ASCII letters. It
never searches passwords. `↑` `↓` pick an entry, `Enter` keeps the filter,
`Esc` restores the list as it was before (an earlier filter, if there was
one), and `Ctrl+U` clears the search.

### Showing and copying passwords

- `s` shows the selected entry's password for 10 seconds. Any key hides it.
- `p` copies the password and `u` copies the username. A countdown shows how
  long the copy stays. After 20 seconds, when you lock, or when Secraxis
  exits, the clipboard is cleared if it still holds that copy, so something
  you copied after it is not cleared. Over SSH this check is not possible:
  there the clear is unconditional, and also erases anything you copied in
  those 20 seconds.

See [Copy and paste](#copy-and-paste) for the platform details.

### Re-sealing

The vault screen keeps each entry separately encrypted in memory, and
re-encrypts entries under fresh keys on a timer and after an entry is shown,
copied or edited. `r` does this at once. You do not normally need it.

## Saving your work

### Manual and automatic saving

By default you save yourself: `w` or `Ctrl+S`. The top line shows
`■ unsaved` while there are unsaved changes. With automatic saving, every
entry you add, edit or delete is saved at once.

Each save builds the new version in memory and decrypts it to check it,
writes it to a temporary file next to the vault, and then replaces the vault
in a single step. An interrupted save (a crash, a power cut, a killed
process) leaves either the previous vault or the new one, never a damaged
file.

### Settings

`o` opens Settings. Both settings are kept in `settings.json`
([Files](#files-secraxis-uses)).

| Setting | Choices |
|---|---|
| **Save changes** | *when I press w* (default): locking with unsaved changes asks what to do · *automatically*: every change is saved at once |
| **At an idle lock, or when the terminal closes** | *save unsaved changes* (default), to a copy next to the vault if it changed on disk · *discard unsaved changes*: nothing is written without you |

### When the vault changed on disk

If another window or a sync tool saved the vault after you opened it,
saving does not overwrite that version. Secraxis asks:

| Key | Action |
|---|---|
| `c` or `Enter` | save a copy next to the vault, named `<name>-conflict.seis` (then `-conflict-2` and so on). The window continues in the copy. |
| `o` | overwrite the other version with yours |
| `Esc` or `n` | go back; your changes stay unsaved |

### When the master password changed elsewhere

If `secraxis passwd`, `rekey` or `upgrade` ran on the vault while it was
open, the open window refuses to save anywhere: saving would bring back the
old password and keys. Lock, unlock with the current password, and make the
changes again.

## Copy and paste

### Copying

- **Windows:** the Windows clipboard. Copies are kept out of the clipboard
  history (`Win+V`) and the cloud clipboard. If another program is holding
  the clipboard when the 20 seconds are up, Secraxis says so and tries again
  every second, also after the vault locks, until it can clear it.
- **Linux desktop:** the first clipboard tool found: `wl-copy` on Wayland,
  `xclip` or `xsel` on X11. Install one of them. Even if Secraxis is killed,
  the copy disappears within 25 seconds (this uses the standard `timeout`
  tool, present on nearly every Linux system).
- **Over SSH** (without X11 forwarding): the copy goes to your local
  terminal's clipboard through OSC 52, and is cleared after 20 seconds.
  Secraxis cannot read that clipboard back, so this clear also erases
  anything you copied since. Windows Terminal and the classic Windows
  console accept OSC 52. GNOME Terminal, other VTE terminals and xterm (by
  default) do not, and Secraxis tells you so instead of pretending.
- **Inside tmux:** OSC 52 needs `set -g set-clipboard on` in tmux.

### Pasting

`Ctrl+V` pastes the clipboard into the focused field: the search, the entry
form, the password prompt, or the start page's path and name fields.
Newlines and tabs are dropped. Where Secraxis cannot read the clipboard
(over SSH, or on Linux without one of the clipboard tools above), `Ctrl+V`
shows a hint instead. The terminal's own paste (right-click,
`Ctrl+Shift+V`, `Shift+Insert`, or `Ctrl+V` in Windows terminals) works
in the same places, everywhere.

**Pasted text never acts as a command.** A pasted `dy` in the list does not
delete anything. This depends on paste detection, the terminal marking a
paste as a paste (bracketed paste):

- **Windows:** Windows Terminal supports it on Windows 11. The classic
  console supports it starting with Windows 11 24H2.
- **Linux:** current terminals support it, including GNOME Terminal,
  Konsole, xterm and tmux.

In a terminal without paste detection, pasted characters arrive as typed
keys. Only paste there while a text field is focused.

## Command-line tools

```
secraxis validate <vault>
secraxis passwd   <vault>
secraxis rekey    <vault>
secraxis upgrade  <vault> --kdf default|strong
secraxis import   <vault> --csv <file> | --json <file>
secraxis backup   <vault> <new-file>
secraxis export-plaintext <vault> --csv <new-file> | --json <new-file>
```

Every command reads the master password at a hidden prompt, so its standard
input must be a terminal: a script run in a terminal works, input from a
pipe does not. No command accepts a password as an argument or from an
environment variable.

**Exit codes:** `0` success; `1` failed or refused (wrong password, damaged
file, aborted); `2` usage error, no interactive terminal, or an import file
that cannot be read; `3` the program could not initialize its cryptography.

### validate

Opens the vault with your password and checks all of it. It prints
`OK: vault is valid and openable.` or `FAILED: wrong password or corrupted
vault.`

### passwd

Changes the master password. It asks for the current password, then the new
one twice. The new password follows the
[master password rules](#unlocking-and-locking).

**Copies and backups made before the change still open with the old
password.** If the old password may be known to someone else, delete those
copies.

`passwd` keeps the vault's internal key and only re-protects it with the
new password. **If your master password leaked, run `passwd` and then
`rekey`:** anyone with the leaked password and an old copy of the file can
recover that internal key, and `passwd` alone does not change it.

### rekey

Re-encrypts the whole vault under a fresh vault key. The master password
stays the same. Use it after `passwd` when the master password leaked, or
when the vault key itself may have been exposed, for example if the vault
was open on a computer that was compromised (then change the password with
`passwd` too, since that computer may have recorded it).

### upgrade

Raises the security profile (`--kdf default` or `--kdf strong`). Lowering it
is refused. A higher profile makes every unlock slower, for you and for an
attacker.

### import

Adds entries from a CSV or JSON file. Existing entries are never changed or
merged, so importing the same file twice adds every entry twice.

- **CSV** needs a header row. These column names are recognized, ignoring
  case; other columns are ignored:

  | Field | Column names |
  |---|---|
  | Name | `name`, `title`, `account` |
  | Username | `username`, `user`, `login`, `email` |
  | Password | `password`, `pass`, `pwd` |
  | URL | `url`, `website`, `uri`, `site` |
  | Tags | `tags`, `group`, `folder` |
  | Remark | `remark`, `notes`, `note`, `comment` |
  | TOTP secret | `totp`, `otp_secret`, `otpauth`, `2fa` |

- **JSON** is an array of objects with the same names as keys:
  `[{"name": "Mail", "username": "me@example.com", "password": "..."}]`.
- A row counts as an entry when it has a name, username, password or URL.
- A file can be up to 16 MiB, with at most 64 columns per CSV row and
  100,000 entries. Any malformed row, or a field longer than the vault
  allows, fails the whole import, and nothing is added.
- The vault screen does not show TOTP secrets in 0.9.2. They are stored,
  kept when the entry is edited, and included in a plaintext export.

The import file holds your passwords in plain text. Delete it securely
afterwards.

### backup

Checks the password, then writes an exact copy of the encrypted vault to a
new file. It never replaces an existing file. The backup opens with the
master password the vault had when the backup was made.

### export-plaintext

Writes every entry, passwords included, **in plain text** as CSV or JSON.
The columns are name, remark, username, url, tags, password and totp. Use
it only to move to another password manager.

- You must type `I UNDERSTAND` before it asks for the password.
- It creates a new file that only you can read (mode 0600 on Linux;
  owner-only permissions on Windows). It never writes over a file or through
  a link.
- Delete the file securely as soon as you are done with it.

## Command-line options

| Option | Effect |
|---|---|
| `--ascii` | ASCII-only drawing and text |
| `--no-color` | no colors; the `NO_COLOR` environment variable does the same |
| `--theme dark` or `--theme light` | override the detected terminal background |
| `--glyphs basic` or `--glyphs rich` | override the detected symbol set |
| `--no-mouse` | leave the mouse to the terminal, for example to select text |
| `--keep-font` | classic Windows console: keep its font (see below) |
| `--no-history` | do not read or write the recent-vaults list |
| `--kdf floor`, `default` or `strong` | the profile for a vault created from the command line |
| `--version`, `--help` | print the version or the usage |

At startup Secraxis checks which symbols the terminal draws correctly and
replaces the others with plain ones. If the classic Windows console's font
draws accented letters two cells wide, Secraxis switches the console to
Consolas while it runs and restores the font on exit. `--keep-font` keeps
your font instead.

The window must be at least 40 columns by 12 rows. From 100 columns and 16
rows, the details appear beside the list.

## Files Secraxis uses

| File | Where | What |
|---|---|---|
| your vault, e.g. `my.seis` | where you put it | the encrypted vault |
| `my.seis.tmp-<16 hex digits>` | next to the vault, during a save | the new version before it replaces the vault. A leftover from an interrupted save is removed by the next save. |
| `my.seis.lock` (Windows) | next to the vault, during a save | keeps two windows from saving at once. It disappears when the save ends. |
| `my-conflict.seis` | next to the vault | a copy saved when the vault changed on disk |
| `recent.json` | config folder | recent vaults: paths and times only |
| `settings.json` | config folder | the two settings |

The config folder is `%APPDATA%\Secraxis` on Windows and
`$XDG_CONFIG_HOME/secraxis` (usually `~/.config/secraxis`) on Linux. The
`SECRAXIS_CONFIG_DIR` environment variable chooses another folder. Secraxis
keeps no logs or caches.

## Keeping your vault safe

### Backups

- Make encrypted backups with `secraxis backup`, and keep one somewhere other
  than the computer that holds the vault.
- A backup opens with the master password the vault had when the backup was
  made.
- Test a backup now and then with `secraxis validate`.

### What Secraxis protects, and what it cannot

- **The vault file** is protected by AES-256-GCM-SIV or XChaCha20-Poly1305
  under a key derived from your master password with Argon2id. Without the
  password, the file reveals only its format details: when it was created
  and last saved, a save counter, its approximate size, its security
  profile and cipher, and a random vault ID that is the same in every copy
  and backup. Nothing about the entries.
- **While the vault is open**, entries stay encrypted in memory (locked
  where the system allows) and are decrypted only as needed: one entry to
  show or copy it, all of them briefly while the vault unlocks or saves. A
  password reaches the screen only when you show it, and the clipboard only
  when you copy it.
- **Secraxis cannot protect you from** malware on your computer while the
  vault is unlocked (keyloggers, screen capture, memory readers), from
  someone watching your screen while a password is shown, or from a
  clipboard manager that keeps copies. A compromised SSH server can also
  see what you do there.
- **On Windows**, a vault file takes the permissions of its folder. Keep
  vaults inside your user profile, or in another folder only you can read.
  On Linux, vault files are readable by you alone.
- `recent.json` shows where your vaults are and when you opened them. Use
  `--no-history` if that matters.

Secraxis 0.9.2 has been tested extensively, but it has **not been audited by
an authority reviewer** ([docs/SECURITY.md](docs/SECURITY.md)).

### How the vault is protected (technical)

From your master password to the file on disk:

```
master password
  -> Argon2id (384 MiB to 1 GiB, per profile)       key derivation
  -> key-encryption key -> HKDF -> wrap key          key hierarchy
  -> unwrap the vault master key                     random, not derived from the password
  -> HKDF subkeys, one per purpose                   manifest, pages, nonces, runtime root
  -> canonical encoding of the entries               one exact byte form (SEIS-CANON-v1)
  -> padding to a size bucket                        hides the exact size
  -> A2ONT transform (fresh seed per save)           reversible reshaping, NOT encryption
  -> AEAD per page                                   the encryption and integrity boundary
```

Every random value (the vault master key, salts, nonces, padding) mixes two
independent sources with HKDF-SHA-512: the operating system's generator and
the processor's RDSEED, health-checked, so neither decides a key alone.
After unlocking, each entry is re-encrypted separately in memory, and the
screen limits how long a secret stays visible or on the clipboard. Every
profile choice in the file is authenticated: a tampered or downgraded file
does not open. A2ONT only reshapes data before encryption; the security of
the vault rests on the AEAD encryption and the key derivation. The details
are in [docs/SEIS_FORMAT.md](docs/SEIS_FORMAT.md),
[docs/CRYPTO_PROFILES.md](docs/CRYPTO_PROFILES.md) and
[docs/A2ONT_INTEGRATION.md](docs/A2ONT_INTEGRATION.md).

## Limits

- **Large vaults on Linux:** an open vault uses 8 memory mappings per entry,
  and a save about 12 (15 with a TOTP secret), because it decrypts every
  entry at once. With Linux's default limit (`vm.max_map_count` = 65530), a
  vault can be saved with up to about 5,500 entries (about 4,200 if they
  have TOTP secrets), and opened with up to about 8,000. Beyond that,
  Secraxis says it does not have enough secure memory ("Not saved: not
  enough secure memory" for a save), and the vault file stays as it was. To
  raise the limit: `sudo sysctl vm.max_map_count=262144` (make it permanent
  in `/etc/sysctl.d/`). A vault holds at most 100,000 entries.
- **After a crash** the terminal is not restored. On Linux, type `reset` and
  press `Enter`; or close the window.
- **VTE terminals** (GNOME Terminal and others) end Secraxis as soon as
  their window closes. Only automatic saving keeps unsaved changes there.
- **TOTP secrets** can be imported and are kept, but the vault screen does
  not show them yet.

## Troubleshooting

| Problem | What to do |
|---|---|
| "This console cannot process terminal sequences." | Use Windows Terminal. In the classic console, turn off *Use legacy console* in its properties. |
| Symbols look wrong or columns are misaligned | Try `--glyphs basic`, or `--ascii`. On Windows, use a font such as Cascadia Mono or Consolas. |
| "Wrong password or corrupted vault." | Check the password, including the keyboard layout and Caps Lock. `secraxis validate` checks the file; if it is damaged, restore a backup. A build without OpenSSL or AWS-LC also says this for vaults that use AES-256-GCM-SIV. |
| Unlocking takes long | That is the security profile's work. Strong takes the longest. `Esc` stops waiting. |
| "Not enough secure memory", or "Not saved: not enough secure memory" | A very large vault on Linux: see [Limits](#limits). The vault file is unchanged. |
| A copy reports it cannot copy | Install `wl-clipboard`, `xclip` or `xsel`. Over SSH, use a terminal that accepts OSC 52; in tmux, set `set-clipboard on`. |
| "Could not clear the clipboard yet" (Windows) | Another program is holding the clipboard. Secraxis keeps trying every second. |
| Saving asks about a changed vault | Another window or a sync tool saved it. See [When the vault changed on disk](#when-the-vault-changed-on-disk). |
| Saving is refused because the keys changed | See [When the master password changed elsewhere](#when-the-master-password-changed-elsewhere). |
| Pasted text acted as keys | The terminal has no paste detection. See [Pasting](#pasting). |
| The terminal looks broken after a crash | On Linux, type `reset` and press `Enter`; or close the window. |
| "This processor offers no RDSEED" | Secraxis needs RDSEED (see [Requirements](#requirements)). In a virtual machine, let it use the host processor's features (RDSEED passthrough). |
| "The processor's RDSEED failed its checks" | Restart Secraxis. If it keeps failing, update the computer's firmware (BIOS/UEFI) and processor microcode: the processor's random generator may be faulty. Nothing was written. |

### Reporting a problem

Report bugs and security problems through
[GitHub Issues](https://github.com/MAXEUR5/Secraxis/issues) on the Secraxis
repository. Issues are public: never include a master password, a real
vault file or any other secret. For a vulnerability, follow
[docs/SECURITY.md](docs/SECURITY.md#reporting-a-vulnerability).

## Keyboard reference

Letter keys work in either case: with Caps Lock on or Shift held, `A` does
what `a` does. Text you type into a field keeps its case.

**Start page**

| Key | Action |
|---|---|
| `↑` `↓`, `j` `k`, `PgUp` `PgDn`, `Home` `End` | move |
| `Enter` | open the selected vault |
| `n` | new vault |
| `o` | open a vault (folder browser) |
| `x` or `Del` | forget the selected vault (the file is kept) |
| `?` | help |
| `q` or `Esc` | quit |

**Folder browser:** type to filter or enter a path; `↑` `↓` move; `Enter`
opens a folder or a vault; `Backspace` on an empty filter goes up; `Esc`
clears the filter, then goes back.

**New vault:** `Tab` and `Shift+Tab` move between fields; on the profile
field `←` `→` or `Space` change it; `Ctrl+O` chooses a folder (in the folder
field also `Ctrl+B`); `Ctrl+S` creates; `Esc` cancels. In every text field,
`Ctrl+A` and `Ctrl+E` jump to the start and end.

**Password prompt:** `Enter` unlocks; `Ctrl+R` shows or hides the password
you are typing; `Ctrl+V` pastes; `Ctrl+U` clears.
`Esc` goes back one step while you confirm a new password; otherwise it
returns to the start page, or quits when the vault was named on the command
line. While unlocking, `Esc` stops waiting.

**Vault**

| Key | Action |
|---|---|
| `↑` `↓`, `j` `k` | move |
| `PgUp` `PgDn`, `Home` `End` | page, first, last |
| `Enter` | details |
| `/` | search |
| `a` | add an entry |
| `m` | edit the entry |
| `d` | delete the entry (asks first) |
| `s` | show the password for 10 seconds |
| `p` | copy the password |
| `u` | copy the username |
| `w` or `Ctrl+S` | save |
| `r` | re-seal memory |
| `o` | Settings |
| `q` | lock (asks first if there are unsaved changes) |
| `?` | help |
| `Esc` | back one level (details, then the search filter) |

**Search:** type to filter; `↑` `↓` pick; `Enter` keeps the filter; `Esc`
restores the list; `Ctrl+U` clears.

**Entry form:** see [Adding and editing](#adding-and-editing).

**Settings:** `↑` `↓`, `j` `k` or `Tab` choose a setting; `←` `→` or `Space`
change it; `Esc`, `Enter` or `o` close Settings.

**Questions**

| Question | Keys |
|---|---|
| Delete this entry? | `y` or `Enter` deletes; any other key cancels |
| Unsaved changes (after `q`) | `s` or `Enter` save and lock; `d` discard and lock; `Esc` or `c` back |
| The vault changed on disk | `c` or `Enter` save a copy; `o` overwrite; `Esc` or `n` back |

**Anywhere:** `Ctrl+L` redraws the screen.
