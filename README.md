<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/secraxis-horizontal-dark.svg">
    <img src="docs/assets/secraxis-horizontal.svg" alt="Secraxis" width="480">
  </picture>
</p>

# Secraxis Vault Manager

A password manager for the terminal that keeps your passwords in one
encrypted file on your own computer.

> *Every chain of trust hangs from a nail no one has seen.*

Secraxis was born of distrust, fundamental and systemic: not of the cloud
alone, but of the assumption beneath it, and beneath much of what we call
security, that some things may simply be trusted. A provider because it is
large, a tool because it is popular, a security product because it is
established, a system because everyone relies on it.

None of these is proof. A certificate shows only that someone, once, was
satisfied. A tool trusted by millions may have been examined by very few.
Trust that has not been verified is not trust; it is hope.

So Secraxis checks what it can, and where it cannot, it tries to let no
single source decide. Every save is decrypted and compared before it
replaces the vault. No encrypted part of a vault is read before it proves
it was not altered. Every key, salt and nonce mixes the operating system's
randomness with the processor's, so that neither, failing or lying, decides
alone.

No system is free of trust; every chain hangs from something. Secraxis keeps
its nails few and names them in its
[threat model](docs/THREAT_MODEL.md#4-trust-assumptions). Secraxis has not
yet been audited by an independent security organization; therefore, like
everything else, it should be scrutinized and questioned.

**Version 0.9.2** · Windows 11 (x64) and Linux (x86-64)

## Features

- **One encrypted vault file** (`.seis`). Works offline: no account, no cloud.
- **Strong encryption.** AES-256-GCM-SIV or XChaCha20-Poly1305, with the key
  derived from your master password by Argon2id (384 MiB to 1 GiB of memory
  per unlock). Every key and nonce comes from two independent random
  sources at once: the system's generator and the processor's RDSEED.
- **Passwords stay hidden.** One is shown only when you ask, for 10 seconds.
  A copied password is cleared from the clipboard after 20 seconds. The vault
  locks after 5 minutes without input.
- **Safe saving.** Every save is verified before it replaces the vault. If
  another window or a sync tool saved the vault meanwhile, Secraxis asks
  before it writes.
- **Keyboard and mouse**, in Windows Terminal, the classic Windows console,
  Linux terminals, tmux and over SSH.
- **Import, backup and key changes:** CSV/JSON import, encrypted backups, and
  changing the master password.

## Install

Download `secraxis.exe` (Windows) or `secraxis` (Linux) from the
[releases page](https://github.com/MAXEUR5/Secraxis/releases) and check its
SHA-256 against [RELEASE_NOTES.md](RELEASE_NOTES.md). On
Windows, keep it in a folder only you can write to
([why](MANUAL.md#release-binaries)); on Linux, make it executable
(`chmod +x secraxis`). Then run it from a terminal. It needs a processor
with RDSEED: every one Windows 11 supports, and on Linux Intel since 2014 or
AMD since 2017. To build it yourself,
see [Building from source](MANUAL.md#building-from-source).

## Get started

```
secraxis              start page: recent vaults, create or open one
secraxis my.seis      open a vault, or create it
secraxis --help       all commands and options
```

On the start page press `n` to create a vault. In a vault: `a` adds an
entry, `w` saves, `q` locks, and `?` lists the keys.

## Good to know

- **A forgotten master password cannot be recovered.** Keep encrypted
  backups: `secraxis backup my.seis my-backup.seis`.
- **Pasted text never acts as a command** where the terminal detects
  pastes: Windows Terminal on Windows 11, the classic console from Windows 11
  24H2, and current Linux terminals.
- The master password is read only at a hidden prompt, never from command
  arguments or the environment.

## Documentation

- [MANUAL.md](MANUAL.md): the user manual (installing, everyday use,
  command-line tools, troubleshooting)
- [RELEASE_NOTES.md](RELEASE_NOTES.md): what is in 0.9.2, checksums, known
  limits
- [CHANGELOG.md](CHANGELOG.md): every change
- [docs/SECURITY.md](docs/SECURITY.md): security model, status, and how to
  report a vulnerability; [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what
  Secraxis does and does not protect against
- [docs/](docs/): file format, cryptography, terminal UI, testing

## Status

Secraxis 0.9.2 is tested on Windows 11 and Linux: unit tests, sanitizers,
fuzzing, static analysis, and scripted sessions in real terminals
([docs/TESTING_AND_FUZZING.md](docs/TESTING_AND_FUZZING.md)). It has **not**
been audited by an authority reviewer yet. The tests, fuzz targets and
test tools belong to the development tree and are not part of this public
source.

## Reporting problems

Report bugs and vulnerabilities through
[GitHub Issues](https://github.com/MAXEUR5/Secraxis/issues) on the Secraxis
repository. Issues are public: never post a master password, a real vault
file or any other secret. Before reporting a vulnerability, read
[docs/SECURITY.md](docs/SECURITY.md#reporting-a-vulnerability).
