# Third-party dependency pins

All production cryptography that protects secrets comes from these vetted
components: no AEAD, password KDF, HKDF or CSPRNG is hand-implemented in
Secraxis Vault Manager itself.

A2ONT is not a third-party dependency: it is part of Secraxis (`src/a2ont`,
built into `secraxis_core`). Its C code includes its own Keccak (SHAKE256,
KMACXOF256) for the transform, which is not a security boundary (the AEAD
applied after it is). Its provenance is recorded in
`docs/A2ONT_INTEGRATION.md` §2.

## libsodium 1.0.20 (AEAD, CSPRNG, secure memory, HKDF-SHA-512, constant-time)

- Upstream: https://github.com/jedisct1/libsodium (release 1.0.20-RELEASE)
- Artifacts (SHA-256, recorded at download time):
  - `libsodium-1.0.20-mingw.tar.gz`
    `01fb81c10ae3d249bfe5890ce59544571469e16691994ab6702a531533c6d726`
    → extracted to `libsodium-win64/` (official prebuilt static lib for MinGW-w64;
    used for local Windows builds; link with `SODIUM_STATIC`).
  - `libsodium-1.0.20.tar.gz`
    `ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19`
    → source tarball used to build on Linux hosts (`remote/run_sanitizers.sh`),
    and kept for reproducibility. Archives live in `downloads/` (git-ignored,
    re-fetchable; re-verify these hashes after any re-download).
- Used for: XChaCha20-Poly1305-ietf AEAD, `randombytes_buf` (OS CSPRNG),
  `crypto_kdf_hkdf_sha512` (RFC 5869), `sodium_malloc`/`sodium_mlock`/
  `sodium_memzero`/`sodium_memcmp` secure memory + constant-time compare;
  also `crypto_generichash` (the clipboard's clear-if-ours fingerprint) and
  `sodium_bin2base64` (OSC 52 copies).
- NOT used for: Argon2 (libsodium `crypto_pwhash` hardcodes `p=1` lanes and a
  16-byte salt; the mandated Secraxis KDF profiles require `p=4`/`p=8` and a
  32-byte salt).

## phc-winner-argon2 20190702 (Argon2id reference implementation)

- Upstream: https://github.com/P-H-C/phc-winner-argon2 (tag 20190702)
- Artifact SHA-256:
  `argon2-20190702.tar.gz`
  `daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c`
- Vendored content: `include/argon2.h`, `src/` (verbatim), `LICENSE` (CC0/Apache-2.0).
- This is the official PHC-winner reference implementation referenced by RFC 9106
  and packaged by major distributions. Used via the low-level `argon2_context`
  API so that Secraxis controls: 32-byte salt, 64-byte output, lanes/threads,
  and a custom arena allocator (best-effort lock + no-dump + guaranteed wipe).
- KATs: three Argon2id vectors from the reference `src/test.c` are executed in
  `tests/unit/test_crypto_selftest.cpp` (`argon2id_reference_kats`).

## OpenSSL 3.5.1 (AES-256-GCM-SIV — SEIS-AEAD-2 **default backend**)

- Upstream: https://github.com/openssl/openssl (release openssl-3.5.1)
- Artifact SHA-256:
  `openssl-3.5.1.tar.gz`
  `529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f`
- Built minimal by `scripts/build_openssl.sh`:
  `no-shared no-tests no-apps no-docs no-deprecated no-legacy no-engine
  no-module no-autoload-config` → static `libcrypto.a` only. The
  `no-autoload-config` flag removes OpenSSL's implicit `openssl.cnf` /
  `OPENSSL_CONF` loading (local-attack surface a vault must not carry).
- Consumed ONLY for `EVP_CIPHER_fetch("AES-256-GCM-SIV")` (RFC 8452), gated by
  the same scope rules as any libcrypto backend (`scripts/check_backend_scope.sh`,
  RFC 8452 KATs + the `.seis` roundtrip and tamper tests as mandatory gates,
  unsupported AEAD IDs rejected never downgraded).
- Release builds use this pinned release (the owner's scope constraint,
  below). Someone building for their own use may instead point
  `-DSECRAXIS_OPENSSL_ROOT` at an installed OpenSSL 3.2 or newer whose
  `libcrypto` is in `<root>/lib` or `<root>/lib64` (Debian's and Ubuntu's
  multiarch folders are not searched). An older one builds and
  links but has no AES-256-GCM-SIV at run time: such a build creates
  XChaCha20-Poly1305 vaults and refuses GCM-SIV vaults as unsupported.
  Ubuntu 24.04 ships 3.0.13, so the Linux test host builds this pinned
  release (`remote/run_openssl_gcmsiv_sanitize.sh`).
- Windows build-time toolchain (never linked, never shipped): MSYS2 base
  pinned release `2026-06-11` (`msys2-base-x86_64-20260611.sfx.exe`, SHA-256
  `c105946e64e08f099ac0e4647461ce762b95333ad211777666476a9a41451d65`),
  extracted to `D:\OTHER_ENV\msys64`; pacman-installed `perl` (5.42, msys
  flavor — required by OpenSSL Configure) and `make` 4.4.1, with pacman's GPG
  keyring verification active. The compiler remains the project's MinGW GCC
  14.2; MSYS2 provides only the POSIX shell, perl, and make for OpenSSL's
  build system.
- Backend interop: `scripts/test_backend_interop.sh` checks that a GCM-SIV
  vault created by an OpenSSL build opens under an AWS-LC build and vice
  versa.

## AWS-LC v5.1.0 (AES-256-GCM-SIV — SEIS-AEAD-2 validated ALTERNATIVE backend)

- Upstream: https://github.com/aws/aws-lc (tag v5.1.0)
- Artifact SHA-256:
  `aws-lc-5.1.0.tar.gz`
  `a6bf6adfc5f9bba559d28554b7d3581b15f2813f03bc9f2ae19f0d915e97dadf`
- Built out-of-repo by `scripts/build_awslc.sh` (CMake+Ninja,
  `-DDISABLE_GO=ON -DDISABLE_PERL=ON`, pregenerated assembly, libcrypto only);
  wired via `-DSECRAXIS_AWSLC_ROOT=...`. Windows-MinGW build verified locally
  (full NASM x86-64 assembly, AES-NI/CLMUL constant-time paths).
- Status: **alternative backend** (select with `-DSECRAXIS_AWSLC_ROOT`);
  OpenSSL is the default per the owner's 2026-07-05 direction (smaller source
  supply chain: 51 MB vs 139 MB tarball; system-present on Unix targets,
  though not always at 3.2 or newer: Ubuntu 24.04 ships 3.0.13).
  AWS-LC is retained as the cross-backend interop oracle and for
  environments that prefer it (its final linked binary is smaller: 2.6 MB vs
  6.2 MB measured).
- **Scope constraint (project owner, 2026-07-05):** any libcrypto here is a
  local pinned dependency ONLY, limited to the AES-256-GCM-SIV backend
  (RFC 8452) unless separately justified in writing.
  `scripts/check_backend_scope.sh` enforces that only `src/crypto/aead.cpp`
  may include OpenSSL-family headers or use `EVP_`/`AES_` symbols. RFC 8452
  KATs and the project `.seis` vectors are mandatory release gates (a `.seis`
  file has no fixed byte vectors, by design: that gate is the `.seis`
  roundtrip and tamper tests, see `tests/vectors/VECTORS.md`). Unsupported
  AEAD IDs are rejected, never silently downgraded.
- Verified against the RFC 8452 C.2 official vectors in
  `tests/unit/test_crypto_selftest.cpp`.
- Selection evidence trail (2026-07-05): libsodium/Botan/mbedTLS/wolfSSL have
  no RFC 8452 GCM-SIV; OpenSSL 3.5.1 `mingw64` Configure requires an
  MSYS-flavored Perl and aborted under native Strawberry Perl (recorded
  attempt); BoringSSL has no releases and needs Go. AWS-LC: tagged releases,
  audited BoringSSL lineage (the implementation family in which GCM-SIV
  originated), FIPS-track, builds everywhere we need with no extra toolchain.

## Rationale for the dependency set

- One AEAD/utility library (libsodium) + the canonical Argon2 reference + one
  libcrypto used for AES-256-GCM-SIV alone (OpenSSL by default, or AWS-LC).
  Minimal surface, all maintained, all with official test vectors, licenses
  compatible (ISC / CC0-Apache2 / Apache-2.0; AWS-LC also has ISC and MIT
  parts). A2ONT is Secraxis's own code (see the top of this file).
- TUI, clipboard, JSON/CSV import parsers are implemented in-tree (no external
  dependency): they handle secrets and must be auditable, fuzzable, and able to
  wipe their buffers — third-party TUI/JSON libraries keep data in unwipeable
  internal strings.
