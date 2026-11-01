# Security

The concise security statement for Secraxis Vault Manager, and how to report
a vulnerability. Detail lives in `THREAT_MODEL.md`, `CRYPTO_PROFILES.md`, and
`RUNTIME_MEMORY_SECURITY.md`.

## Reporting a vulnerability

Report vulnerabilities through **GitHub Issues**: open an issue in the
Secraxis repository, <https://github.com/MAXEUR5/Secraxis/issues>. There
is no email address for reports.

GitHub Issues are public. In a report:

- **Include** the version (`secraxis --version`), the platform and
  terminal, what goes wrong, and how to make it happen.
- **Leave out** master passwords, real vault files and every other secret.
  If the problem needs a vault to show, create a new one with a throwaway
  password and made-up entries.
- **Describe the effect** (for example, "a crafted import file crashes the
  program") rather than posting a ready-made attack. More detail can follow
  in the issue when it is needed.

## Boundaries (non-negotiable)

1. **A2ONT is not encryption.** It is a reversible pre-encryption transform.
2. **AEAD is the confidentiality and integrity boundary** — always applied
   after A2ONT.
3. **Argon2id raises offline guessing cost; it does not add password entropy.**
   Each vault has its own random 32-byte salt, drawn again at every password
   or key change, so no precomputed table or guessing work carries from one
   vault to another.
4. **KEK/VMK separation is mandatory**; the VMK is 64 random bytes from both
   random sources (item 5), never derived from the master password.
5. **Randomness** comes from two independent sources mixed by HKDF-SHA-512
   on every draw: the OS CSPRNG and the CPU's RDSEED (health-checked). There
   is no fallback to either alone: without a working RDSEED nothing that
   needs random numbers runs (`CRYPTO_PROFILES.md` §5).
6. **Primitives** come from vetted, hash-pinned libraries; none are
   hand-implemented; all are gated by official KATs.
7. **Runtime memory protection** reduces exposure but does not defeat a
   privileged in-machine adversary.
8. Statistical randomness tests are leakage-reduction evidence, **not** proof
   of secrecy.

## What Secraxis reduces

Offline master-password guessing (Argon2id), at-rest structure/length leakage
(A2ONT + bucket padding), parser/error oracles (verify-before-parse + one
generic error), full-vault plaintext residency (runtime sealing + wipe),
accidental leakage (SecureBuffer, no-log, no-argv/env, alt-screen), stable
addresses (moving-target sealing), clipboard lingering (TTL), and torn writes
(atomic, verify-before-rename).

## What it does not protect against

Malicious kernel / rootkit / hypervisor / DMA; keyloggers; screen recorders;
malicious terminal emulators; cold-boot / co-located side-channels; arbitrary
code execution inside the process. See `THREAT_MODEL.md` §2.2.

## Cryptographic profiles

- KDF: Argon2id — Floor 384 MiB/t3/p4, Default 512 MiB/t4/p4, Strong
  1024 MiB/t5/p8; salt 32 B, output 64 B.
- AEAD: AES-256-GCM-SIV (default, misuse-resistant) or XChaCha20-Poly1305
  (portable). The chosen profile is recorded in the header and
  authenticated; no silent downgrade.
- Subkeys: HKDF-SHA-512, domain-separated, bound to vault/epoch/save_salt/index.
- A2ONT: v1.0 default/strong, 32-byte seed (module spec).

Every crypto-affecting parameter is authenticated; unsupported/weaker profiles
are rejected, never downgraded.

## Review status

This is a reference implementation produced under an internal agenda. The
memory-dump experiment (agenda §22.4) and the static-analysis pass over the
Linux and Windows code (the Clang Static Analyzer, CodeQL, clang-tidy,
cppcheck, and GCC's analyzer on the A2ONT C code; no defect found) are done
(`TESTING_AND_FUZZING.md`), and three independent AI code reviews were made
for 0.9.1, with every finding fixed with a test or documented. An
independent human cryptographic and code review has **not** been made; it
is the only open release gate. Do not treat Secraxis as audited production
software until it has.

## Handling secrets in this repo

Server credentials and the agenda live under `doc/` and are **git-ignored**;
they are never committed, logged, printed, or copied into any deliverable.
Credential material used for the experiments (e.g. an SSH key) lives only
in a session scratchpad and is wiped when remote work completes.
