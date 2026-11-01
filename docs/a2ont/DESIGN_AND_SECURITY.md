# A2ONT v1.0 — Design, Security Claims, Non-Goals, and Limitations

This document is the human-readable companion to the normative
[`A2ONT-SPEC-v1.0.md`](A2ONT-SPEC-v1.0.md). It states what A2ONT is designed to do, what it may and
may not claim, and where its honest limits are.

## 1. Design overview

A2ONT transforms a padded vault byte array `B` (length `L`, `L mod 16 = 0`) into `Y ‖ Y_extra`
(length `L + 32`) using a fresh 256-bit CSPRNG seed `R` that is **never stored directly**:

```
Y        = Body_R(B)
Y_extra  = R ⊕ SHAKE256("A2ONT-seed-hide-v1" ‖ ctx ‖ profile-binding ‖ Y , 32)
```

`Body_R` is a composition of exactly-invertible maps:

```
symbol-mask  → GF(2^128) threshold core → [ round ]×round_count
round = PermuteBytes → BitPreMix → XOR-whiten → AR32 → MDS → FwdAddChain → BwdAddChain
```

Decoding recomputes the seed-hiding mask from `Y`, recovers `R = Y_extra ⊕ mask`, and inverts every
layer in reverse. Because the seed-hiding mask is a function of the **entire** `Y`, any missing or
wrong output bit yields a wrong `R`, which makes the inverse body produce high-entropy garbage
rather than a valid vault — this is the all-or-nothing dependency.

### 1.1 Why each layer exists

| Layer | Role | Reversibility |
|-------|------|---------------|
| Symbol mask (`B ⊕ PRG_R`) | classical AONT seed masking | XOR self-inverse |
| GF(2¹²⁸) Cauchy core | symbol-level all-or-nothing threshold; one changed symbol perturbs the whole 256-byte block | invertible matrix (superregular) |
| PermuteBytes | destroys positional locality | inverse permutation |
| BitPreMix | intra-byte diffusion; breaks byte-value structure | inverse 8-bit permutation |
| XOR-whiten | AONT-style bit-flip whitening | XOR self-inverse |
| AR32 | nonlinear (carry + odd-multiply) 32-bit diffusion; defeats pure XOR-linearity | subtract / odd-inverse / counter-rotate |
| MDS4 | local byte diffusion (GF(2⁸), MDS + involutory) | involutory matrix |
| Fwd/Bwd add-chains | global carry-coupled diffusion in both directions | prefix/suffix differences |

The combination is what turns a **local** input change into a **global** output change (empirically
≈50% of output bits flip for a single input-bit change — see the avalanche report), which simple
XOR-based AONT does not achieve.

### 1.2 Modularity

Every primitive is profile-selected (hash/XOF, PRG, RNG, permutation sampler, BitPreMix sampler,
MDS matrix, field backend, round count, symbol size, chain operator). The `profile_id` string is
bound into both the PRG input and the seed-hiding hash, so different profiles produce
cryptographically unrelated streams and cannot be confused at decode time (profile binding,
agenda §14).

## 2. Security claims that A2ONT v1.0 MAY make

1. It is a reversible, randomized, seed-hidden, AONT-derived **pre-encryption** encoding transform.
2. It hides the seed using a SHAKE256-based seed-hiding trailer bound to `Y` and all profile
   parameters.
3. It supports **explicit missing-entropy thresholds** expressed in bits / security symbols.
4. It uses 128-bit security symbols by default (256-bit optional).
5. It **empirically improves avalanche** metrics versus classical and OAEP-style AONT baselines.
6. It **reduces structural locality** before AEAD: local plaintext edits disperse globally.
7. It supports modular cryptographic backends.
8. It is suitable for empirical evaluation as a pre-AEAD reshaping step.

## 3. Non-goals — claims A2ONT v1.0 MUST NOT make

1. A2ONT is **not** encryption and does not provide confidentiality on its own.
2. A2ONT is **not** authentication and provides no integrity/MAC.
3. A2ONT does **not** replace AEAD; AEAD after A2ONT is mandatory.
4. A2ONT does **not** provide 128-bit security when only one byte is missing (that is `2^8`).
5. A2ONT does **not** provide information-theoretic secrecy for non-uniform vault plaintexts.
6. Passing NIST STS / Dieharder / TestU01 does **not** prove confidentiality — those tests measure
   distributional behavior only.
7. A2ONT is **not** a new block or stream cipher.

## 4. Missing-entropy analysis (the central discipline)

For any public, unkeyed, efficiently invertible transform, if an attacker knows all output except
`h` bits, there are at most `2^h` candidate completions. Therefore:

| Missing | Completion space | Feasibility |
|---------|------------------|-------------|
| 1 byte | `2^8` | trivially enumerable |
| 2 bytes | `2^16` | enumerable |
| 3 bytes | `2^24` | enumerable |
| 4 bytes | `2^32` | large; sampled |
| 8 bytes | `2^64` | infeasible; sampled |
| 1 × 128-bit symbol (16 bytes) | `2^128` | infeasible |
| 32 bytes | `2^256` | infeasible |

A2ONT v1.0's honest headline claim:

> A2ONT v1.0 targets ~128-bit all-or-nothing recovery hardness **only** when at least one complete
> 128-bit security symbol (or ≥128 unknown output bits) is unavailable, and only under the
> assumption that no shortcut exists beyond enumerating the missing output information.

The missing-entropy experiment (§20) demonstrates this directly: 1–3 missing bytes are enumerated
(exactly one completion — the true one — reproduces the plaintext; the parser oracle yields no
false-positive valid vaults from the wrong completions), while 16-byte and 32-byte gaps are sampled
and never recovered. This experiment is included specifically to **avoid overclaiming**.

### 4.1 Blockwise-core honesty note

The default profile uses a **blockwise** 16×16 Cauchy matrix over GF(2¹²⁸) (256-byte blocks) rather
than a single dense `s×s` matrix, because a dense matrix is `O(s²)` and infeasible for large vaults
(agenda §27.4 explicitly directs evaluating structured profiles). Consequently the *field-core*
undetermined-set property is **per-block**. The **global** all-or-nothing dependency across the whole
output is carried by the **seed-hiding trailer**: any missing output bits corrupt the recovered seed
`R`, so the entire inverse body produces garbage. Both mechanisms are real; we describe them
separately rather than conflating them. A dense-matrix profile is available for small inputs and for
the threshold-core ablation.

## 5. Reversibility guarantee

`A2ONT_Decode(A2ONT_Encode(B, ctx, profile), ctx, profile) == B` for every valid `B`. Each component
is bijective (XOR self-inverse; invertible field matrices; byte/bit permutations; AR32 via odd
multipliers invertible mod 2³²; involutory MDS; invertible modular-add chains), so the composition
is bijective. This is verified by 200+ Python property tests, the C test battery, and 21
deterministic cross-language vectors that match **byte-for-byte** across Python, Windows/MinGW-GCC,
and Linux GCC 11/13.

## 6. Threat model

A2ONT operates **before** AEAD, on data that will be protected by AEAD. Its adversary model for the
empirical evaluation is a **structural-leakage** adversary who sees the A2ONT output (or a padded
baseline) and tries to (a) classify sensitive vault properties, (b) locate/identify local edits, or
(c) complete a partially-missing output. A2ONT's goal is to reduce this adversary's advantage
relative to padded-only and simple-AONT baselines. A2ONT does **not** defend against an adversary who
sees the seed `R`, nor against side-channel observation of the transform in progress (see §7).

## 7. Engineering security properties

* **Seed sensitivity.** `R` is treated as sensitive until AEAD completes. The C library wipes `R`,
  PRG/mask streams, and intermediate buffers with a non-elided secure-wipe
  (`SecureZeroMemory`/`explicit_bzero`/volatile fallback). Python keeps sensitive material in
  `bytearray`s and zeroizes best-effort; Python cannot guarantee erasure of immutable copies (a
  documented limitation).
* **RNG.** Production uses OS CSPRNG only (`secrets`/`BCryptGenRandom`/`getrandom`/`arc4random_buf`).
  Deterministic seeds exist only behind `A2ONT_TEST_ONLY` / explicit test entry points, used solely
  for test vectors and experiments.
* **Sampling.** All uniform integer sampling uses rejection sampling (no modulo bias); permutation
  and BitPreMix bias tests confirm near-ideal fixed-point counts and index uniformity.
* **No secret logging.** Seeds, streams, plaintext, and intermediate state are never logged. Server
  credentials live only under the git-ignored `doc/` and the session scratchpad; they never appear
  in source, logs, reports, or commits.
* **Error handling.** Decode never emits partial plaintext on failure; explicit error codes
  (`A2ONT_ERR_*`) map 1:1 between C and Python. Header/profile mismatch and malformed input are
  rejected without crashing (fuzz-tested, ASan/UBSan clean).
* **Constant-time.** A2ONT is a public transform used before AEAD; v1.0 does **not** claim full
  side-channel resistance against a local process observing the transform in real time. It avoids
  gratuitous secret-dependent branching but is not hardened against timing/cache attacks.

## 8. Relationship to prior AONT work

A2ONT inherits the classical AONT pattern `U = X ⊕ G(R); V = R ⊕ H(U)` (Rivest package transform;
Boyko OAEP-as-AONT) and extends the body with security-symbol finite-field mixing and
avalanche-oriented reversible rounds. Unlike the linear/position-preserving structure of the
classical and OAEP baselines (whose output change stays local to the input change), A2ONT's rounds
make output changes global and non-linear. The threshold-core theory aligns with finite-alphabet
AONT literature (AONTs as bijections over tuples), while remaining honest that a *public* transform
cannot exceed the `2^h` missing-entropy bound.

## 9. Known limitations

1. Blockwise field-core undetermined-set property is per-block (see §4.1); global dependency is via
   seed hiding.
2. Python throughput is clarity-first (~0.05 MB/s); the C library is the performance path
   (~2 MB/s single-thread; see the benchmark report). Neither is constant-time.
3. `y_extra_len = seed_len = 32` is fixed in v1.0; longer seeds/trailers are a future profile.
4. External batteries (Dieharder/TestU01/PractRand) are run "where practical"; the always-available
   evidence is the in-repo NIST-STS subset plus entropy/compression/divergence metrics.
5. A2ONT provides no protection once the seed is exposed, and no side-channel guarantees.
6. **A2ONT output retains GF(2)-linear structure.** Its diffusion is largely linear over GF(2)
   (symbol matrix, MDS, permutations, XOR whitening), with non-linearity only from AR32 and the
   carry-coupled add-chains. Consequently A2ONT output fails the binary matrix-rank test
   (`diehard_rank_32x32`) while AEAD ciphertext passes it (see the external battery report). This
   is expected — A2ONT is not a cipher. It is direct evidence for the discipline that A2ONT reshapes
   data before AEAD and does not replace it; randomness-battery outcomes say nothing about
   confidentiality either way.
