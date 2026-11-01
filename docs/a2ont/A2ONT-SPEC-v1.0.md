# A2ONT v1.0 — Normative Implementation Specification

This document pins down every byte-level decision needed so that independent implementations
(Python `a2ont`, C `liba2ont`) produce **identical** outputs. It refines
`doc/a2ont_project_agenda.md` (the agenda); where the agenda leaves an encoding or parameter
unspecified, the choice made here is normative and the rationale is recorded in
`docs/00_project_understanding.md` §6.

**Security boundary (restated, normative):** A2ONT is a reversible, randomized, seed-hidden,
AONT-derived pre-encryption encoding transform. It is **not** encryption, not AEAD, not a MAC.
AEAD after A2ONT is mandatory. All all-or-nothing statements are missing-entropy statements:
`h` unknown output bits ⇒ at most `2^h` candidate completions; missing 1 byte ⇒ at most `2^8`.
≈128-bit recovery hardness may be claimed only when ≥1 full 128-bit security symbol (or ≥128
output bits) is missing.

---

## 1. Notation and canonical encodings

* All multi-byte integers in A2ONT internal encodings are **little-endian (LE)**.
* `u32le(n)` — 4-byte LE; `u64le(n)` — 8-byte LE.
* `enc_bytes(b)` = `u32le(len(b)) ‖ b` (length in bytes).
* `enc_str(s)` = `enc_bytes(UTF8(s))`.
* `enc_int(n)` = `u64le(n)` (all agenda `encode(integer)` fields).
* Absent/None `extra_context` ≡ empty byte string: `enc_bytes(b"")` = `00 00 00 00`.
* ASCII literals in quotes ("A2ONT-v1", "A2ONT-seed-hide-v1", "A2ONT-PRG") are raw ASCII bytes
  with **no** length prefix (they are fixed domain-separation prefixes).

## 2. Primitives

### 2.1 SHAKE256 (FIPS 202) — `hash_xof` backend id `"SHAKE256"`

Standard SHAKE256; XOF (arbitrary output length).

### 2.2 cSHAKE256 and KMACXOF256 (NIST SP 800-185) — `seed_prg` backend id `"KMACXOF256"`

SP 800-185 exactly:

* `left_encode(x)`: minimal big-endian byte string of `x` (length `n ≥ 1` bytes), **prefixed** by
  byte `n`. `left_encode(0) = 01 00`.
* `right_encode(x)`: same, **suffixed** by byte `n`. `right_encode(0) = 00 01`.
* `encode_string(S)` = `left_encode(8·len(S)) ‖ S` (length in bits).
* `bytepad(X, w)` = `left_encode(w) ‖ X`, zero-padded to a multiple of `w` bytes.
* `cSHAKE256(X, L, N, S)`: if `N = "" ∧ S = ""` → `SHAKE256(X, L)`; else
  `KECCAK[512]( bytepad(encode_string(N) ‖ encode_string(S), 136) ‖ X ‖ 00₂, L )`
  (i.e. Keccak-f[1600], rate 136, domain suffix bits `00` → pad byte `0x04`).
* `KMACXOF256(K, X, L, S)` = `cSHAKE256( bytepad(encode_string(K), 136) ‖ X ‖ right_encode(0),
  L, "KMAC", S )`.

Because KMACXOF appends `right_encode(0)`, outputs of different lengths are prefix-consistent:
a KMACXOF256 stream is an **unbounded XOF stream** consumed incrementally.

### 2.3 RNG

Production: OS CSPRNG only (Python `secrets.token_bytes`; C: Windows `BCryptGenRandom`,
Linux `getrandom()` with `/dev/urandom` fallback, macOS/BSD `arc4random_buf`). Interface:
`rng_generate(n)`, `rng_name()`, `rng_selftest()`. Deterministic RNG exists only under
`A2ONT_TEST_ONLY` builds / explicit test-only APIs used for test vectors.

### 2.4 UniformInteger (rejection sampling; normative)

To draw a uniform integer in `[0, n)` (`n ≥ 1`) from an XOF stream:

```
if n == 1: return 0                      # consumes no bytes
k     = smallest integer with 256^k >= n
limit = floor(256^k / n) * n
loop:
    u = LE integer from the next k stream bytes
    if u < limit: return u mod n         # unbiased
    # else: reject, continue (consumes k more bytes)
```

Fisher–Yates `j = UniformInteger(0..i)` uses `n = i+1`. BitPreMix index uses `n = 40320`
(⇒ `k = 2`, `limit = 40320`, acceptance ≈ 61.5%).

## 3. Seed PRG (agenda §9.3; normative layout)

Every seed-derived stream is a single KMACXOF256 instance:

```
PRG_R(label, t, extra) = KMACXOF256(
    key = R,
    X   = "A2ONT-v1"                 # 8 raw bytes
        ‖ enc_str(label)
        ‖ enc_int(t)                 # round index (0 for round-independent streams)
        ‖ enc_int(L)
        ‖ enc_str(profile_id)
        ‖ enc_int(security_symbol_bits)
        ‖ enc_int(round_count)
        ‖ enc_bytes(extra or b"")
    S   = "A2ONT-PRG",
    L   = unbounded (XOF stream)
)
```

Labels (domain-separated; never reuse a stream across purposes):
`"symbol-mask"`, `"field-matrix"` (reserved), `"perm"`, `"bit-premix"`, `"mask"`, `"add"`,
`"mul"`, `"rot32"`, `"mds"` (reserved), `"fwd-chain"`, `"bwd-chain"`.
Default profile: `extra = None` everywhere (the per-byte BitPreMix profile variant uses
`extra = enc-of-byte-index`, see §6.3).

## 4. Profiles

```
profile_id                 "A2ONT-v1.0-default"          (strong: "A2ONT-v1.0-strong")
seed_len_bytes             32
y_extra_len_bytes          32        (must equal seed_len_bytes in v1.0)
security_symbol_bits       128       (symbol_bytes = 16)
missing_symbol_threshold   1
round_count                2         (strong: 3)
hash_xof_id                "SHAKE256"
seed_prg_id                "KMACXOF256"
rng_id                     "OS_CSPRNG"
byte_order                 little-endian ; word 32 bits
byte_permutation           "fisher-yates-rejection-sampling"
bit_premix                 "perm8-lehmer-stream-v1"      (alt: "perm8-lehmer-perbyte", "off")
ar32                       add mod 2^32 · odd mul mod 2^32 · ROTL32   ("on" / "off")
mds_id                     "A2ONT-MDS4-v1"               (alt: "off")
chain_operator             "modular-addition"            (alt: "xor")
matrix_id                  "A2ONT-GF128-MDS-v1"          (alt: "off")
field_block_symbols        16
padding_policy_id          "vault-bucket-padding-v1"     (informational; padding is done upstream)
```

Ablation profiles (fixed `profile_id`s, used by experiments; the id feeds the PRG/seed-hide
binding, so ablated variants produce unrelated streams by construction):
`A2ONT-v1.0-r1` (round_count 1), `A2ONT-v1.0-r3` ≡ strong, `A2ONT-v1.0-no-core`
(matrix_id "off"), `A2ONT-v1.0-no-bitpremix` (bit_premix "off"), `A2ONT-v1.0-xor-chains`
(chain_operator "xor"), `A2ONT-v1.0-no-ar32` (ar32 "off"), `A2ONT-v1.0-sym256`
(security_symbol_bits 256, field_block_symbols 8).

**Input validity:** `L mod 16 = 0`, `L mod symbol_bytes = 0`, `L ≥ 0`. (`L = 0` valid.)

## 5. Threshold core (agenda §7)

### 5.1 GF(2^128)

Element = polynomial over GF(2) mod `p(x) = x^128 + x^7 + x^2 + x + 1`.
A 16-byte symbol maps to an element by reading the bytes as a **little-endian** 128-bit integer
`a`; bit `k` of `a` is the coefficient of `x^k`. (Plain polynomial basis; **not** GCM's
reflected convention. A2ONT is not GCM and not AEAD.)
Multiplication: schoolbook shift-and-reduce (reduce with `(1<<128) | 0x87`).
Inversion: Fermat, `a^(2^128 - 2)` (127 squarings, 126 multiplies), or any method with equal
results.

### 5.2 Matrix `A2ONT-GF128-MDS-v1`

Fixed blockwise **Cauchy** matrix, block size `b = field_block_symbols = 16`:

```
M[i][j] = inverse( elem(i) XOR elem(b + j) )      for i, j in [0, b)
```

where `elem(n)` is the integer `n` as a field element. `i XOR (b+j) ≠ 0` always (bit 4 set), all
`x_i`/`y_j` distinct ⇒ Cauchy ⇒ invertible and **superregular** (every square submatrix
invertible), which satisfies agenda §7.4 including submatrix invertibility for threshold study.
`M⁻¹` is computed once by Gauss–Jordan elimination over GF(2^128); implementations must verify
`M·M⁻¹ = I` at initialization or in tests.

### 5.3 Core application

Input bytes are parsed into `s = L / 16` symbols (§5.1 mapping), processed in consecutive blocks
of `b` symbols. A trailing block of `s mod b` symbols uses the leading principal
`(s mod b)×(s mod b)` submatrix of `M` (invertible by superregularity). Within a block
(row-vector × matrix):

```
V[j] = XOR_{i=0..b-1}  U[i] ⊗ M[i][j]
```

Inverse uses `M⁻¹` identically. With `matrix_id = "off"` (ablation), the core is the identity
(the symbol mask of §7.1 still applies).

Honest scope note (documented also in the design doc): with the blockwise default, the
*field-core* undetermined-set property is per 256-byte block; *global* all-or-nothing dependency
is provided by seed hiding (§8) — any missing output bits corrupt recovery of `R` and hence the
whole plaintext, with completion cost `2^h` for `h` missing bits.

## 6. Avalanche body (agenda §8–§9)

Round structure for `t = 0 .. round_count-1`, operating on byte array `S` of length `L`:

### 6.1 PermuteBytes

Stream: `PRG_R("perm", t)`. Fisher–Yates over `π = [0..L-1]`:
`for i = L-1 downto 1: j = UniformInteger(stream, i+1); swap π[i], π[j]`.
Apply **gather**: `T[i] = S[π[i]]`. Inverse applies `π⁻¹` the same way.

### 6.2 BitPreMix (default `"perm8-lehmer-stream-v1"`)

Stream: `PRG_R("bit-premix", t)`. For `i = 0 .. L-1` (sequential stream consumption):
`idx_i = UniformInteger(stream, 40320)`; `ρ = UnrankPermutation(idx_i, 8)` (Lehmer, §6.3);
`S[i] = BitPermute8(S[i], ρ)` where **output bit `k` = input bit `ρ[k]`**:

```
out = 0; for k in 0..7: out |= ((in >> ρ[k]) & 1) << k
```

Inverse uses `ρ⁻¹` (`ρ⁻¹[ρ[k]] = k`).

### 6.3 Lehmer unranking (normative) and per-byte variant

`UnrankPermutation(idx, m)`: factorial-base digits, selecting from the **ascending** remaining
list:

```
elems = [0,1,...,m-1]
for pos in 0..m-1:
    f = (m-1-pos)!
    d = idx / f ; idx = idx mod f
    ρ[pos] = elems[d] ; remove elems[d]
```

Profile `"perm8-lehmer-perbyte"` (agenda §9.5 literal): per byte `i`, a fresh stream
`PRG_R("bit-premix", t, extra = enc_int(i))` provides the draws for `idx_i`. Semantically
equivalent domain separation; costs one KMAC per byte, so it is not the default (see
understanding report §6.2).

### 6.4 XOR mask

`Mask = PRG_R("mask", t)`, first `L` bytes; `S[i] ^= Mask[i]`. Self-inverse.
(Described as seed-derived bit-flip whitening — not encryption.)

### 6.5 AR32

`L mod 4 = 0` guaranteed. `W[j]` = LE u32 words of `S`, `wc = L/4`.
Streams: `A = PRG_R("add", t)` (4·wc bytes, `A_j` = LE u32 at offset 4j);
`Q = PRG_R("mul", t)` (4·wc bytes, `Q_j = (LE u32) | 1`);
`r = PRG_R("rot32", t)` (wc bytes, `r_j = byte mod 32` — bias-free).

```
forward:  W[j] = ROTL32( ((W[j] + A_j) mod 2^32) · Q_j mod 2^32 , r_j )
inverse:  u = ROTR32(W[j], r_j); v = u · Q_j⁻¹ mod 2^32; W[j] = (v − A_j) mod 2^32
```

`Q_j⁻¹` = modular inverse of odd `Q_j` mod 2^32 (Newton: `x ← x·(2 − Q·x)`, 5 iterations from
`x = Q`).

### 6.6 MDS `A2ONT-MDS4-v1`

GF(2^8) with reduction polynomial `0x11B`. Fixed involutory Hadamard-type matrix

```
M8 = [ 01 02 04 06
       02 01 06 04
       04 06 01 02
       06 04 02 01 ]          (hex entries)
```

which is MDS (all minors of all orders nonsingular — verified computationally in tests) and
**involutory** (`M8 = M8⁻¹` over 0x11B), so encode and decode use the same matrix.
For each consecutive 4-byte group `x`: `y_i = XOR_j M8[i][j] ⊗ x_j` (column-vector convention).

### 6.7 Chains (default `chain_operator = "modular-addition"`)

`C_f = PRG_R("fwd-chain", t)`, `C_b = PRG_R("bwd-chain", t)`, `L` bytes each. All mod 256.

```
forward:   F[0] = S[0] + C_f[0] ;  F[i] = S[i] + F[i-1] + C_f[i]
backward:  S'[L-1] = F[L-1] + C_b[L-1] ;  S'[i] = F[i] + S'[i+1] + C_b[i]   (i = L-2 .. 0)
inv bwd:   F[L-1] = S'[L-1] − C_b[L-1] ;  F[i] = S'[i] − S'[i+1] − C_b[i]
inv fwd:   S[0] = F[0] − C_f[0] ;  S[i] = F[i] − F[i-1] − C_f[i]
```

XOR-chain ablation replaces `+`/`−` by XOR.

## 7. Full transform

**Encode(B, ctx, profile):** validate `L`; `R ← RNG(32)`;
`U = B XOR PRG_R("symbol-mask", 0)[0..L)`; threshold core (§5) → `S`;
rounds `t = 0..rc-1`: Permute → BitPreMix → XOR mask → AR32 → MDS → FwdChain → BwdChain;
`Y = S`; `Y_extra = R XOR H_mask(ctx, Y)`; output `Y ‖ Y_extra`.

**H_mask (seed hiding; binds all profile parameters):**

```
H_mask = SHAKE256(
    "A2ONT-seed-hide-v1"              # 18 raw bytes
  ‖ enc_bytes(ctx)
  ‖ enc_str(profile_id)
  ‖ enc_int(L)
  ‖ enc_int(seed_len_bytes)
  ‖ enc_int(security_symbol_bits)
  ‖ enc_int(missing_symbol_threshold)
  ‖ enc_int(round_count)
  ‖ enc_str(matrix_id)
  ‖ enc_str(mds_id)
  ‖ Y,                                # raw, last field
  out_len = seed_len_bytes )
```

**Decode(Y‖Y_extra, ctx, profile):** split (`L = total − 32`; validate);
`R = Y_extra XOR H_mask(ctx, Y)`; invert rounds `t = rc-1..0` (InvBwdChain, InvFwdChain, InvMDS
(= MDS, involutory), InvAR32, XOR mask, InvBitPreMix, InvPermute); invert core (`M⁻¹`);
`B = U XOR PRG_R("symbol-mask", 0)`. Errors never return partial plaintext.

## 8. Serialization (agenda §14)

Raw package = `Y ‖ Y_extra`. Container format `"A2ONT-container-v1"`:

```
magic "A2ONT" (5B) ‖ u16le(version=1) ‖ enc_str(profile_id) ‖ enc_int(L)
‖ enc_int(seed_len_bytes) ‖ enc_int(security_symbol_bits) ‖ enc_int(missing_symbol_threshold)
‖ enc_int(round_count) ‖ enc_str(hash_xof_id) ‖ enc_str(seed_prg_id) ‖ enc_str(matrix_id)
‖ enc_str(mds_id) ‖ enc_str(padding_policy_id) ‖ Y ‖ Y_extra
```

The header bytes (everything before `Y`) must be fed as AAD to the downstream AEAD when used in
the vault pipeline. Header fields must match the profile at decode or decoding fails
(`ERR_INVALID_PROFILE`).

## 9. Error model (agenda §28.2)

`OK / ERR_INVALID_LENGTH / ERR_INVALID_PROFILE / ERR_UNSUPPORTED_BACKEND / ERR_DECODE_FAILED /
ERR_RNG_FAILED / ERR_ALLOCATION_FAILED / ERR_INTERNAL` (C ints; Python exceptions carrying the
same codes).

## 10. Test vectors (agenda §29)

JSON files in `vectors/`, fields: `name, profile_id, ctx_hex, input_hex, seed_hex, Y_hex,
Y_extra_hex, output_hex` (+ optional `notes`). Deterministic: `seed_hex` is fixed per vector;
vectors are generated via the test-only deterministic-seed entry point. Classes: minimal 16 B,
64 B, 1 KiB, 64 KiB structured vault, all-zero, all-0xFF, repeated pattern, random, single-bit
flip pair, cross-language full vector (plus each ablation profile at 64 B, and an `L = 0` vector).
Cross-language rule: C and Python must reproduce `Y_hex ‖ Y_extra_hex` byte-for-byte.

## 11. Sensitive-data handling

Wipe (best effort in Python via `bytearray` zeroization; guaranteed-not-elided wipes in C):
`R`, PRG/mask streams, intermediate `S/U/V` buffers, decoded plaintext on error paths, field
temporaries. Never log seeds, streams, plaintext, or intermediate state (deterministic public
test-vector runs excepted, per agenda). Seeds are sensitive until AEAD completes.
