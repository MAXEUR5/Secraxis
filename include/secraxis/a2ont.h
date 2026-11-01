/* a2ont.h — A2ONT v1.0 public C API (liba2ont).
 *
 * A2ONT is a reversible, randomized, seed-hidden, AONT-derived
 * PRE-ENCRYPTION encoding transform. It is NOT encryption, NOT AEAD,
 * NOT a MAC. Confidentiality and integrity MUST be provided by a
 * standard AEAD layer applied after A2ONT.
 *
 * All-or-nothing statements are missing-entropy statements: h unknown
 * output bits imply at most 2^h candidate completions (missing 1 byte
 * => at most 2^8). ~128-bit recovery hardness applies only when at
 * least one full 128-bit security symbol (or >= 128 output bits) is
 * missing.
 */
#ifndef A2ONT_H
#define A2ONT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A2ONT_VERSION_MAJOR 1
#define A2ONT_VERSION_MINOR 0
#define A2ONT_VERSION_PATCH 0

/* ---- error codes (agenda 28.2) ---- */
#define A2ONT_OK 0
#define A2ONT_ERR_INVALID_LENGTH 1
#define A2ONT_ERR_INVALID_PROFILE 2
#define A2ONT_ERR_UNSUPPORTED_BACKEND 3
#define A2ONT_ERR_DECODE_FAILED 4
#define A2ONT_ERR_RNG_FAILED 5
#define A2ONT_ERR_ALLOCATION_FAILED 6
#define A2ONT_ERR_INTERNAL 7

/* ---- numeric profile ids ---- */
#define A2ONT_PROFILE_V1_DEFAULT 1u      /* "A2ONT-v1.0-default"      */
#define A2ONT_PROFILE_V1_STRONG 2u       /* "A2ONT-v1.0-strong" (r=3) */
#define A2ONT_PROFILE_V1_R1 3u           /* "A2ONT-v1.0-r1"           */
#define A2ONT_PROFILE_V1_NO_CORE 4u      /* "A2ONT-v1.0-no-core"      */
#define A2ONT_PROFILE_V1_NO_BITPREMIX 5u /* "A2ONT-v1.0-no-bitpremix" */
#define A2ONT_PROFILE_V1_XOR_CHAINS 6u   /* "A2ONT-v1.0-xor-chains"   */
#define A2ONT_PROFILE_V1_NO_AR32 7u      /* "A2ONT-v1.0-no-ar32"      */
#define A2ONT_PROFILE_V1_SYM256 8u       /* "A2ONT-v1.0-sym256"       */
#define A2ONT_PROFILE_V1_PERBYTE_BPM 9u  /* "A2ONT-v1.0-perbyte-bpm"  */

/* ---- backend ids ---- */
#define A2ONT_HASH_SHAKE256 1u
#define A2ONT_PRG_KMACXOF256 1u
#define A2ONT_MATRIX_OFF 0u
#define A2ONT_MATRIX_GF128_MDS_V1 1u
#define A2ONT_MDS_OFF 0u
#define A2ONT_MDS4_V1 1u

/* Public profile descriptor (agenda 16.1). Fill with a2ont_profile_init. */
typedef struct {
    uint32_t version;              /* 1 */
    uint32_t profile_id;           /* A2ONT_PROFILE_* */
    uint32_t seed_len_bytes;       /* 32 in v1.0 */
    uint32_t security_symbol_bits; /* 128 or 256 */
    uint32_t round_count;          /* 1..16 */
    uint32_t hash_xof_id;          /* A2ONT_HASH_* */
    uint32_t seed_prg_id;          /* A2ONT_PRG_* */
    uint32_t matrix_id;            /* A2ONT_MATRIX_* */
    uint32_t mds_id;               /* A2ONT_MDS_* */
} a2ont_profile_t;

/* Resolve a numeric profile id to a fully populated descriptor. */
int a2ont_profile_init(a2ont_profile_t *profile, uint32_t profile_id);

/* Canonical profile-id string (feeds PRG/seed-hide binding); NULL if unknown. */
const char *a2ont_profile_name(uint32_t profile_id);

/* Output size: input_len + seed_len (Y || Y_extra). 0 on invalid input. */
size_t a2ont_output_len(size_t input_len, const a2ont_profile_t *profile);

/* Validate an input length against the profile (16-byte + symbol multiple). */
int a2ont_check_input_len(size_t input_len, const a2ont_profile_t *profile);

/* A2ONT_Encode(B, ctx, profile) -> Y || Y_extra.
 * output_len must equal a2ont_output_len(input_len, profile).
 * Uses the OS CSPRNG for the seed. Returns A2ONT_OK or an error code. */
int a2ont_encode(const uint8_t *input, size_t input_len,
                 const uint8_t *ctx, size_t ctx_len,
                 const a2ont_profile_t *profile,
                 uint8_t *output, size_t output_len);

/* A2ONT_Decode(Y || Y_extra, ctx, profile) -> B.
 * output_len must equal input_len - seed_len. Never writes partial
 * plaintext on failure. */
int a2ont_decode(const uint8_t *input, size_t input_len,
                 const uint8_t *ctx, size_t ctx_len,
                 const a2ont_profile_t *profile,
                 uint8_t *output, size_t output_len);

/* ---- container header (agenda sect. 14; feed these bytes to AEAD AAD) ---- */
size_t a2ont_header_len(const a2ont_profile_t *profile, size_t input_len);
int a2ont_header_build(const a2ont_profile_t *profile, size_t input_len,
                       uint8_t *out, size_t out_len);
/* Parse+validate a header; on success sets *body_offset and *body_len(=L). */
int a2ont_header_parse(const uint8_t *blob, size_t blob_len,
                       const a2ont_profile_t *expected_profile,
                       size_t *body_offset, size_t *body_len);

/* ---- utilities ---- */
const char *a2ont_error_str(int code);
void a2ont_secure_wipe(void *buf, size_t len); /* not optimized away */
int a2ont_rng_selftest(void);
const char *a2ont_rng_name(void);
uint32_t a2ont_runtime_version(void);

/* ---- deterministic entry points: TEST/VECTOR BUILDS ONLY ---- */
#ifdef A2ONT_TEST_ONLY
int a2ont_encode_with_seed(const uint8_t *input, size_t input_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const a2ont_profile_t *profile,
                           const uint8_t *seed, size_t seed_len,
                           uint8_t *output, size_t output_len);
/* Body-only transforms and PRG stream access for component testing. */
int a2ont_encode_body(const uint8_t *input, size_t input_len,
                      const uint8_t *seed, size_t seed_len,
                      const a2ont_profile_t *profile, uint8_t *output);
int a2ont_decode_body(const uint8_t *y, size_t y_len,
                      const uint8_t *seed, size_t seed_len,
                      const a2ont_profile_t *profile, uint8_t *output);
int a2ont_prg_bytes(const uint8_t *seed, size_t seed_len, const char *label,
                    uint64_t round_index, uint64_t total_len,
                    const a2ont_profile_t *profile,
                    const uint8_t *extra, size_t extra_len, int has_extra,
                    uint8_t *out, size_t out_len);
#endif /* A2ONT_TEST_ONLY */

#ifdef __cplusplus
}
#endif

#endif /* A2ONT_H */
