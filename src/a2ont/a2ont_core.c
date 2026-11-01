/* Full A2ONT v1.0 pipeline (agenda sections 10-11).
 *
 * SECURITY POSITIONING: A2ONT is not encryption; it is a reversible,
 * seed-hidden pre-encryption encoding. AEAD after A2ONT is mandatory.
 * Decode never emits partial plaintext on failure. */
#include <stdlib.h>
#include <string.h>

#include "secraxis/a2ont.h"
#include "encoding.h"
#include "keccak.h"
#include "prg.h"
#include "profile_internal.h"
#include "transforms.h"
#include "wipe.h"

#define SEED_HIDE_PREFIX "A2ONT-seed-hide-v1"

void a2ont_seed_hide_mask(const uint8_t *ctx, size_t ctx_len, const uint8_t *y,
                          size_t y_len, const a2ont_iprofile *ip, uint8_t *out)
{
    a2ont_sponge sp;
    a2ont_shake256_init(&sp);
    a2ont_sponge_absorb(&sp, (const uint8_t *)SEED_HIDE_PREFIX,
                        sizeof SEED_HIDE_PREFIX - 1);
    a2ont_absorb_enc_bytes(&sp, ctx, ctx_len);
    a2ont_absorb_enc_str(&sp, ip->name);
    a2ont_absorb_enc_int(&sp, (uint64_t)y_len);
    a2ont_absorb_enc_int(&sp, ip->seed_len_bytes);
    a2ont_absorb_enc_int(&sp, ip->security_symbol_bits);
    a2ont_absorb_enc_int(&sp, ip->missing_symbol_threshold);
    a2ont_absorb_enc_int(&sp, ip->round_count);
    a2ont_absorb_enc_str(&sp, ip->matrix_name);
    a2ont_absorb_enc_str(&sp, ip->mds_name);
    if (y_len)
        a2ont_sponge_absorb(&sp, y, y_len);
    a2ont_sponge_squeeze(&sp, out, ip->seed_len_bytes);
    a2ont_sponge_wipe(&sp);
}

static int symbol_mask(uint8_t *s, size_t L, const uint8_t *seed,
                       const a2ont_iprofile *ip)
{
    a2ont_prg prg;
    uint8_t buf[4096];
    size_t done = 0;
    if (L == 0)
        return A2ONT_OK;
    a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "symbol-mask", 0, L, ip,
                   NULL, 0);
    while (done < L) {
        size_t n = L - done < sizeof buf ? L - done : sizeof buf;
        size_t i;
        a2ont_prg_read(&prg, buf, n);
        for (i = 0; i < n; i++)
            s[done + i] ^= buf[i];
        done += n;
    }
    a2ont_prg_close(&prg);
    a2ont_secure_wipe_impl(buf, sizeof buf);
    return A2ONT_OK;
}

static int body_forward(uint8_t *s, size_t L, const uint8_t *seed,
                        const a2ont_iprofile *ip)
{
    uint64_t t;
    int rc;
    if ((rc = symbol_mask(s, L, seed, ip)) != A2ONT_OK)
        return rc;
    if ((rc = a2ont_field_mix(s, L, ip, 0)) != A2ONT_OK)
        return rc;
    for (t = 0; t < ip->round_count; t++) {
        if ((rc = a2ont_permute(s, L, seed, t, ip, 0)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_bit_premix(s, L, seed, t, ip, 0)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_xor_mask(s, L, seed, t, ip)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_ar32(s, L, seed, t, ip, 0)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_mds(s, L, ip, 0)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_chain_forward(s, L, seed, t, ip, 0)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_chain_backward(s, L, seed, t, ip, 0)) != A2ONT_OK)
            return rc;
    }
    return A2ONT_OK;
}

static int body_inverse(uint8_t *s, size_t L, const uint8_t *seed,
                        const a2ont_iprofile *ip)
{
    uint64_t t;
    int rc;
    for (t = ip->round_count; t-- > 0;) {
        if ((rc = a2ont_chain_backward(s, L, seed, t, ip, 1)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_chain_forward(s, L, seed, t, ip, 1)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_mds(s, L, ip, 1)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_ar32(s, L, seed, t, ip, 1)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_xor_mask(s, L, seed, t, ip)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_bit_premix(s, L, seed, t, ip, 1)) != A2ONT_OK)
            return rc;
        if ((rc = a2ont_permute(s, L, seed, t, ip, 1)) != A2ONT_OK)
            return rc;
    }
    if ((rc = a2ont_field_mix(s, L, ip, 1)) != A2ONT_OK)
        return rc;
    return symbol_mask(s, L, seed, ip);
}

static int encode_impl(const uint8_t *input, size_t input_len,
                       const uint8_t *ctx, size_t ctx_len,
                       const a2ont_iprofile *ip, const uint8_t *seed,
                       uint8_t *output, size_t output_len)
{
    int rc;
    uint8_t hmask[64];
    uint32_t k;
    if (output_len != input_len + ip->y_extra_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    if (input_len && (input == NULL || output == NULL))
        return A2ONT_ERR_INVALID_LENGTH;
    if (input_len)
        memcpy(output, input, input_len);
    rc = body_forward(output, input_len, seed, ip);
    if (rc != A2ONT_OK) {
        a2ont_secure_wipe_impl(output, output_len);
        return rc;
    }
    a2ont_seed_hide_mask(ctx, ctx_len, output, input_len, ip, hmask);
    for (k = 0; k < ip->seed_len_bytes; k++)
        output[input_len + k] = (uint8_t)(seed[k] ^ hmask[k]);
    a2ont_secure_wipe_impl(hmask, sizeof hmask);
    return A2ONT_OK;
}

int a2ont_encode(const uint8_t *input, size_t input_len,
                 const uint8_t *ctx, size_t ctx_len,
                 const a2ont_profile_t *profile,
                 uint8_t *output, size_t output_len)
{
    const a2ont_iprofile *ip;
    uint8_t seed[64];
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if ((rc = a2ont_iprofile_check_len(ip, input_len)) != A2ONT_OK)
        return rc;
    if (a2ont_rng_bytes(seed, ip->seed_len_bytes) != A2ONT_OK)
        return A2ONT_ERR_RNG_FAILED;
    rc = encode_impl(input, input_len, ctx, ctx_len, ip, seed, output,
                     output_len);
    a2ont_secure_wipe_impl(seed, sizeof seed);
    return rc;
}

int a2ont_decode(const uint8_t *input, size_t input_len,
                 const uint8_t *ctx, size_t ctx_len,
                 const a2ont_profile_t *profile,
                 uint8_t *output, size_t output_len)
{
    const a2ont_iprofile *ip;
    size_t L;
    uint8_t hmask[64], seed[64];
    uint32_t k;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if (input_len < ip->y_extra_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    L = input_len - ip->y_extra_len_bytes;
    if ((rc = a2ont_iprofile_check_len(ip, L)) != A2ONT_OK)
        return rc;
    if (output_len != L)
        return A2ONT_ERR_INVALID_LENGTH;
    if (L && (input == NULL || output == NULL))
        return A2ONT_ERR_INVALID_LENGTH;
    a2ont_seed_hide_mask(ctx, ctx_len, input, L, ip, hmask);
    for (k = 0; k < ip->seed_len_bytes; k++)
        seed[k] = (uint8_t)(input[L + k] ^ hmask[k]);
    a2ont_secure_wipe_impl(hmask, sizeof hmask);
    if (L)
        memcpy(output, input, L);
    rc = body_inverse(output, L, seed, ip);
    a2ont_secure_wipe_impl(seed, sizeof seed);
    if (rc != A2ONT_OK) {
        a2ont_secure_wipe_impl(output, output_len); /* no partial plaintext */
        return rc == A2ONT_ERR_ALLOCATION_FAILED ? rc : A2ONT_ERR_DECODE_FAILED;
    }
    return A2ONT_OK;
}

void a2ont_secure_wipe(void *buf, size_t len)
{
    a2ont_secure_wipe_impl(buf, len);
}

/* ---------------- deterministic test-only entry points ---------------- */
#ifdef A2ONT_TEST_ONLY
int a2ont_encode_with_seed(const uint8_t *input, size_t input_len,
                           const uint8_t *ctx, size_t ctx_len,
                           const a2ont_profile_t *profile,
                           const uint8_t *seed, size_t seed_len,
                           uint8_t *output, size_t output_len)
{
    const a2ont_iprofile *ip;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if ((rc = a2ont_iprofile_check_len(ip, input_len)) != A2ONT_OK)
        return rc;
    if (seed_len != ip->seed_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    return encode_impl(input, input_len, ctx, ctx_len, ip, seed, output,
                       output_len);
}

int a2ont_encode_body(const uint8_t *input, size_t input_len,
                      const uint8_t *seed, size_t seed_len,
                      const a2ont_profile_t *profile, uint8_t *output)
{
    const a2ont_iprofile *ip;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if ((rc = a2ont_iprofile_check_len(ip, input_len)) != A2ONT_OK)
        return rc;
    if (seed_len != ip->seed_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    if (input_len)
        memcpy(output, input, input_len);
    return body_forward(output, input_len, seed, ip);
}

int a2ont_decode_body(const uint8_t *y, size_t y_len,
                      const uint8_t *seed, size_t seed_len,
                      const a2ont_profile_t *profile, uint8_t *output)
{
    const a2ont_iprofile *ip;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if ((rc = a2ont_iprofile_check_len(ip, y_len)) != A2ONT_OK)
        return rc;
    if (seed_len != ip->seed_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    if (y_len)
        memcpy(output, y, y_len);
    return body_inverse(output, y_len, seed, ip);
}

int a2ont_prg_bytes(const uint8_t *seed, size_t seed_len, const char *label,
                    uint64_t round_index, uint64_t total_len,
                    const a2ont_profile_t *profile,
                    const uint8_t *extra, size_t extra_len, int has_extra,
                    uint8_t *out, size_t out_len)
{
    const a2ont_iprofile *ip;
    a2ont_prg prg;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if (seed_len != ip->seed_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    a2ont_prg_open(&prg, seed, seed_len, label, round_index, total_len, ip,
                   has_extra ? extra : NULL, has_extra ? extra_len : 0);
    a2ont_prg_read(&prg, out, out_len);
    a2ont_prg_close(&prg);
    return A2ONT_OK;
}
#endif
