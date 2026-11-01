#include "keccak.h"

#include <string.h>

#include "wipe.h"

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* rotation offsets for lane x + 5y */
static const unsigned RHO[25] = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
};

static uint64_t rotl64(uint64_t v, unsigned r)
{
    return r ? ((v << r) | (v >> (64u - r))) : v;
}

static void keccak_f1600(uint64_t a[25])
{
    uint64_t b[25], c[5], d[5];
    int round, x, y;
    for (round = 0; round < 24; round++) {
        for (x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (x = 0; x < 5; x++)
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (x = 0; x < 5; x++)
            for (y = 0; y < 25; y += 5)
                a[x + y] ^= d[x];
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], RHO[x + 5 * y]);
        for (y = 0; y < 25; y += 5) {
            uint64_t b0 = b[y], b1 = b[y + 1], b2 = b[y + 2], b3 = b[y + 3], b4 = b[y + 4];
            a[y] = b0 ^ ((~b1) & b2);
            a[y + 1] = b1 ^ ((~b2) & b3);
            a[y + 2] = b2 ^ ((~b3) & b4);
            a[y + 3] = b3 ^ ((~b4) & b0);
            a[y + 4] = b4 ^ ((~b0) & b1);
        }
        a[0] ^= RC[round];
    }
    a2ont_secure_wipe_impl(b, sizeof b);
    a2ont_secure_wipe_impl(c, sizeof c);
    a2ont_secure_wipe_impl(d, sizeof d);
}

static void absorb_block(a2ont_sponge *sp, const uint8_t *block)
{
    size_t i;
    for (i = 0; i < A2ONT_KECCAK_RATE256 / 8; i++) {
        uint64_t lane = 0;
        size_t k;
        for (k = 0; k < 8; k++)
            lane |= (uint64_t)block[8 * i + k] << (8 * k);
        sp->state[i] ^= lane;
    }
    keccak_f1600(sp->state);
}

void a2ont_sponge_init(a2ont_sponge *sp, uint8_t domain_suffix)
{
    memset(sp, 0, sizeof *sp);
    sp->domain_suffix = domain_suffix;
}

void a2ont_sponge_absorb(a2ont_sponge *sp, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t take = A2ONT_KECCAK_RATE256 - sp->buf_used;
        if (take > len)
            take = len;
        memcpy(sp->buf + sp->buf_used, data, take);
        sp->buf_used += take;
        data += take;
        len -= take;
        if (sp->buf_used == A2ONT_KECCAK_RATE256) {
            absorb_block(sp, sp->buf);
            sp->buf_used = 0;
        }
    }
}

static void pad_and_switch(a2ont_sponge *sp)
{
    memset(sp->buf + sp->buf_used, 0, A2ONT_KECCAK_RATE256 - sp->buf_used);
    sp->buf[sp->buf_used] ^= sp->domain_suffix;
    sp->buf[A2ONT_KECCAK_RATE256 - 1] ^= 0x80;
    absorb_block(sp, sp->buf);
    sp->squeezing = 1;
    sp->squeeze_off = A2ONT_KECCAK_RATE256; /* force refill */
}

static void refill(a2ont_sponge *sp)
{
    size_t i, k;
    for (i = 0; i < A2ONT_KECCAK_RATE256 / 8; i++)
        for (k = 0; k < 8; k++)
            sp->buf[8 * i + k] = (uint8_t)(sp->state[i] >> (8 * k));
    keccak_f1600(sp->state);
    sp->squeeze_off = 0;
}

void a2ont_sponge_squeeze(a2ont_sponge *sp, uint8_t *out, size_t len)
{
    if (!sp->squeezing)
        pad_and_switch(sp);
    while (len > 0) {
        size_t avail, take;
        if (sp->squeeze_off == A2ONT_KECCAK_RATE256)
            refill(sp);
        avail = A2ONT_KECCAK_RATE256 - sp->squeeze_off;
        take = avail < len ? avail : len;
        memcpy(out, sp->buf + sp->squeeze_off, take);
        sp->squeeze_off += take;
        out += take;
        len -= take;
    }
}

void a2ont_sponge_wipe(a2ont_sponge *sp)
{
    a2ont_secure_wipe_impl(sp, sizeof *sp);
}

/* -------------------- SP 800-185 helpers -------------------- */

size_t a2ont_left_encode(uint64_t x, uint8_t out[9])
{
    uint8_t tmp[8];
    size_t n = 0, i;
    do {
        tmp[n++] = (uint8_t)(x & 0xFF);
        x >>= 8;
    } while (x);
    out[0] = (uint8_t)n;
    for (i = 0; i < n; i++)
        out[1 + i] = tmp[n - 1 - i]; /* big-endian */
    return n + 1;
}

size_t a2ont_right_encode(uint64_t x, uint8_t out[9])
{
    uint8_t tmp[8];
    size_t n = 0, i;
    do {
        tmp[n++] = (uint8_t)(x & 0xFF);
        x >>= 8;
    } while (x);
    for (i = 0; i < n; i++)
        out[i] = tmp[n - 1 - i];
    out[n] = (uint8_t)n;
    return n + 1;
}

void a2ont_absorb_encoded_string(a2ont_sponge *sp, const uint8_t *s, size_t len)
{
    uint8_t enc[9];
    size_t n = a2ont_left_encode((uint64_t)len * 8u, enc);
    a2ont_sponge_absorb(sp, enc, n);
    if (len)
        a2ont_sponge_absorb(sp, s, len);
}

/* absorb bytepad prefix left_encode(w) and track padding to w manually:
 * callers absorb their content then call pad_to_rate to zero-fill. */
static void absorb_zeros_to_block_boundary(a2ont_sponge *sp)
{
    static const uint8_t zeros[64] = {0};
    size_t rem = sp->buf_used % A2ONT_KECCAK_RATE256;
    size_t need = rem ? (A2ONT_KECCAK_RATE256 - rem) : 0;
    /* buf_used is always < rate; zero-fill to complete the block */
    while (need > 0) {
        size_t take = need < sizeof zeros ? need : sizeof zeros;
        a2ont_sponge_absorb(sp, zeros, take);
        need -= take;
    }
}

void a2ont_shake256_init(a2ont_sponge *sp)
{
    a2ont_sponge_init(sp, 0x1F);
}

void a2ont_cshake256_init(a2ont_sponge *sp, const uint8_t *n, size_t n_len,
                          const uint8_t *s, size_t s_len)
{
    if (n_len == 0 && s_len == 0) {
        a2ont_shake256_init(sp);
        return;
    }
    a2ont_sponge_init(sp, 0x04);
    {
        uint8_t enc[9];
        size_t m = a2ont_left_encode(A2ONT_KECCAK_RATE256, enc);
        a2ont_sponge_absorb(sp, enc, m);
    }
    a2ont_absorb_encoded_string(sp, n, n_len);
    a2ont_absorb_encoded_string(sp, s, s_len);
    absorb_zeros_to_block_boundary(sp);
}

void a2ont_kmacxof256_begin(a2ont_sponge *sp, const uint8_t *key, size_t key_len,
                            const uint8_t *custom, size_t custom_len)
{
    a2ont_cshake256_init(sp, (const uint8_t *)"KMAC", 4, custom, custom_len);
    {
        uint8_t enc[9];
        size_t m = a2ont_left_encode(A2ONT_KECCAK_RATE256, enc);
        a2ont_sponge_absorb(sp, enc, m);
    }
    a2ont_absorb_encoded_string(sp, key, key_len);
    absorb_zeros_to_block_boundary(sp);
    /* caller now absorbs X, then calls finish() */
}

void a2ont_kmacxof256_finish(a2ont_sponge *sp)
{
    uint8_t enc[9];
    size_t n = a2ont_right_encode(0, enc);
    a2ont_sponge_absorb(sp, enc, n);
}
