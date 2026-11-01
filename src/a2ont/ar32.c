#include <string.h>

#include "secraxis/a2ont.h"
#include "encoding.h"
#include "transforms.h"
#include "prg.h"
#include "wipe.h"

static uint32_t rotl32(uint32_t v, unsigned r)
{
    return r ? ((v << r) | (v >> (32u - r))) : v;
}

static uint32_t rotr32(uint32_t v, unsigned r)
{
    return r ? ((v >> r) | (v << (32u - r))) : v;
}

static uint32_t inv_odd_u32(uint32_t q)
{
    uint32_t x = q;
    unsigned i;
    for (i = 0; i < 5; i++)
        x = x * (2u - q * x);
    return x;
}

#define AR32_CHUNK_WORDS 1024u

int a2ont_ar32(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
               const a2ont_iprofile *ip, int inverse)
{
    a2ont_prg prg_a, prg_q, prg_r;
    size_t wc, done;
    uint8_t abuf[4 * AR32_CHUNK_WORDS], qbuf[4 * AR32_CHUNK_WORDS];
    uint8_t rbuf[AR32_CHUNK_WORDS];
    if (!ip->ar32_enabled || L == 0)
        return A2ONT_OK;
    wc = L / 4;
    a2ont_prg_open(&prg_a, seed, ip->seed_len_bytes, "add", t, L, ip, NULL, 0);
    a2ont_prg_open(&prg_q, seed, ip->seed_len_bytes, "mul", t, L, ip, NULL, 0);
    a2ont_prg_open(&prg_r, seed, ip->seed_len_bytes, "rot32", t, L, ip, NULL, 0);
    for (done = 0; done < wc; done += AR32_CHUNK_WORDS) {
        size_t n = wc - done < AR32_CHUNK_WORDS ? wc - done : AR32_CHUNK_WORDS;
        size_t j;
        a2ont_prg_read(&prg_a, abuf, 4 * n);
        a2ont_prg_read(&prg_q, qbuf, 4 * n);
        a2ont_prg_read(&prg_r, rbuf, n);
        for (j = 0; j < n; j++) {
            uint8_t *wp = s + 4 * (done + j);
            uint32_t w = a2ont_get_u32le(wp);
            uint32_t a = a2ont_get_u32le(abuf + 4 * j);
            uint32_t q = a2ont_get_u32le(qbuf + 4 * j) | 1u;
            unsigned r = rbuf[j] & 31u;
            if (!inverse) {
                w = (w + a) * q;
                w = rotl32(w, r);
            } else {
                w = rotr32(w, r);
                w = w * inv_odd_u32(q);
                w = w - a;
            }
            a2ont_put_u32le(wp, w);
        }
    }
    a2ont_prg_close(&prg_a);
    a2ont_prg_close(&prg_q);
    a2ont_prg_close(&prg_r);
    a2ont_secure_wipe_impl(abuf, sizeof abuf);
    a2ont_secure_wipe_impl(qbuf, sizeof qbuf);
    a2ont_secure_wipe_impl(rbuf, sizeof rbuf);
    return A2ONT_OK;
}
