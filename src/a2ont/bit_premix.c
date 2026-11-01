#include <string.h>

#include "secraxis/a2ont.h"
#include "encoding.h"
#include "transforms.h"
#include "prg.h"
#include "uniform.h"

#define FACT8 40320u

/* all 8-element permutations by Lehmer rank: 40320 x 8 = 322 KB, built once */
static uint8_t PERMS[FACT8][8];
static volatile int PERMS_READY = 0;

static const unsigned FACTS[8] = {5040, 720, 120, 24, 6, 2, 1, 1};

static void unrank8(unsigned idx, uint8_t out[8])
{
    uint8_t elems[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    unsigned pos, k;
    for (pos = 0; pos < 8; pos++) {
        unsigned f = FACTS[pos];
        unsigned d = idx / f;
        idx %= f;
        out[pos] = elems[d];
        for (k = d; k < 7u - pos; k++)
            elems[k] = elems[k + 1];
    }
}

static void ensure_perms(void)
{
    if (!PERMS_READY) {
        unsigned i;
        for (i = 0; i < FACT8; i++)
            unrank8(i, PERMS[i]);
        PERMS_READY = 1; /* idempotent build; racing builders write same data */
    }
}

static uint8_t permute_bits(uint8_t in, const uint8_t rho[8])
{
    unsigned k;
    uint8_t out = 0;
    for (k = 0; k < 8; k++)
        out |= (uint8_t)(((in >> rho[k]) & 1u) << k);
    return out;
}

int a2ont_bit_premix(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                     const a2ont_iprofile *ip, int inverse)
{
    size_t i;
    if (ip->bit_premix == A2ONT_BPM_OFF || L == 0)
        return A2ONT_OK;
    ensure_perms();
    if (ip->bit_premix == A2ONT_BPM_STREAM) {
        a2ont_prg prg;
        a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "bit-premix", t, L, ip,
                       NULL, 0);
        for (i = 0; i < L; i++) {
            unsigned idx = (unsigned)a2ont_uniform_int(&prg, FACT8);
            const uint8_t *rho = PERMS[idx];
            uint8_t inv[8];
            if (inverse) {
                unsigned k;
                for (k = 0; k < 8; k++)
                    inv[rho[k]] = (uint8_t)k;
                s[i] = permute_bits(s[i], inv);
            } else {
                s[i] = permute_bits(s[i], rho);
            }
        }
        a2ont_prg_close(&prg);
        return A2ONT_OK;
    }
    /* per-byte profile variant (agenda 9.5 literal) */
    for (i = 0; i < L; i++) {
        a2ont_prg prg;
        uint8_t extra[8];
        unsigned idx;
        const uint8_t *rho;
        a2ont_put_u64le(extra, (uint64_t)i);
        a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "bit-premix", t, L, ip,
                       extra, 8);
        idx = (unsigned)a2ont_uniform_int(&prg, FACT8);
        a2ont_prg_close(&prg);
        rho = PERMS[idx];
        if (inverse) {
            uint8_t inv[8];
            unsigned k;
            for (k = 0; k < 8; k++)
                inv[rho[k]] = (uint8_t)k;
            s[i] = permute_bits(s[i], inv);
        } else {
            s[i] = permute_bits(s[i], rho);
        }
    }
    return A2ONT_OK;
}
