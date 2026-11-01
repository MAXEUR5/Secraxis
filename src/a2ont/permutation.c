#include <stdlib.h>
#include <string.h>

#include "secraxis/a2ont.h"
#include "transforms.h"
#include "prg.h"
#include "uniform.h"
#include "wipe.h"

int a2ont_permute(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                  const a2ont_iprofile *ip, int inverse)
{
    a2ont_prg prg;
    uint32_t *perm;
    uint8_t *tmp;
    size_t i;
    if (L == 0)
        return A2ONT_OK;
    perm = (uint32_t *)malloc(L * sizeof(uint32_t));
    tmp = (uint8_t *)malloc(L);
    if (perm == NULL || tmp == NULL) {
        free(perm);
        free(tmp);
        return A2ONT_ERR_ALLOCATION_FAILED;
    }
    for (i = 0; i < L; i++)
        perm[i] = (uint32_t)i;
    a2ont_prg_open(&prg, seed, ip->seed_len_bytes, "perm", t, L, ip, NULL, 0);
    for (i = L - 1; i >= 1; i--) {
        uint64_t j = a2ont_uniform_int(&prg, (uint64_t)i + 1);
        uint32_t sw = perm[i];
        perm[i] = perm[j];
        perm[j] = sw;
    }
    a2ont_prg_close(&prg);
    if (!inverse) {
        for (i = 0; i < L; i++)
            tmp[i] = s[perm[i]];
    } else {
        /* apply pi^{-1} as a gather: tmp[i] = s[pi_inv[i]] <=> tmp[pi[i]] = s[i] */
        for (i = 0; i < L; i++)
            tmp[perm[i]] = s[i];
    }
    memcpy(s, tmp, L);
    a2ont_secure_wipe_impl(tmp, L);
    a2ont_secure_wipe_impl(perm, L * sizeof(uint32_t));
    free(tmp);
    free(perm);
    return A2ONT_OK;
}
