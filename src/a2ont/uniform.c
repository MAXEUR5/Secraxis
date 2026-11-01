#include "uniform.h"

uint64_t a2ont_uniform_int(a2ont_prg *prg, uint64_t n)
{
    unsigned k;
    uint64_t space, limit;
    if (n <= 1)
        return 0;
    k = 1;
    space = 256;
    while (space < n) { /* n <= 2^31 in practice; loop terminates */
        space <<= 8;
        k++;
    }
    limit = (space / n) * n;
    for (;;) {
        uint8_t buf[8];
        uint64_t u = 0;
        unsigned i;
        a2ont_prg_read(prg, buf, k);
        for (i = 0; i < k; i++)
            u |= (uint64_t)buf[i] << (8 * i); /* little-endian */
        if (u < limit)
            return u % n;
    }
}
