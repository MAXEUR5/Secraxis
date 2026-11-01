/* MDS4 "A2ONT-MDS4-v1": involutory Hadamard had(01,02,04,06) over
 * GF(2^8)/0x11B (verified MDS + involutory in tests). */
#include "secraxis/a2ont.h"
#include "transforms.h"

static const uint8_t HROW[4] = {0x01, 0x02, 0x04, 0x06};

static uint8_t T1[256], T2[256], T4[256], T6[256];
static volatile int MDS_READY = 0;

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    unsigned r = 0, aa = a, bb = b;
    while (bb) {
        if (bb & 1)
            r ^= aa;
        bb >>= 1;
        aa <<= 1;
        if (aa & 0x100)
            aa ^= 0x11B;
    }
    return (uint8_t)r;
}

static void ensure_tables(void)
{
    if (!MDS_READY) {
        unsigned x;
        for (x = 0; x < 256; x++) {
            T1[x] = (uint8_t)x;
            T2[x] = gf256_mul(0x02, (uint8_t)x);
            T4[x] = gf256_mul(0x04, (uint8_t)x);
            T6[x] = gf256_mul(0x06, (uint8_t)x);
        }
        MDS_READY = 1;
    }
}

static const uint8_t *table_for(uint8_t c)
{
    switch (c) {
    case 0x01: return T1;
    case 0x02: return T2;
    case 0x04: return T4;
    default: return T6;
    }
}

int a2ont_mds(uint8_t *s, size_t L, const a2ont_iprofile *ip, int inverse)
{
    size_t base;
    const uint8_t *m00, *m01, *m02, *m03;
    (void)inverse; /* involutory: same matrix both directions */
    if (ip->mds_id == A2ONT_MDS_OFF || L == 0)
        return A2ONT_OK;
    ensure_tables();
    m00 = table_for(HROW[0]);
    m01 = table_for(HROW[1]);
    m02 = table_for(HROW[2]);
    m03 = table_for(HROW[3]);
    for (base = 0; base + 4 <= L; base += 4) {
        uint8_t x0 = s[base], x1 = s[base + 1], x2 = s[base + 2], x3 = s[base + 3];
        /* Hadamard rows: row i entry j = HROW[i^j] */
        s[base + 0] = (uint8_t)(m00[x0] ^ m01[x1] ^ m02[x2] ^ m03[x3]);
        s[base + 1] = (uint8_t)(m01[x0] ^ m00[x1] ^ m03[x2] ^ m02[x3]);
        s[base + 2] = (uint8_t)(m02[x0] ^ m03[x1] ^ m00[x2] ^ m01[x3]);
        s[base + 3] = (uint8_t)(m03[x0] ^ m02[x1] ^ m01[x2] ^ m00[x3]);
    }
    return A2ONT_OK;
}
