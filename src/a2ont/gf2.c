#include "gf2.h"

#include <stdlib.h>
#include <string.h>

#include "wipe.h"

/* portable once-guard (GCC/Clang builtins; MinGW included) */
#if defined(_WIN32) && defined(_MSC_VER)
#include <windows.h>
static int cas_int(volatile long *p, long expect, long desired)
{
    return InterlockedCompareExchange(p, desired, expect) == expect;
}
typedef volatile long once_t;
#else
typedef volatile int once_t;
static int cas_int(once_t *p, int expect, int desired)
{
    return __sync_bool_compare_and_swap(p, expect, desired);
}
#endif

void a2ont_gf_init(a2ont_gf *gf, unsigned bits)
{
    gf->bits = bits;
    gf->limbs = bits / 64u;
    switch (bits) {
    case 64: gf->poly_low = 0x1BULL; break;   /* x^64+x^4+x^3+x+1 */
    case 128: gf->poly_low = 0x87ULL; break;  /* x^128+x^7+x^2+x+1 */
    case 256: gf->poly_low = 0x425ULL; break; /* x^256+x^10+x^5+x^2+1 */
    default: gf->bits = 0; gf->limbs = 0; gf->poly_low = 0; break;
    }
}

void a2ont_gf_from_bytes(const a2ont_gf *gf, a2ont_gfel *e, const uint8_t *in)
{
    unsigned i, k;
    memset(e, 0, sizeof *e);
    for (i = 0; i < gf->limbs; i++) {
        uint64_t v = 0;
        for (k = 0; k < 8; k++)
            v |= (uint64_t)in[8 * i + k] << (8 * k);
        e->v[i] = v;
    }
}

void a2ont_gf_to_bytes(const a2ont_gf *gf, const a2ont_gfel *e, uint8_t *out)
{
    unsigned i, k;
    for (i = 0; i < gf->limbs; i++)
        for (k = 0; k < 8; k++)
            out[8 * i + k] = (uint8_t)(e->v[i] >> (8 * k));
}

void a2ont_gf_set_u64(a2ont_gfel *e, uint64_t v)
{
    memset(e, 0, sizeof *e);
    e->v[0] = v;
}

int a2ont_gf_is_zero(const a2ont_gf *gf, const a2ont_gfel *e)
{
    unsigned i;
    uint64_t acc = 0;
    for (i = 0; i < gf->limbs; i++)
        acc |= e->v[i];
    return acc == 0;
}

int a2ont_gf_equal(const a2ont_gf *gf, const a2ont_gfel *a, const a2ont_gfel *b)
{
    unsigned i;
    uint64_t acc = 0;
    for (i = 0; i < gf->limbs; i++)
        acc |= a->v[i] ^ b->v[i];
    return acc == 0;
}

void a2ont_gf_add(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a,
                  const a2ont_gfel *b)
{
    unsigned i;
    for (i = 0; i < gf->limbs; i++)
        r->v[i] = a->v[i] ^ b->v[i];
}

static void gf_xtime(const a2ont_gf *gf, a2ont_gfel *e)
{
    unsigned i;
    uint64_t carry = e->v[gf->limbs - 1] >> 63;
    for (i = gf->limbs - 1; i > 0; i--)
        e->v[i] = (e->v[i] << 1) | (e->v[i - 1] >> 63);
    e->v[0] <<= 1;
    if (carry)
        e->v[0] ^= gf->poly_low;
}

void a2ont_gf_mul(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a,
                  const a2ont_gfel *b)
{
    a2ont_gfel acc, cur;
    unsigned limb, bit;
    memset(&acc, 0, sizeof acc);
    cur = *a;
    for (limb = 0; limb < gf->limbs; limb++) {
        uint64_t w = b->v[limb];
        for (bit = 0; bit < 64; bit++) {
            if (w & 1) {
                unsigned i;
                for (i = 0; i < gf->limbs; i++)
                    acc.v[i] ^= cur.v[i];
            }
            w >>= 1;
            gf_xtime(gf, &cur);
        }
    }
    *r = acc;
    a2ont_secure_wipe_impl(&cur, sizeof cur);
}

void a2ont_gf_inv(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a)
{
    /* Fermat: a^(2^bits - 2); addition chain r=a; (bits-2)x {r=r^2*a}; r=r^2 */
    a2ont_gfel acc = *a;
    unsigned i;
    for (i = 0; i + 2 < gf->bits; i++) {
        a2ont_gf_mul(gf, &acc, &acc, &acc);
        a2ont_gf_mul(gf, &acc, &acc, a);
    }
    a2ont_gf_mul(gf, r, &acc, &acc);
    a2ont_secure_wipe_impl(&acc, sizeof acc);
}

void a2ont_gf_wconst_init(const a2ont_gf *gf, a2ont_gf_wconst *w,
                          const a2ont_gfel *c)
{
    a2ont_gfel base = *c;
    unsigned win, v, i;
    w->nwin = gf->bits / 4;
    for (win = 0; win < w->nwin; win++) {
        a2ont_gfel p[4];
        p[0] = base;
        p[1] = p[0]; gf_xtime(gf, &p[1]);
        p[2] = p[1]; gf_xtime(gf, &p[2]);
        p[3] = p[2]; gf_xtime(gf, &p[3]);
        for (v = 0; v < 16; v++) {
            a2ont_gfel acc;
            memset(&acc, 0, sizeof acc);
            for (i = 0; i < 4; i++)
                if (v & (1u << i)) {
                    unsigned k;
                    for (k = 0; k < gf->limbs; k++)
                        acc.v[k] ^= p[i].v[k];
                }
            w->t[win][v] = acc;
        }
        base = p[3];
        gf_xtime(gf, &base);
    }
}

void a2ont_gf_wconst_mul(const a2ont_gf *gf, const a2ont_gf_wconst *w,
                         a2ont_gfel *r, const a2ont_gfel *x)
{
    a2ont_gfel acc;
    unsigned win;
    memset(&acc, 0, sizeof acc);
    for (win = 0; win < w->nwin; win++) {
        unsigned nib = (unsigned)((x->v[win >> 4] >> (4u * (win & 15u))) & 0xF);
        if (nib) {
            const a2ont_gfel *t = &w->t[win][nib];
            unsigned k;
            for (k = 0; k < gf->limbs; k++)
                acc.v[k] ^= t->v[k];
        }
    }
    *r = acc;
}

int a2ont_gf_matrix_invert(const a2ont_gf *gf, unsigned n,
                           const a2ont_gfel in[][A2ONT_GF_MAX_BLOCK],
                           a2ont_gfel out[][A2ONT_GF_MAX_BLOCK])
{
    /* augmented Gauss-Jordan over GF(2^m) */
    a2ont_gfel a[A2ONT_GF_MAX_BLOCK][2 * A2ONT_GF_MAX_BLOCK];
    unsigned i, j, col;
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            a[i][j] = in[i][j];
            memset(&a[i][n + j], 0, sizeof(a2ont_gfel));
        }
        a2ont_gf_set_u64(&a[i][n + i], 1);
    }
    for (col = 0; col < n; col++) {
        unsigned piv = n;
        a2ont_gfel pinv;
        for (i = col; i < n; i++)
            if (!a2ont_gf_is_zero(gf, &a[i][col])) {
                piv = i;
                break;
            }
        if (piv == n)
            return -1;
        if (piv != col)
            for (j = 0; j < 2 * n; j++) {
                a2ont_gfel tmp = a[col][j];
                a[col][j] = a[piv][j];
                a[piv][j] = tmp;
            }
        a2ont_gf_inv(gf, &pinv, &a[col][col]);
        for (j = 0; j < 2 * n; j++)
            a2ont_gf_mul(gf, &a[col][j], &a[col][j], &pinv);
        for (i = 0; i < n; i++) {
            a2ont_gfel f;
            if (i == col || a2ont_gf_is_zero(gf, &a[i][col]))
                continue;
            f = a[i][col];
            for (j = 0; j < 2 * n; j++) {
                a2ont_gfel t;
                a2ont_gf_mul(gf, &t, &f, &a[col][j]);
                a[i][j].v[0] ^= t.v[0];
                a[i][j].v[1] ^= t.v[1];
                a[i][j].v[2] ^= t.v[2];
                a[i][j].v[3] ^= t.v[3];
            }
        }
    }
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++)
            out[i][j] = a[i][n + j];
    return 0;
}

/* ------------------------- global matrix contexts ------------------------ */

typedef struct {
    unsigned bits, block;
    a2ont_gf_matctx *ctx;
    once_t state; /* 0 = uninit, 1 = building, 2 = ready, 3 = failed */
} ctx_slot;

static ctx_slot SLOTS[4] = {
    {128, 16, NULL, 0}, {256, 8, NULL, 0}, {64, 16, NULL, 0}, {128, 4, NULL, 0},
};

static int build_ctx(a2ont_gf_matctx *ctx, unsigned bits, unsigned block)
{
    unsigned i, j;
    a2ont_gf_init(&ctx->gf, bits);
    if (ctx->gf.limbs == 0 || block > A2ONT_GF_MAX_BLOCK)
        return -1;
    ctx->block = block;
    for (i = 0; i < block; i++)
        for (j = 0; j < block; j++) {
            a2ont_gfel x;
            a2ont_gf_set_u64(&x, (uint64_t)(i ^ (block + j)));
            a2ont_gf_inv(&ctx->gf, &ctx->M[i][j], &x);
        }
    if (a2ont_gf_matrix_invert(&ctx->gf, block, ctx->M, ctx->Minv) != 0)
        return -1;
    /* verify M * Minv = I */
    for (i = 0; i < block; i++)
        for (j = 0; j < block; j++) {
            a2ont_gfel acc, t, expect;
            unsigned k;
            memset(&acc, 0, sizeof acc);
            for (k = 0; k < block; k++) {
                a2ont_gf_mul(&ctx->gf, &t, &ctx->M[i][k], &ctx->Minv[k][j]);
                a2ont_gf_add(&ctx->gf, &acc, &acc, &t);
            }
            a2ont_gf_set_u64(&expect, i == j ? 1 : 0);
            if (!a2ont_gf_equal(&ctx->gf, &acc, &expect))
                return -1;
        }
    /* window tables */
    ctx->wM = (a2ont_gf_wconst *)malloc(sizeof(a2ont_gf_wconst) * block * block);
    ctx->wMinv = (a2ont_gf_wconst *)malloc(sizeof(a2ont_gf_wconst) * block * block);
    if (ctx->wM == NULL || ctx->wMinv == NULL)
        return -1;
    for (i = 0; i < block; i++)
        for (j = 0; j < block; j++) {
            a2ont_gf_wconst_init(&ctx->gf, &ctx->wM[i * block + j], &ctx->M[i][j]);
            a2ont_gf_wconst_init(&ctx->gf, &ctx->wMinv[i * block + j],
                                 &ctx->Minv[i][j]);
        }
    /* precompute leading principal submatrix inverses for tail blocks */
    for (i = 1; i < block; i++) {
        if (a2ont_gf_matrix_invert(&ctx->gf, i, ctx->M, ctx->sub_inv[i]) != 0)
            return -1;
        ctx->sub_ready[i] = 1;
    }
    return 0;
}

const a2ont_gf_matctx *a2ont_gf_matctx_get(unsigned bits, unsigned block)
{
    unsigned s;
    for (s = 0; s < sizeof SLOTS / sizeof SLOTS[0]; s++) {
        ctx_slot *slot = &SLOTS[s];
        if (slot->bits != bits || slot->block != block)
            continue;
        for (;;) {
            if (slot->state == 2)
                return slot->ctx;
            if (slot->state == 3)
                return NULL;
            if (cas_int(&slot->state, 0, 1)) {
                a2ont_gf_matctx *ctx =
                    (a2ont_gf_matctx *)calloc(1, sizeof(a2ont_gf_matctx));
                if (ctx == NULL || build_ctx(ctx, bits, block) != 0) {
                    if (ctx) {
                        free(ctx->wM);
                        free(ctx->wMinv);
                        free(ctx);
                    }
                    slot->state = 3;
                    return NULL;
                }
                slot->ctx = ctx;
                slot->state = 2;
                return ctx;
            }
            /* another thread is building; spin */
        }
    }
    return NULL;
}

int a2ont_gf_submatrix_inv(const a2ont_gf_matctx *ctx, unsigned size,
                           a2ont_gfel out[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK])
{
    unsigned i, j;
    if (size == 0 || size >= ctx->block || !ctx->sub_ready[size])
        return -1;
    for (i = 0; i < size; i++)
        for (j = 0; j < size; j++)
            out[i][j] = ctx->sub_inv[size][i][j];
    return 0;
}
