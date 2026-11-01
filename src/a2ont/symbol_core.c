#include <string.h>

#include "secraxis/a2ont.h"
#include "gf2.h"
#include "transforms.h"
#include "wipe.h"

int a2ont_field_mix(uint8_t *s, size_t L, const a2ont_iprofile *ip, int inverse)
{
    const a2ont_gf_matctx *ctx;
    unsigned sym, block;
    size_t nsym, pos;
    if (ip->matrix_id == A2ONT_MATRIX_OFF || L == 0)
        return A2ONT_OK;
    sym = ip->security_symbol_bits / 8u;
    block = ip->field_block_symbols;
    ctx = a2ont_gf_matctx_get(ip->security_symbol_bits, block);
    if (ctx == NULL)
        return A2ONT_ERR_ALLOCATION_FAILED;
    nsym = L / sym;
    pos = 0;
    while (pos < nsym) {
        unsigned blk = (nsym - pos) < block ? (unsigned)(nsym - pos) : block;
        uint8_t *base = s + pos * sym;
        a2ont_gfel u[A2ONT_GF_MAX_BLOCK], v[A2ONT_GF_MAX_BLOCK];
        unsigned i, j;
        for (i = 0; i < blk; i++)
            a2ont_gf_from_bytes(&ctx->gf, &u[i], base + (size_t)i * sym);
        if (blk == block) {
            const a2ont_gf_wconst *w = inverse ? ctx->wMinv : ctx->wM;
            for (j = 0; j < blk; j++) {
                a2ont_gfel acc, t;
                memset(&acc, 0, sizeof acc);
                for (i = 0; i < blk; i++) {
                    if (a2ont_gf_is_zero(&ctx->gf, &u[i]))
                        continue;
                    a2ont_gf_wconst_mul(&ctx->gf, &w[i * block + j], &t, &u[i]);
                    a2ont_gf_add(&ctx->gf, &acc, &acc, &t);
                }
                v[j] = acc;
            }
        } else {
            a2ont_gfel sub[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK];
            const a2ont_gfel(*m)[A2ONT_GF_MAX_BLOCK];
            if (inverse) {
                if (a2ont_gf_submatrix_inv(ctx, blk, sub) != 0)
                    return A2ONT_ERR_INTERNAL;
                m = sub;
            } else {
                m = ctx->M;
            }
            for (j = 0; j < blk; j++) {
                a2ont_gfel acc, t;
                memset(&acc, 0, sizeof acc);
                for (i = 0; i < blk; i++) {
                    a2ont_gf_mul(&ctx->gf, &t, &u[i], &m[i][j]);
                    a2ont_gf_add(&ctx->gf, &acc, &acc, &t);
                }
                v[j] = acc;
            }
        }
        for (j = 0; j < blk; j++)
            a2ont_gf_to_bytes(&ctx->gf, &v[j], base + (size_t)j * sym);
        a2ont_secure_wipe_impl(u, sizeof u);
        a2ont_secure_wipe_impl(v, sizeof v);
        pos += blk;
    }
    return A2ONT_OK;
}
