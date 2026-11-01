/* GF(2^lambda) arithmetic (lambda in {64,128,256}) in plain polynomial basis.
 * Elements: little-endian byte mapping onto uint64 limbs (limb 0 = lowest).
 * NOT the GCM reflected convention; A2ONT is not GCM / not AEAD. */
#ifndef A2ONT_GF2_H
#define A2ONT_GF2_H

#include <stddef.h>
#include <stdint.h>

#define A2ONT_GF_MAX_LIMBS 4
#define A2ONT_GF_MAX_BLOCK 16

typedef struct {
    uint64_t v[A2ONT_GF_MAX_LIMBS];
} a2ont_gfel;

typedef struct {
    unsigned bits;    /* 64 / 128 / 256 */
    unsigned limbs;   /* bits/64 */
    uint64_t poly_low; /* low word of reduction polynomial */
} a2ont_gf;

void a2ont_gf_init(a2ont_gf *gf, unsigned bits);
void a2ont_gf_from_bytes(const a2ont_gf *gf, a2ont_gfel *e, const uint8_t *in);
void a2ont_gf_to_bytes(const a2ont_gf *gf, const a2ont_gfel *e, uint8_t *out);
void a2ont_gf_set_u64(a2ont_gfel *e, uint64_t v);
int a2ont_gf_is_zero(const a2ont_gf *gf, const a2ont_gfel *e);
int a2ont_gf_equal(const a2ont_gf *gf, const a2ont_gfel *a, const a2ont_gfel *b);
void a2ont_gf_add(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a,
                  const a2ont_gfel *b); /* XOR */
void a2ont_gf_mul(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a,
                  const a2ont_gfel *b);
void a2ont_gf_inv(const a2ont_gf *gf, a2ont_gfel *r, const a2ont_gfel *a);

/* 4-bit window tables for a fixed constant: mul = (bits/4) table lookups. */
typedef struct {
    a2ont_gfel t[A2ONT_GF_MAX_LIMBS * 16][16]; /* [window][nibble] */
    unsigned nwin;
} a2ont_gf_wconst;

void a2ont_gf_wconst_init(const a2ont_gf *gf, a2ont_gf_wconst *w,
                          const a2ont_gfel *c);
void a2ont_gf_wconst_mul(const a2ont_gf *gf, const a2ont_gf_wconst *w,
                         a2ont_gfel *r, const a2ont_gfel *x);

/* Blockwise Cauchy matrix context ("A2ONT-GF128-MDS-v1" construction):
 * M[i][j] = inv(elem(i) ^ elem(block+j)); Minv by Gauss-Jordan; window
 * tables for both. Leading principal submatrix inverses are computed on
 * demand for tail blocks (superregularity guarantees invertibility). */
typedef struct {
    a2ont_gf gf;
    unsigned block;
    a2ont_gfel M[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK];
    a2ont_gfel Minv[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK];
    a2ont_gf_wconst *wM;    /* block*block entries, row-major (heap) */
    a2ont_gf_wconst *wMinv;
    /* cached tail-submatrix inverses, one per possible size 1..block-1 */
    a2ont_gfel sub_inv[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK];
    uint8_t sub_ready[A2ONT_GF_MAX_BLOCK];
} a2ont_gf_matctx;

/* Get (and lazily build) the global matrix context for (bits, block).
 * Returns NULL on allocation failure. Thread-safe via atomic once-guard. */
const a2ont_gf_matctx *a2ont_gf_matctx_get(unsigned bits, unsigned block);

/* Invert the leading size x size submatrix into out (for tail blocks). */
int a2ont_gf_submatrix_inv(const a2ont_gf_matctx *ctx, unsigned size,
                           a2ont_gfel out[A2ONT_GF_MAX_BLOCK][A2ONT_GF_MAX_BLOCK]);

/* Generic Gauss-Jordan inversion of an n x n matrix (row-major, stride
 * A2ONT_GF_MAX_BLOCK). Returns 0 on success, -1 if singular. */
int a2ont_gf_matrix_invert(const a2ont_gf *gf, unsigned n,
                           const a2ont_gfel in[][A2ONT_GF_MAX_BLOCK],
                           a2ont_gfel out[][A2ONT_GF_MAX_BLOCK]);

#endif
