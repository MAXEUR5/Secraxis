/* Internal transform layers. All operate on a working buffer of length L
 * (validated by the caller) and are exactly invertible. */
#ifndef A2ONT_TRANSFORMS_H
#define A2ONT_TRANSFORMS_H

#include <stddef.h>
#include <stdint.h>

#include "profile_internal.h"

/* threshold core: blockwise GF(2^lambda) Cauchy mixing (spec section 5) */
int a2ont_field_mix(uint8_t *s, size_t L, const a2ont_iprofile *ip, int inverse);

/* seed-driven byte permutation (spec 6.1); scratch: L bytes + L uint32 */
int a2ont_permute(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                  const a2ont_iprofile *ip, int inverse);

/* BitPreMix (spec 6.2/6.3) */
int a2ont_bit_premix(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                     const a2ont_iprofile *ip, int inverse);

/* seed-derived XOR whitening (spec 6.4) */
int a2ont_xor_mask(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                   const a2ont_iprofile *ip);

/* AR32 (spec 6.5) */
int a2ont_ar32(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
               const a2ont_iprofile *ip, int inverse);

/* MDS4 byte diffusion (spec 6.6; involutory) */
int a2ont_mds(uint8_t *s, size_t L, const a2ont_iprofile *ip, int inverse);

/* forward+backward chains (spec 6.7) */
int a2ont_chain_forward(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                        const a2ont_iprofile *ip, int inverse);
int a2ont_chain_backward(uint8_t *s, size_t L, const uint8_t *seed, uint64_t t,
                         const a2ont_iprofile *ip, int inverse);

/* seed hiding: H_mask = SHAKE256(binding || Y) (spec section 7) */
void a2ont_seed_hide_mask(const uint8_t *ctx, size_t ctx_len, const uint8_t *y,
                          size_t y_len, const a2ont_iprofile *ip, uint8_t *out);

int a2ont_rng_bytes(uint8_t *out, size_t len); /* rng.c */

#endif
