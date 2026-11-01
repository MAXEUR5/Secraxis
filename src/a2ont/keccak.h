/* Internal: Keccak-f[1600] sponge, SHAKE256/cSHAKE256/KMACXOF256 (rate 136),
 * and SP 800-185 string encodings. Incremental absorb and squeeze. */
#ifndef A2ONT_KECCAK_H
#define A2ONT_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#define A2ONT_KECCAK_RATE256 136

typedef struct {
    uint64_t state[25];
    uint8_t buf[A2ONT_KECCAK_RATE256]; /* absorb staging / squeeze cache */
    size_t buf_used;                   /* absorb: bytes staged */
    size_t squeeze_off;                /* squeeze: bytes consumed of buf */
    int squeezing;
    uint8_t domain_suffix;             /* 0x1F SHAKE, 0x04 cSHAKE */
} a2ont_sponge;

void a2ont_sponge_init(a2ont_sponge *sp, uint8_t domain_suffix);
void a2ont_sponge_absorb(a2ont_sponge *sp, const uint8_t *data, size_t len);
void a2ont_sponge_squeeze(a2ont_sponge *sp, uint8_t *out, size_t len);
void a2ont_sponge_wipe(a2ont_sponge *sp);

/* SP 800-185 encodings. Buffers must hold >= 9 bytes; returns length. */
size_t a2ont_left_encode(uint64_t x, uint8_t out[9]);
size_t a2ont_right_encode(uint64_t x, uint8_t out[9]);
/* absorb encode_string(s) = left_encode(8*len) || s */
void a2ont_absorb_encoded_string(a2ont_sponge *sp, const uint8_t *s, size_t len);

/* SHAKE256 XOF (one-shot init; absorb then squeeze). */
void a2ont_shake256_init(a2ont_sponge *sp);

/* cSHAKE256 with function name N and customization S (either may be empty;
 * both empty degenerates to SHAKE256 per SP 800-185). */
void a2ont_cshake256_init(a2ont_sponge *sp, const uint8_t *n, size_t n_len,
                          const uint8_t *s, size_t s_len);

/* KMACXOF256 streaming: begin(key, custom) -> absorb X pieces -> finish()
 * (appends right_encode(0)) -> squeeze. */
void a2ont_kmacxof256_begin(a2ont_sponge *sp, const uint8_t *key, size_t key_len,
                            const uint8_t *custom, size_t custom_len);
void a2ont_kmacxof256_finish(a2ont_sponge *sp);

#endif
