/* Canonical A2ONT byte encodings (spec section 1), absorbed straight into
 * sponges to avoid heap staging of PRG inputs. */
#ifndef A2ONT_ENCODING_H
#define A2ONT_ENCODING_H

#include <stddef.h>
#include <stdint.h>

#include "keccak.h"

void a2ont_put_u32le(uint8_t out[4], uint32_t v);
void a2ont_put_u64le(uint8_t out[8], uint64_t v);
uint32_t a2ont_get_u32le(const uint8_t in[4]);
uint64_t a2ont_get_u64le(const uint8_t in[8]);

/* enc_bytes(b) = u32le(len) || b ; enc_str = enc_bytes(utf8) ;
 * enc_int(n) = u64le(n) — absorbed into the sponge. */
void a2ont_absorb_enc_bytes(a2ont_sponge *sp, const uint8_t *b, size_t len);
void a2ont_absorb_enc_str(a2ont_sponge *sp, const char *s);
void a2ont_absorb_enc_int(a2ont_sponge *sp, uint64_t v);

#endif
