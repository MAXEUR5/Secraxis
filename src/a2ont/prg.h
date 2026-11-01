/* Seed PRG streams (agenda 9.3 / spec section 3): KMACXOF256 keyed by R with
 * canonical domain-separated input; unbounded incremental squeeze. */
#ifndef A2ONT_PRG_H
#define A2ONT_PRG_H

#include <stddef.h>
#include <stdint.h>

#include "keccak.h"
#include "profile_internal.h"

typedef struct {
    a2ont_sponge sp;
} a2ont_prg;

/* extra == NULL means "no extra_context" (encoded as empty byte string). */
void a2ont_prg_open(a2ont_prg *prg, const uint8_t *seed, size_t seed_len,
                    const char *label, uint64_t round_index, uint64_t total_len,
                    const a2ont_iprofile *ip,
                    const uint8_t *extra, size_t extra_len);
void a2ont_prg_read(a2ont_prg *prg, uint8_t *out, size_t len);
void a2ont_prg_close(a2ont_prg *prg); /* wipes state */

#endif
