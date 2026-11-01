#include "prg.h"

#include "encoding.h"

#define PRG_PREFIX "A2ONT-v1"
#define PRG_CUSTOM "A2ONT-PRG"

void a2ont_prg_open(a2ont_prg *prg, const uint8_t *seed, size_t seed_len,
                    const char *label, uint64_t round_index, uint64_t total_len,
                    const a2ont_iprofile *ip,
                    const uint8_t *extra, size_t extra_len)
{
    a2ont_sponge *sp = &prg->sp;
    a2ont_kmacxof256_begin(sp, seed, seed_len,
                           (const uint8_t *)PRG_CUSTOM, sizeof PRG_CUSTOM - 1);
    a2ont_sponge_absorb(sp, (const uint8_t *)PRG_PREFIX, sizeof PRG_PREFIX - 1);
    a2ont_absorb_enc_str(sp, label);
    a2ont_absorb_enc_int(sp, round_index);
    a2ont_absorb_enc_int(sp, total_len);
    a2ont_absorb_enc_str(sp, ip->name);
    a2ont_absorb_enc_int(sp, ip->security_symbol_bits);
    a2ont_absorb_enc_int(sp, ip->round_count);
    a2ont_absorb_enc_bytes(sp, extra, extra ? extra_len : 0);
    a2ont_kmacxof256_finish(sp);
}

void a2ont_prg_read(a2ont_prg *prg, uint8_t *out, size_t len)
{
    a2ont_sponge_squeeze(&prg->sp, out, len);
}

void a2ont_prg_close(a2ont_prg *prg)
{
    a2ont_sponge_wipe(&prg->sp);
}
