/* Internal resolved profile: numeric ids -> full parameter set including the
 * canonical profile_id string bound into PRG and seed hiding. */
#ifndef A2ONT_PROFILE_INTERNAL_H
#define A2ONT_PROFILE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "secraxis/a2ont.h"

typedef enum {
    A2ONT_BPM_STREAM = 0, /* perm8-lehmer-stream-v1 */
    A2ONT_BPM_PERBYTE = 1,
    A2ONT_BPM_OFF = 2,
} a2ont_bpm_mode;

typedef struct {
    uint32_t numeric_id;
    const char *name; /* canonical profile_id string */
    uint32_t seed_len_bytes;
    uint32_t y_extra_len_bytes;
    uint32_t security_symbol_bits;
    uint32_t missing_symbol_threshold;
    uint32_t round_count;
    uint32_t hash_xof_id;
    uint32_t seed_prg_id;
    uint32_t matrix_id;       /* A2ONT_MATRIX_* */
    uint32_t mds_id;          /* A2ONT_MDS_* */
    uint32_t field_block_symbols;
    a2ont_bpm_mode bit_premix;
    int ar32_enabled;
    int chain_xor; /* 0 = modular-addition, 1 = xor */
    const char *matrix_name;  /* string bound into seed hiding */
    const char *mds_name;
    const char *padding_policy;
} a2ont_iprofile;

/* Resolve; returns NULL if unknown. */
const a2ont_iprofile *a2ont_iprofile_get(uint32_t numeric_id);

/* Validate that a public descriptor matches its resolved profile. */
int a2ont_iprofile_check(const a2ont_profile_t *pub, const a2ont_iprofile **out);

int a2ont_iprofile_check_len(const a2ont_iprofile *ip, size_t input_len);

#endif
