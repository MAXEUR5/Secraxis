#include <string.h>

#include "profile_internal.h"

#define MATRIX_NAME_ON "A2ONT-GF128-MDS-v1"
#define MDS_NAME_ON "A2ONT-MDS4-v1"
#define PAD_POLICY "vault-bucket-padding-v1"

static const a2ont_iprofile PROFILES[] = {
    {A2ONT_PROFILE_V1_DEFAULT, "A2ONT-v1.0-default", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_STRONG, "A2ONT-v1.0-strong", 32, 32, 128, 1, 3,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_R1, "A2ONT-v1.0-r1", 32, 32, 128, 1, 1,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_NO_CORE, "A2ONT-v1.0-no-core", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_OFF,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 1, 0, "off", MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_NO_BITPREMIX, "A2ONT-v1.0-no-bitpremix", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_OFF, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_XOR_CHAINS, "A2ONT-v1.0-xor-chains", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 1, 1, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_NO_AR32, "A2ONT-v1.0-no-ar32", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_STREAM, 0, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_SYM256, "A2ONT-v1.0-sym256", 32, 32, 256, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 8, A2ONT_BPM_STREAM, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
    {A2ONT_PROFILE_V1_PERBYTE_BPM, "A2ONT-v1.0-perbyte-bpm", 32, 32, 128, 1, 2,
     A2ONT_HASH_SHAKE256, A2ONT_PRG_KMACXOF256, A2ONT_MATRIX_GF128_MDS_V1,
     A2ONT_MDS4_V1, 16, A2ONT_BPM_PERBYTE, 1, 0, MATRIX_NAME_ON, MDS_NAME_ON,
     PAD_POLICY},
};

const a2ont_iprofile *a2ont_iprofile_get(uint32_t numeric_id)
{
    size_t i;
    for (i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++)
        if (PROFILES[i].numeric_id == numeric_id)
            return &PROFILES[i];
    return NULL;
}

const char *a2ont_profile_name(uint32_t profile_id)
{
    const a2ont_iprofile *ip = a2ont_iprofile_get(profile_id);
    return ip ? ip->name : NULL;
}

int a2ont_profile_init(a2ont_profile_t *profile, uint32_t profile_id)
{
    const a2ont_iprofile *ip = a2ont_iprofile_get(profile_id);
    if (profile == NULL)
        return A2ONT_ERR_INVALID_PROFILE;
    if (ip == NULL)
        return A2ONT_ERR_INVALID_PROFILE;
    profile->version = 1;
    profile->profile_id = ip->numeric_id;
    profile->seed_len_bytes = ip->seed_len_bytes;
    profile->security_symbol_bits = ip->security_symbol_bits;
    profile->round_count = ip->round_count;
    profile->hash_xof_id = ip->hash_xof_id;
    profile->seed_prg_id = ip->seed_prg_id;
    profile->matrix_id = ip->matrix_id;
    profile->mds_id = ip->mds_id;
    return A2ONT_OK;
}

int a2ont_iprofile_check(const a2ont_profile_t *pub, const a2ont_iprofile **out)
{
    const a2ont_iprofile *ip;
    if (pub == NULL)
        return A2ONT_ERR_INVALID_PROFILE;
    ip = a2ont_iprofile_get(pub->profile_id);
    if (ip == NULL)
        return A2ONT_ERR_INVALID_PROFILE;
    if (pub->version != 1 || pub->seed_len_bytes != ip->seed_len_bytes ||
        pub->security_symbol_bits != ip->security_symbol_bits ||
        pub->round_count != ip->round_count ||
        pub->hash_xof_id != ip->hash_xof_id ||
        pub->seed_prg_id != ip->seed_prg_id ||
        pub->matrix_id != ip->matrix_id || pub->mds_id != ip->mds_id)
        return A2ONT_ERR_INVALID_PROFILE;
    if (ip->hash_xof_id != A2ONT_HASH_SHAKE256 ||
        ip->seed_prg_id != A2ONT_PRG_KMACXOF256)
        return A2ONT_ERR_UNSUPPORTED_BACKEND;
    if (out)
        *out = ip;
    return A2ONT_OK;
}

int a2ont_iprofile_check_len(const a2ont_iprofile *ip, size_t input_len)
{
    size_t sym = ip->security_symbol_bits / 8;
    if (input_len > (size_t)1 << 31)
        return A2ONT_ERR_INVALID_LENGTH;
    if (input_len % 16 != 0)
        return A2ONT_ERR_INVALID_LENGTH;
    if (input_len % sym != 0)
        return A2ONT_ERR_INVALID_LENGTH;
    return A2ONT_OK;
}

size_t a2ont_output_len(size_t input_len, const a2ont_profile_t *profile)
{
    const a2ont_iprofile *ip;
    if (a2ont_iprofile_check(profile, &ip) != A2ONT_OK)
        return 0;
    if (a2ont_iprofile_check_len(ip, input_len) != A2ONT_OK)
        return 0;
    return input_len + ip->y_extra_len_bytes;
}

int a2ont_check_input_len(size_t input_len, const a2ont_profile_t *profile)
{
    const a2ont_iprofile *ip;
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    return a2ont_iprofile_check_len(ip, input_len);
}

const char *a2ont_error_str(int code)
{
    switch (code) {
    case A2ONT_OK: return "A2ONT_OK";
    case A2ONT_ERR_INVALID_LENGTH: return "A2ONT_ERR_INVALID_LENGTH";
    case A2ONT_ERR_INVALID_PROFILE: return "A2ONT_ERR_INVALID_PROFILE";
    case A2ONT_ERR_UNSUPPORTED_BACKEND: return "A2ONT_ERR_UNSUPPORTED_BACKEND";
    case A2ONT_ERR_DECODE_FAILED: return "A2ONT_ERR_DECODE_FAILED";
    case A2ONT_ERR_RNG_FAILED: return "A2ONT_ERR_RNG_FAILED";
    case A2ONT_ERR_ALLOCATION_FAILED: return "A2ONT_ERR_ALLOCATION_FAILED";
    case A2ONT_ERR_INTERNAL: return "A2ONT_ERR_INTERNAL";
    default: return "A2ONT_ERR_UNKNOWN";
    }
}

uint32_t a2ont_runtime_version(void)
{
    return (A2ONT_VERSION_MAJOR << 16) | (A2ONT_VERSION_MINOR << 8) |
           A2ONT_VERSION_PATCH;
}
