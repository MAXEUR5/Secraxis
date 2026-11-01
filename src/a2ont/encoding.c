#include "encoding.h"

#include <string.h>

void a2ont_put_u32le(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

void a2ont_put_u64le(uint8_t out[8], uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

uint32_t a2ont_get_u32le(const uint8_t in[4])
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

uint64_t a2ont_get_u64le(const uint8_t in[8])
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--)
        v = (v << 8) | in[i];
    return v;
}

void a2ont_absorb_enc_bytes(a2ont_sponge *sp, const uint8_t *b, size_t len)
{
    uint8_t hdr[4];
    a2ont_put_u32le(hdr, (uint32_t)len);
    a2ont_sponge_absorb(sp, hdr, 4);
    if (len)
        a2ont_sponge_absorb(sp, b, len);
}

void a2ont_absorb_enc_str(a2ont_sponge *sp, const char *s)
{
    a2ont_absorb_enc_bytes(sp, (const uint8_t *)s, strlen(s));
}

void a2ont_absorb_enc_int(a2ont_sponge *sp, uint64_t v)
{
    uint8_t b[8];
    a2ont_put_u64le(b, v);
    a2ont_sponge_absorb(sp, b, 8);
}
