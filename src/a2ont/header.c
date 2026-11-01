/* Container header (agenda section 14; spec section 8). */
#include <string.h>

#include "secraxis/a2ont.h"
#include "encoding.h"
#include "profile_internal.h"

#define MAGIC "A2ONT"
#define MAGIC_LEN 5
#define HVERSION 1u

static size_t str_field_len(const char *s)
{
    return 4 + strlen(s);
}

size_t a2ont_header_len(const a2ont_profile_t *profile, size_t input_len)
{
    const a2ont_iprofile *ip;
    (void)input_len;
    if (a2ont_iprofile_check(profile, &ip) != A2ONT_OK)
        return 0;
    return MAGIC_LEN + 2 + str_field_len(ip->name) + 8 * 5 +
           str_field_len("SHAKE256") + str_field_len("KMACXOF256") +
           str_field_len(ip->matrix_name) + str_field_len(ip->mds_name) +
           str_field_len(ip->padding_policy);
}

typedef struct {
    uint8_t *p;
    size_t left;
} writer;

static int put(writer *w, const void *src, size_t n)
{
    if (w->left < n)
        return -1;
    memcpy(w->p, src, n);
    w->p += n;
    w->left -= n;
    return 0;
}

static int put_str(writer *w, const char *s)
{
    uint8_t hdr[4];
    size_t n = strlen(s);
    a2ont_put_u32le(hdr, (uint32_t)n);
    if (put(w, hdr, 4))
        return -1;
    return put(w, s, n);
}

static int put_u64(writer *w, uint64_t v)
{
    uint8_t b[8];
    a2ont_put_u64le(b, v);
    return put(w, b, 8);
}

int a2ont_header_build(const a2ont_profile_t *profile, size_t input_len,
                       uint8_t *out, size_t out_len)
{
    const a2ont_iprofile *ip;
    writer w;
    uint8_t v16[2];
    int rc = a2ont_iprofile_check(profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    if ((rc = a2ont_iprofile_check_len(ip, input_len)) != A2ONT_OK)
        return rc;
    if (out_len < a2ont_header_len(profile, input_len))
        return A2ONT_ERR_INVALID_LENGTH;
    w.p = out;
    w.left = out_len;
    v16[0] = HVERSION & 0xFF;
    v16[1] = (HVERSION >> 8) & 0xFF;
    if (put(&w, MAGIC, MAGIC_LEN) || put(&w, v16, 2) ||
        put_str(&w, ip->name) || put_u64(&w, input_len) ||
        put_u64(&w, ip->seed_len_bytes) ||
        put_u64(&w, ip->security_symbol_bits) ||
        put_u64(&w, ip->missing_symbol_threshold) ||
        put_u64(&w, ip->round_count) || put_str(&w, "SHAKE256") ||
        put_str(&w, "KMACXOF256") || put_str(&w, ip->matrix_name) ||
        put_str(&w, ip->mds_name) || put_str(&w, ip->padding_policy))
        return A2ONT_ERR_INTERNAL;
    return A2ONT_OK;
}

typedef struct {
    const uint8_t *p;
    size_t left;
} reader;

static int take(reader *r, void *dst, size_t n)
{
    if (r->left < n)
        return -1;
    if (dst)
        memcpy(dst, r->p, n);
    r->p += n;
    r->left -= n;
    return 0;
}

static int take_str_expect(reader *r, const char *expect)
{
    uint8_t hdr[4];
    uint32_t n;
    if (take(r, hdr, 4))
        return -1;
    n = a2ont_get_u32le(hdr);
    if (n > 4096 || r->left < n)
        return -1;
    if (expect != NULL &&
        (strlen(expect) != n || memcmp(r->p, expect, n) != 0))
        return -1;
    r->p += n;
    r->left -= n;
    return 0;
}

static int take_u64(reader *r, uint64_t *out)
{
    uint8_t b[8];
    if (take(r, b, 8))
        return -1;
    *out = a2ont_get_u64le(b);
    return 0;
}

int a2ont_header_parse(const uint8_t *blob, size_t blob_len,
                       const a2ont_profile_t *expected_profile,
                       size_t *body_offset, size_t *body_len)
{
    const a2ont_iprofile *ip;
    reader r;
    uint8_t magic[MAGIC_LEN], v16[2];
    uint64_t L, u;
    int rc = a2ont_iprofile_check(expected_profile, &ip);
    if (rc != A2ONT_OK)
        return rc;
    r.p = blob;
    r.left = blob_len;
    if (take(&r, magic, MAGIC_LEN) || memcmp(magic, MAGIC, MAGIC_LEN) != 0)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take(&r, v16, 2) || (v16[0] | ((uint32_t)v16[1] << 8)) != HVERSION)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_str_expect(&r, ip->name))
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_u64(&r, &L))
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_u64(&r, &u) || u != ip->seed_len_bytes)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_u64(&r, &u) || u != ip->security_symbol_bits)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_u64(&r, &u) || u != ip->missing_symbol_threshold)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_u64(&r, &u) || u != ip->round_count)
        return A2ONT_ERR_INVALID_PROFILE;
    if (take_str_expect(&r, "SHAKE256") || take_str_expect(&r, "KMACXOF256") ||
        take_str_expect(&r, ip->matrix_name) ||
        take_str_expect(&r, ip->mds_name) ||
        take_str_expect(&r, ip->padding_policy))
        return A2ONT_ERR_INVALID_PROFILE;
    if (a2ont_iprofile_check_len(ip, (size_t)L) != A2ONT_OK)
        return A2ONT_ERR_INVALID_LENGTH;
    if (r.left != (size_t)L + ip->y_extra_len_bytes)
        return A2ONT_ERR_INVALID_LENGTH;
    if (body_offset)
        *body_offset = blob_len - r.left;
    if (body_len)
        *body_len = (size_t)L;
    return A2ONT_OK;
}
