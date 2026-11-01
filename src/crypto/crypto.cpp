#include "secraxis/crypto.h"

#include <sodium.h>

#include <cstring>

#include "secraxis/crypto_profile.h"

static_assert(secraxis::HKDF_PRK_LEN == crypto_kdf_hkdf_sha512_KEYBYTES,
              "HKDF PRK length mismatch");

namespace secraxis {

bool crypto_init() noexcept { return sodium_init() >= 0; }

Status hkdf_extract(uint8_t* prk_out, ByteView salt, ByteView ikm) noexcept {
    if (crypto_kdf_hkdf_sha512_extract(prk_out, salt.ptr, salt.len, ikm.ptr,
                                       ikm.len) != 0) {
        return status_fail(Err::Internal);
    }
    return status_ok();
}

Status hkdf_expand(uint8_t* out, size_t out_len, const uint8_t* prk,
                   ByteView info) noexcept {
    if (out_len == 0 || out_len > crypto_kdf_hkdf_sha512_BYTES_MAX) {
        return status_fail(Err::InvalidArgument);
    }
    if (crypto_kdf_hkdf_sha512_expand(out, out_len,
                                      reinterpret_cast<const char*>(info.ptr),
                                      info.len, prk) != 0) {
        return status_fail(Err::Internal);
    }
    return status_ok();
}

SecureBuffer hkdf_derive(ByteView salt, ByteView ikm, ByteView info,
                         size_t out_len) {
    SecureBuffer prk = SecureBuffer::alloc(HKDF_PRK_LEN);
    SecureBuffer out;
    if (!prk.valid()) return out;
    if (!hkdf_extract(prk.data(), salt, ikm).ok()) return out;
    out = SecureBuffer::alloc(out_len);
    if (!out.valid()) return out;
    if (!hkdf_expand(out.data(), out_len, prk.data(), info).ok()) {
        out.reset();
    }
    return out;
}

}  // namespace secraxis
