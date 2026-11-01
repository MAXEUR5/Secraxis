#include "secraxis/aead.h"

#include <sodium.h>

#include <cstring>

#include "secraxis/secure_buffer.h"

#if defined(SECRAXIS_HAVE_GCM_SIV)
// Two interchangeable backends for the SEIS-AEAD-2 wire format (RFC 8452).
// Wire output is byte-identical either way (same RFC KATs gate both).
#if defined(SECRAXIS_GCM_SIV_OPENSSL)
#include <openssl/evp.h>   // OpenSSL >= 3.2 EVP_CIPHER "AES-256-GCM-SIV"
#elif defined(SECRAXIS_GCM_SIV_AWSLC)
#include <openssl/aead.h>  // AWS-LC / BoringSSL EVP_AEAD one-shot API
#else
#error "SECRAXIS_HAVE_GCM_SIV set without a backend selection"
#endif
#endif

static_assert(secraxis::AEAD_KEY_LEN ==
                  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
              "xchacha key len");
static_assert(secraxis::AEAD_TAG_LEN ==
                  crypto_aead_xchacha20poly1305_ietf_ABYTES,
              "xchacha tag len");

namespace secraxis {

const AeadProfile* aead_profile_by_id(uint32_t id) noexcept {
    switch (static_cast<AeadId>(id)) {
        case AeadId::XChaCha20Poly1305:
            return &AEAD_XCHACHA;
        case AeadId::Aes256GcmSiv:
            return &AEAD_GCMSIV;
        default:
            return nullptr;
    }
}

#if defined(SECRAXIS_HAVE_GCM_SIV)
namespace {
// Whether the GCM-SIV this build links really works here: an OpenSSL older
// than 3.2 links and loads, yet has no AES-256-GCM-SIV (the fetch fails).
// Checked at run time, so such a vault is "unsupported" (never "wrong
// password") and new vaults fall back to XChaCha20-Poly1305.
bool gcmsiv_runtime_available() noexcept;
}  // namespace
#endif

bool aead_profile_available(AeadId id) noexcept {
    switch (id) {
        case AeadId::XChaCha20Poly1305:
            return true;
        case AeadId::Aes256GcmSiv:
#if defined(SECRAXIS_HAVE_GCM_SIV)
            return gcmsiv_runtime_available();
#else
            return false;
#endif
    }
    return false;
}

const char* aead_backend_name() noexcept {
#if defined(SECRAXIS_GCM_SIV_OPENSSL)
    return "OpenSSL";
#elif defined(SECRAXIS_GCM_SIV_AWSLC)
    return "AWS-LC";
#else
    return "none";
#endif
}

namespace {

[[maybe_unused]] bool cpu_has_aes_clmul() noexcept {
#if defined(SECRAXIS_HAVE_GCM_SIV) && (defined(__x86_64__) || defined(_M_X64))
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul");
#else
    return true;
#endif
#else
    return false;
#endif
}

// ---- SEIS-AEAD-1: XChaCha20-Poly1305 (libsodium) --------------------------
Status xchacha_seal(uint8_t* ct, ByteView pt, ByteView aad,
                    const uint8_t* nonce24, const uint8_t* key32) noexcept {
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen, pt.ptr, pt.len,
                                                   aad.ptr, aad.len, nullptr,
                                                   nonce24, key32) != 0) {
        return status_fail(Err::Internal);
    }
    if (clen != pt.len + AEAD_TAG_LEN) return status_fail(Err::Internal);
    return status_ok();
}

Status xchacha_open(uint8_t* pt, ByteView ct, ByteView aad,
                    const uint8_t* nonce24, const uint8_t* key32) noexcept {
    if (ct.len < AEAD_TAG_LEN) return status_fail(Err::AuthGeneric);
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &plen, nullptr, ct.ptr,
                                                   ct.len, aad.ptr, aad.len,
                                                   nonce24, key32) != 0) {
        return status_fail(Err::AuthGeneric);
    }
    if (plen != ct.len - AEAD_TAG_LEN) return status_fail(Err::AuthGeneric);
    return status_ok();
}

#if defined(SECRAXIS_GCM_SIV_OPENSSL)
// ---- SEIS-AEAD-2 backend: OpenSSL >= 3.2 (default backend) ----------------
// GCM-SIV is two-pass; OpenSSL buffers internally and emits at *Final. AAD
// then the whole body go in as single Update calls; tag trails the body.

struct EvpCtx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~EvpCtx() {
        if (ctx != nullptr) EVP_CIPHER_CTX_free(ctx);
    }
};

const EVP_CIPHER* gcmsiv_cipher() noexcept {
    // Fetched once from the built-in default provider; never freed
    // (process-lifetime) — the documented pattern for fetched algorithms.
    static const EVP_CIPHER* c =
        EVP_CIPHER_fetch(nullptr, "AES-256-GCM-SIV", nullptr);
    return c;
}

bool gcmsiv_runtime_available() noexcept { return gcmsiv_cipher() != nullptr; }

Status gcmsiv_seal(uint8_t* ct, ByteView pt, ByteView aad,
                   const uint8_t* nonce12, const uint8_t* key32) noexcept {
    const EVP_CIPHER* cipher = gcmsiv_cipher();
    if (cipher == nullptr) return status_fail(Err::Internal);
    EvpCtx c;
    if (c.ctx == nullptr) return status_fail(Err::AllocationFailed);
    int len = 0;
    if (EVP_EncryptInit_ex2(c.ctx, cipher, key32, nonce12, nullptr) != 1)
        return status_fail(Err::Internal);
    if (aad.len > 0 &&
        EVP_EncryptUpdate(c.ctx, nullptr, &len, aad.ptr,
                          static_cast<int>(aad.len)) != 1)
        return status_fail(Err::Internal);
    // GCM-SIV requires the body Update even for empty plaintext (it triggers
    // the internal SIV computation); use a non-null pointer for the len-0
    // case to stay within the EVP contract.
    static const uint8_t kEmptyIn = 0;
    int out1 = 0;
    if (EVP_EncryptUpdate(c.ctx, ct, &out1, pt.len ? pt.ptr : &kEmptyIn,
                          static_cast<int>(pt.len)) != 1)
        return status_fail(Err::Internal);
    int out2 = 0;
    if (EVP_EncryptFinal_ex(c.ctx, ct + out1, &out2) != 1)
        return status_fail(Err::Internal);
    if (static_cast<size_t>(out1) + static_cast<size_t>(out2) != pt.len)
        return status_fail(Err::Internal);
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN,
                            ct + pt.len) != 1)
        return status_fail(Err::Internal);
    return status_ok();
}

Status gcmsiv_open(uint8_t* pt, ByteView ct, ByteView aad,
                   const uint8_t* nonce12, const uint8_t* key32) noexcept {
    if (ct.len < AEAD_TAG_LEN) return status_fail(Err::AuthGeneric);
    const size_t body_len = ct.len - AEAD_TAG_LEN;
    const EVP_CIPHER* cipher = gcmsiv_cipher();
    if (cipher == nullptr) return status_fail(Err::AuthGeneric);
    EvpCtx c;
    if (c.ctx == nullptr) return status_fail(Err::AllocationFailed);
    if (EVP_DecryptInit_ex2(c.ctx, cipher, key32, nonce12, nullptr) != 1)
        return status_fail(Err::AuthGeneric);
    // SIV verifies over (AAD, ciphertext) as a unit; set the expected tag up
    // front.
    uint8_t tag[AEAD_TAG_LEN];
    std::memcpy(tag, ct.ptr + body_len, AEAD_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, tag) !=
        1)
        return status_fail(Err::AuthGeneric);
    int len = 0;
    if (aad.len > 0 &&
        EVP_DecryptUpdate(c.ctx, nullptr, &len, aad.ptr,
                          static_cast<int>(aad.len)) != 1)
        return status_fail(Err::AuthGeneric);
    // Body Update always runs (even body_len 0); ct.ptr is non-null because
    // ct.len >= tag length was checked above.
    int out1 = 0;
    if (EVP_DecryptUpdate(c.ctx, pt, &out1, ct.ptr,
                          static_cast<int>(body_len)) != 1) {
        secure_wipe(pt, body_len);
        return status_fail(Err::AuthGeneric);
    }
    int out2 = 0;
    if (EVP_DecryptFinal_ex(c.ctx, pt + out1, &out2) != 1) {
        secure_wipe(pt, body_len);  // no unauthenticated plaintext survives
        return status_fail(Err::AuthGeneric);
    }
    if (static_cast<size_t>(out1) + static_cast<size_t>(out2) != body_len) {
        secure_wipe(pt, body_len);
        return status_fail(Err::AuthGeneric);
    }
    return status_ok();
}

#elif defined(SECRAXIS_GCM_SIV_AWSLC)
// ---- SEIS-AEAD-2 backend: AWS-LC (validated alternative) ------------------
bool gcmsiv_runtime_available() noexcept { return EVP_aead_aes_256_gcm_siv() != nullptr; }

struct AeadCtx {
    EVP_AEAD_CTX* ctx = nullptr;
    explicit AeadCtx(const uint8_t* key32) {
        ctx = EVP_AEAD_CTX_new(EVP_aead_aes_256_gcm_siv(), key32, AEAD_KEY_LEN,
                               AEAD_TAG_LEN);
    }
    ~AeadCtx() {
        if (ctx != nullptr) EVP_AEAD_CTX_free(ctx);
    }
};

Status gcmsiv_seal(uint8_t* ct, ByteView pt, ByteView aad,
                   const uint8_t* nonce12, const uint8_t* key32) noexcept {
    AeadCtx c(key32);
    if (c.ctx == nullptr) return status_fail(Err::AllocationFailed);
    size_t out_len = 0;
    if (EVP_AEAD_CTX_seal(c.ctx, ct, &out_len, pt.len + AEAD_TAG_LEN, nonce12,
                          AEAD_GCMSIV.nonce_len, pt.ptr, pt.len, aad.ptr,
                          aad.len) != 1) {
        return status_fail(Err::Internal);
    }
    if (out_len != pt.len + AEAD_TAG_LEN) return status_fail(Err::Internal);
    return status_ok();
}

Status gcmsiv_open(uint8_t* pt, ByteView ct, ByteView aad,
                   const uint8_t* nonce12, const uint8_t* key32) noexcept {
    if (ct.len < AEAD_TAG_LEN) return status_fail(Err::AuthGeneric);
    const size_t body_len = ct.len - AEAD_TAG_LEN;
    AeadCtx c(key32);
    if (c.ctx == nullptr) return status_fail(Err::AllocationFailed);
    size_t out_len = 0;
    if (EVP_AEAD_CTX_open(c.ctx, pt, &out_len, body_len, nonce12,
                          AEAD_GCMSIV.nonce_len, ct.ptr, ct.len, aad.ptr,
                          aad.len) != 1) {
        secure_wipe(pt, body_len);
        return status_fail(Err::AuthGeneric);
    }
    if (out_len != body_len) {
        secure_wipe(pt, body_len);
        return status_fail(Err::AuthGeneric);
    }
    return status_ok();
}
#endif  // backend selection

}  // namespace

const AeadProfile& aead_default_profile() noexcept {
#if defined(SECRAXIS_HAVE_GCM_SIV)
    if (cpu_has_aes_clmul() && gcmsiv_runtime_available()) return AEAD_GCMSIV;
#endif
    return AEAD_XCHACHA;
}

Status aead_seal(const AeadProfile& p, uint8_t* ct, ByteView pt, ByteView aad,
                 const uint8_t* nonce, const uint8_t* key) noexcept {
    switch (p.id) {
        case AeadId::XChaCha20Poly1305:
            return xchacha_seal(ct, pt, aad, nonce, key);
        case AeadId::Aes256GcmSiv:
#if defined(SECRAXIS_HAVE_GCM_SIV)
            return gcmsiv_seal(ct, pt, aad, nonce, key);
#else
            return status_fail(Err::FormatUnsupported);
#endif
    }
    return status_fail(Err::InvalidArgument);
}

Status aead_open(const AeadProfile& p, uint8_t* pt, ByteView ct, ByteView aad,
                 const uint8_t* nonce, const uint8_t* key) noexcept {
    switch (p.id) {
        case AeadId::XChaCha20Poly1305:
            return xchacha_open(pt, ct, aad, nonce, key);
        case AeadId::Aes256GcmSiv:
#if defined(SECRAXIS_HAVE_GCM_SIV)
            return gcmsiv_open(pt, ct, aad, nonce, key);
#else
            return status_fail(Err::FormatUnsupported);
#endif
    }
    return status_fail(Err::InvalidArgument);
}

}  // namespace secraxis
