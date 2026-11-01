// aead.h — profile-dispatched AEAD layer (docs/CRYPTO_PROFILES.md §3).
//
// Two registered profiles:
//   SEIS-AEAD-1  XChaCha20-Poly1305-ietf  (libsodium; portable profile)
//   SEIS-AEAD-2  AES-256-GCM-SIV          (OpenSSL libcrypto; misuse-resistant
//                                          profile, prioritized default when
//                                          built in and hardware-suitable)
//
// The profile ID is chosen at vault creation, serialized in the public
// header, and authenticated. Both profiles use the same structural
// nonce-uniqueness derivation (unique key AND nonce per object per save);
// GCM-SIV's misuse resistance is defense-in-depth on top, not a license to
// relax nonce discipline.
#ifndef SECRAXIS_AEAD_H
#define SECRAXIS_AEAD_H

#include "secraxis/common.h"
#include "secraxis/crypto_profile.h"

namespace secraxis {

struct AeadProfile {
    AeadId id;
    uint32_t key_len;
    uint32_t nonce_len;
    uint32_t tag_len;
    const char* name;  // stable, non-secret
};

inline constexpr AeadProfile AEAD_XCHACHA{AeadId::XChaCha20Poly1305, 32, 24, 16,
                                          "SEIS-AEAD-1/XChaCha20-Poly1305"};
inline constexpr AeadProfile AEAD_GCMSIV{AeadId::Aes256GcmSiv, 32, 12, 16,
                                         "SEIS-AEAD-2/AES-256-GCM-SIV"};

// nullptr for unknown ids (parser rejects the file).
const AeadProfile* aead_profile_by_id(uint32_t id) noexcept;

// Compiled-in? (SEIS-AEAD-2 requires a libcrypto-backed build.)
bool aead_profile_available(AeadId id) noexcept;

// "OpenSSL", "AWS-LC", or "none" — which GCM-SIV backend this build carries.
// Non-secret; used for diagnostics and the experiment reports.
const char* aead_backend_name() noexcept;

// Profile for NEW vaults: AES-256-GCM-SIV when compiled in and the CPU has
// AES+CLMUL (constant-time hardware path); otherwise XChaCha20-Poly1305.
// Existing vaults always use their recorded, authenticated profile.
const AeadProfile& aead_default_profile() noexcept;

// Combined mode: ct = body || tag. ct must hold pt.len + tag_len.
Status aead_seal(const AeadProfile& p, uint8_t* ct, ByteView pt, ByteView aad,
                 const uint8_t* nonce, const uint8_t* key) noexcept;
// pt must hold ct.len - tag_len. Uniform Err::AuthGeneric on ANY failure;
// never leaves partial plaintext in pt on failure.
Status aead_open(const AeadProfile& p, uint8_t* pt, ByteView ct, ByteView aad,
                 const uint8_t* nonce, const uint8_t* key) noexcept;

}  // namespace secraxis

#endif  // SECRAXIS_AEAD_H
