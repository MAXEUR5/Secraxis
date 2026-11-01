// crypto_profile.h — versioned cryptographic profiles for .seis (agenda §5, §7).
//
// Every ID here is serialized into the .seis public header AND authenticated
// (bound into AEAD AAD / the encrypted manifest), so downgrade or confusion
// attacks fail closed. No silent downgrade path exists: parsers accept only
// registered IDs and reject anything weaker than the floor.
#ifndef SECRAXIS_CRYPTO_PROFILE_H
#define SECRAXIS_CRYPTO_PROFILE_H

#include <cstdint>

namespace secraxis {

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------
inline constexpr uint8_t SEIS_MAGIC[4] = {'S', 'E', 'I', 'S'};
constexpr uint16_t SEIS_FORMAT_VERSION = 1;

constexpr uint32_t VAULT_ID_LEN = 16;   // random per vault, non-secret
constexpr uint32_t KDF_SALT_LEN = 32;   // mandated 32-byte salt
constexpr uint32_t KDF_OUT_LEN = 64;    // 512-bit KEK material
constexpr uint32_t VMK_LEN = 64;        // 512-bit vault master key

// ---------------------------------------------------------------------------
// KDF profiles (Argon2id, RFC 9106). Non-negotiable values from the agenda.
// ---------------------------------------------------------------------------
enum class KdfProfileId : uint32_t {
    Floor = 1,    // 384 MiB, t=3, p=4
    Default = 2,  // 512 MiB, t=4, p=4
    Strong = 3,   // 1024 MiB, t=5, p=8
};

struct KdfProfile {
    KdfProfileId id;
    uint32_t memory_mib;
    uint32_t iterations;
    uint32_t lanes;
};

inline constexpr KdfProfile KDF_FLOOR{KdfProfileId::Floor, 384, 3, 4};
inline constexpr KdfProfile KDF_DEFAULT{KdfProfileId::Default, 512, 4, 4};
inline constexpr KdfProfile KDF_STRONG{KdfProfileId::Strong, 1024, 5, 8};

// Returns nullptr for unknown IDs (parser rejects). Custom parameters weaker
// than KDF_FLOOR are never accepted from a file.
const KdfProfile* kdf_profile_by_id(uint32_t id) noexcept;

// ---------------------------------------------------------------------------
// AEAD profiles: XChaCha20-Poly1305 and AES-256-GCM-SIV. Each one is an
// explicit, versioned addition (with vectors), never a runtime toggle.
// ---------------------------------------------------------------------------
enum class AeadId : uint32_t {
    XChaCha20Poly1305 = 1,  // SEIS-AEAD-1: key 32, nonce 24, tag 16 (libsodium)
    Aes256GcmSiv = 2,       // SEIS-AEAD-2: key 32, nonce 12, tag 16 (OpenSSL)
};

constexpr uint32_t AEAD_KEY_LEN = 32;        // both profiles
constexpr uint32_t AEAD_TAG_LEN = 16;        // both profiles
constexpr uint32_t AEAD_MAX_NONCE_LEN = 24;  // per-profile actual length applies

// ---------------------------------------------------------------------------
// A2ONT profiles (numeric ids mirror a2ont.h; name binding is authenticated).
// v1 uses the 32-byte-seed A2ONT-v1.0 profiles — the module's documented
// spec. (Agenda §4.2: use the documented 256-bit profile rather than silently
// changing the module.)
// ---------------------------------------------------------------------------
enum class A2ontProfileId : uint32_t {
    Default = 1,  // "A2ONT-v1.0-default" (r=2)
    Strong = 2,   // "A2ONT-v1.0-strong"  (r=3)
};

constexpr uint32_t A2ONT_SEED_LEN = 32;  // v1.0 fixed

// ---------------------------------------------------------------------------
// Padding policy (agenda §11): versioned bucket schedule, CSPRNG-filled.
// ---------------------------------------------------------------------------
enum class PaddingPolicyId : uint32_t {
    BucketV1 = 1,  // 64K,128K,256K,512K,1M,2M,4M,8M then +4M steps
};

// ---------------------------------------------------------------------------
// Canonical encoding version for the plaintext vault body.
// ---------------------------------------------------------------------------
constexpr uint32_t CANONICAL_VERSION = 1;  // "SEIS-CANON-v1"

// ---------------------------------------------------------------------------
// Subkey derivation labels (agenda §6.3). Never reuse across purposes.
// ---------------------------------------------------------------------------
inline constexpr const char* LBL_VMK_WRAP = "seis-vmk-wrap-v1";
inline constexpr const char* LBL_MANIFEST = "seis-manifest-v1";
inline constexpr const char* LBL_MANIFEST_NONCE = "seis-manifest-nonce-v1";
inline constexpr const char* LBL_PAGE_AEAD = "seis-page-aead-v1";
inline constexpr const char* LBL_PAGE_NONCE = "seis-page-nonce-v1";
inline constexpr const char* LBL_HEADER_AUTH = "seis-header-auth-v1";
inline constexpr const char* LBL_RUNTIME_ROOT = "seis-runtime-root-v1";
inline constexpr const char* LBL_ENTRY_META = "seis-entry-metadata-v1";
inline constexpr const char* LBL_ENTRY_SECRET = "seis-entry-secret-v1";
inline constexpr const char* LBL_EXPORT = "seis-export-v1";
inline constexpr const char* LBL_A2ONT_CTX = "seis-a2ont-context-v1";
inline constexpr const char* LBL_PADDING = "seis-padding-v1";
// In-memory only (never in a file): the runtime store's PRK salt. v2 since it
// carries VERSE_RUNTIME_KEYS.
inline constexpr const char* LBL_RUNTIME_PRK = "seis-runtime-prk-v2";

// ---------------------------------------------------------------------------
// Randomness (entropy.cpp): the mixer of the OS CSPRNG and RDSEED.
// ---------------------------------------------------------------------------
inline constexpr const char* LBL_ENTROPY_MIX = "secraxis-entropy-mix-v1";        // salt
inline constexpr const char* LBL_ENTROPY_OUT = "secraxis-entropy-out-v1";        // info
inline constexpr const char* LBL_ENTROPY_STREAM = "secraxis-entropy-stream-v1";  // info

// Secraxis's verse, one line per salt it marks: the mixer's and the runtime
// store's. Public constants that only name a context; they replace no entropy
// and never reach a stored key's derivation, so they may change in any release.
inline constexpr const char* VERSE_ENTROPY_MIX =
    "Every watcher lies alone; two liars cannot lie as one.";
inline constexpr const char* VERSE_RUNTIME_KEYS =
    "Nothing that rests goes unseen, so the keys never rest.";

// Page size for the AEAD page layer (fixed in v1; recorded + authenticated).
constexpr uint32_t SEIS_PAGE_SIZE = 64 * 1024;

}  // namespace secraxis

#endif  // SECRAXIS_CRYPTO_PROFILE_H
