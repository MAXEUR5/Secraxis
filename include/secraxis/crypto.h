// crypto.h — thin, total wrappers over vetted primitives (agenda §4.3).
//
// Everything here delegates to libsodium (AEAD, CSPRNG, HKDF-SHA-512,
// constant-time compare) or the Argon2 reference implementation (kdf.h).
// No primitive is implemented in this codebase.
#ifndef SECRAXIS_CRYPTO_H
#define SECRAXIS_CRYPTO_H

#include <cstddef>
#include <cstdint>

#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"

namespace secraxis {

// Must be called (and succeed) before any other function here. Idempotent.
bool crypto_init() noexcept;

// ---------------------------------------------------------------------------
// Randomness (entropy.cpp). Every draw takes 64 fresh bytes from the OS
// CSPRNG and 64 from the CPU's RDSEED (health-checked) and mixes them with
// HKDF-SHA-512. There is no fallback: without a working RDSEED every draw
// fails, and the operation that needed it is refused (Err::RngFailed).
// ---------------------------------------------------------------------------
enum class EntropyState : uint8_t {
    Ready,     // RDSEED present and its start-up self-test passed
    NoRdseed,  // the processor (or the virtual machine) offers no RDSEED
    Failed,    // RDSEED failed a health check or stopped answering
    NoMemory,  // no secure memory for the generator's working buffer
};
// Runs RDSEED's start-up self-test the first time it is called; afterwards
// returns the result. Anything but Ready is final until the program restarts.
EntropyState entropy_state() noexcept;
// One sentence for the user: why no random numbers can be made.
const char* entropy_state_text(EntropyState s) noexcept;

// Fills out[0, n). False when no random numbers can be made: out is zeroed
// and the caller must refuse its operation with Err::RngFailed.
[[nodiscard]] bool random_bytes(uint8_t* out, size_t n) noexcept;
// Secret randomness (VMK, keys) straight into secure memory. Fails with
// Err::RngFailed or Err::AllocationFailed.
Result<SecureBuffer> random_secret(size_t n);

// ---------------------------------------------------------------------------
// HKDF-SHA-512 (RFC 5869, via libsodium). PRK length is 64 bytes.
// ---------------------------------------------------------------------------
constexpr size_t HKDF_PRK_LEN = 64;

// prk_out must be HKDF_PRK_LEN bytes (inside a SecureBuffer).
Status hkdf_extract(uint8_t* prk_out, ByteView salt, ByteView ikm) noexcept;
// out_len <= 255*64. info is a pre-built canonical binding blob.
Status hkdf_expand(uint8_t* out, size_t out_len, const uint8_t* prk,
                   ByteView info) noexcept;

// Convenience: extract(salt, ikm) then expand(info) into a SecureBuffer.
SecureBuffer hkdf_derive(ByteView salt, ByteView ikm, ByteView info, size_t out_len);

// AEAD lives in aead.h (profile-dispatched: SEIS-AEAD-1 / SEIS-AEAD-2).

}  // namespace secraxis

#endif  // SECRAXIS_CRYPTO_H
