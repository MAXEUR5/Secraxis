// secure_buffer.h — secure memory containers (agenda §13).
//
// SecureBuffer is the ONLY permitted home for secret bytes: master password,
// KEK material, VMK, subkeys, page keys, A2ONT seed, canonical plaintext,
// entry secrets, clipboard scratch, export plaintext.
//
// Guarantees (via libsodium's guarded allocator):
//  * allocation is placed before a guard page, with a canary; overflow/underflow
//    touching the guard page faults instead of corrupting silently
//  * pages are best-effort locked (mlock / VirtualLock) and flagged no-dump
//    where the platform supports it (MADV_DONTDUMP)
//  * zeroized on destruction (sodium_free wipes before unmapping)
//  * move-only: no accidental copies; an explicit, audited clone() exists
//  * no stream operators, no serialization, no implicit string conversion
//
// Honest limitation (documented in RUNTIME_MEMORY_SECURITY.md): none of this
// defeats a malicious kernel, DMA, or code running inside this process.
#ifndef SECRAXIS_SECURE_BUFFER_H
#define SECRAXIS_SECURE_BUFFER_H

#include <cstddef>
#include <cstdint>

#include "secraxis/common.h"

namespace secraxis {

class SecureBuffer final {
  public:
    SecureBuffer() noexcept = default;

    // Allocates n bytes of guarded, locked, wipe-on-free memory (zero-filled).
    // On allocation failure returns an empty buffer (check valid()).
    static SecureBuffer alloc(size_t n) noexcept;

    // Explicit, audited deep copy. Every call site is a review point.
    SecureBuffer clone() const noexcept;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    ~SecureBuffer();

    bool valid() const noexcept { return data_ != nullptr; }
    size_t size() const noexcept { return size_; }
    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    ByteView view() const noexcept { return ByteView(data_, size_); }
    MutByteView mut() noexcept { return MutByteView(data_, size_); }

    // Wipe now and release. Safe on empty buffers.
    void reset() noexcept;

    // Constant-time equality (length mismatch returns false without leaking
    // position information; length itself is not secret in our uses).
    bool ct_equals(const SecureBuffer& other) const noexcept;
    bool ct_equals(ByteView other) const noexcept;

  private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

// Wipe arbitrary memory (guaranteed not elided).
void secure_wipe(void* p, size_t n) noexcept;

// Constant-time comparison of equal-length regions.
bool ct_equal(const void* a, const void* b, size_t n) noexcept;

// Best-effort page locking for memory owned elsewhere (e.g. the KDF arena).
// Returns false if unavailable — callers treat that as a non-secret warning.
bool best_effort_lock(void* p, size_t n) noexcept;
void best_effort_unlock(void* p, size_t n) noexcept;
// No-dump / no-fork-inherit hints where the platform has them.
void best_effort_nodump(void* p, size_t n) noexcept;

}  // namespace secraxis

#endif  // SECRAXIS_SECURE_BUFFER_H
