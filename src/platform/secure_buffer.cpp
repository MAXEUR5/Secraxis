#include "secraxis/secure_buffer.h"

#include <sodium.h>

#include <atomic>
#include <cstring>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace secraxis {

namespace {
// sodium_init is idempotent and thread-safe; every entry point that can touch
// secure memory funnels through this.
bool ensure_sodium() noexcept {
    return sodium_init() >= 0;
}

#if defined(SECRAXIS_TEST_WEAK_KDF)
std::atomic<long> g_fail_alloc_in{0};
#endif
}  // namespace

#if defined(SECRAXIS_TEST_WEAK_KDF)
// TEST BUILDS ONLY (like the weak KDF profile): the n-th next allocation
// fails (0: none), so tests can check that callers fail loudly rather than
// carry on without the secret. The tests that use it declare it themselves.
void secure_alloc_fail_nth_for_test(long n) noexcept { g_fail_alloc_in.store(n); }
#endif

SecureBuffer SecureBuffer::alloc(size_t n) noexcept {
    SecureBuffer b;
    if (!ensure_sodium()) return b;
    if (n == 0) return b;
#if defined(SECRAXIS_TEST_WEAK_KDF)
    if (g_fail_alloc_in.load() > 0 && g_fail_alloc_in.fetch_sub(1) == 1) return b;
#endif
    void* p = sodium_malloc(n);
    if (p == nullptr) return b;
    std::memset(p, 0, n);
    b.data_ = static_cast<uint8_t*>(p);
    b.size_ = n;
    return b;
}

SecureBuffer SecureBuffer::clone() const noexcept {
    SecureBuffer b;
    if (!valid()) return b;
    b = SecureBuffer::alloc(size_);
    if (b.valid()) std::memcpy(b.data_, data_, size_);
    return b;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        reset();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

SecureBuffer::~SecureBuffer() { reset(); }

void SecureBuffer::reset() noexcept {
    if (data_ != nullptr) {
        // sodium_free wipes the region (and canary-checks) before unmapping.
        sodium_free(data_);
        data_ = nullptr;
        size_ = 0;
    }
}

bool SecureBuffer::ct_equals(const SecureBuffer& other) const noexcept {
    return ct_equals(other.view());
}

bool SecureBuffer::ct_equals(ByteView other) const noexcept {
    if (size_ != other.len) return false;
    if (size_ == 0) return true;
    return ct_equal(data_, other.ptr, size_);
}

void secure_wipe(void* p, size_t n) noexcept {
    if (p != nullptr && n > 0) sodium_memzero(p, n);
}

bool ct_equal(const void* a, const void* b, size_t n) noexcept {
    if (n == 0) return true;
    return sodium_memcmp(a, b, n) == 0;
}

bool best_effort_lock(void* p, size_t n) noexcept {
    if (p == nullptr || n == 0) return true;
    if (!ensure_sodium()) return false;
    // sodium_mlock also applies MADV_DONTDUMP where available.
    return sodium_mlock(p, n) == 0;
}

void best_effort_unlock(void* p, size_t n) noexcept {
    if (p == nullptr || n == 0) return;
    // sodium_munlock wipes before unlocking — exactly what we want for arenas.
    sodium_munlock(p, n);
}

void best_effort_nodump(void* p, size_t n) noexcept {
    if (p == nullptr || n == 0) return;
#if defined(MADV_DONTDUMP)
    madvise(p, n, MADV_DONTDUMP);
#else
    (void)p;
    (void)n;
#endif
}

}  // namespace secraxis
