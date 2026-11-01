#include "secraxis/kdf.h"

#include <argon2.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace secraxis {

namespace {

// The argon2_context callbacks carry no user pointer, so arena state is
// process-global, and argon2id_raw runs one KDF at a time (g_kdf_mutex):
// an unlock abandoned with Esc may still be deriving when the next one
// starts, and two arenas of up to 1 GiB must not pile up.
std::atomic<bool> g_arena_locked{false};
std::mutex g_kdf_mutex;

int arena_allocate(uint8_t** memory, size_t bytes) {
    void* p = std::malloc(bytes);
    if (p == nullptr) return ARGON2_MEMORY_ALLOCATION_ERROR;
    bool locked = best_effort_lock(p, bytes);
    g_arena_locked.store(locked, std::memory_order_relaxed);
    if (!locked) best_effort_nodump(p, bytes);
    *memory = static_cast<uint8_t*>(p);
    return ARGON2_OK;
}

void arena_deallocate(uint8_t* memory, size_t bytes) {
    if (memory == nullptr) return;
    if (g_arena_locked.load(std::memory_order_relaxed)) {
        best_effort_unlock(memory, bytes);  // wipes, then unlocks
    } else {
        secure_wipe(memory, bytes);
    }
    std::free(memory);
}

}  // namespace

#if defined(SECRAXIS_TEST_WEAK_KDF)
// In every binary built with the weak test profile, and in no other: the
// release check (the shipped binary must not contain this string) relies on
// it. A plain local string was optimized away, so that check could never
// fail; this one has external linkage and is kept.
#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
extern const char kWeakKdfMarker[] = "SECRAXIS-WEAK-KDF";
#endif

const KdfProfile* kdf_profile_by_id(uint32_t id) noexcept {
#if defined(SECRAXIS_TEST_WEAK_KDF)
    // TEST BUILDS ONLY (see CMakeLists): tiny profile so tamper-matrix tests
    // do not pay minutes of Argon2. Absent from release builds; the marker
    // string below is greppable in binaries as a release-gate check.
    if (id == 999) {
        static const KdfProfile kWeak{static_cast<KdfProfileId>(999), 16, 1, 1};
        return &kWeak;
    }
#endif
    switch (static_cast<KdfProfileId>(id)) {
        case KdfProfileId::Floor:
            return &KDF_FLOOR;
        case KdfProfileId::Default:
            return &KDF_DEFAULT;
        case KdfProfileId::Strong:
            return &KDF_STRONG;
        default:
            return nullptr;
    }
}

KdfOutcome argon2id_raw(ByteView password, ByteView salt, uint32_t t_cost,
                        uint32_t mem_kib, uint32_t lanes,
                        size_t out_len) noexcept {
    KdfOutcome outcome;
    if (out_len < 4 || out_len > 1024 || salt.len < 8 || lanes == 0 ||
        mem_kib < 8 * lanes) {
        outcome.err = Err::InvalidArgument;
        return outcome;
    }
    SecureBuffer out = SecureBuffer::alloc(out_len);
    if (!out.valid()) {
        outcome.err = Err::AllocationFailed;
        return outcome;
    }

    argon2_context ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.out = out.data();
    ctx.outlen = static_cast<uint32_t>(out_len);
    // The reference API takes non-const pointers but does not modify unless
    // the corresponding CLEAR flag is set (we manage our own wiping).
    ctx.pwd = const_cast<uint8_t*>(password.ptr);
    ctx.pwdlen = static_cast<uint32_t>(password.len);
    ctx.salt = const_cast<uint8_t*>(salt.ptr);
    ctx.saltlen = static_cast<uint32_t>(salt.len);
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = nullptr;
    ctx.adlen = 0;
    ctx.t_cost = t_cost;
    ctx.m_cost = mem_kib;
    ctx.lanes = lanes;
    ctx.threads = lanes;
    ctx.version = ARGON2_VERSION_13;
    ctx.allocate_cbk = arena_allocate;
    ctx.free_cbk = arena_deallocate;
    ctx.flags = ARGON2_DEFAULT_FLAGS;

    std::lock_guard<std::mutex> one_at_a_time(g_kdf_mutex);
    int rc = argon2id_ctx(&ctx);
    if (rc != ARGON2_OK) {
        // Non-secret failure classification only.
        outcome.err = (rc == ARGON2_MEMORY_ALLOCATION_ERROR)
                          ? Err::AllocationFailed
                          : Err::Internal;
        return outcome;
    }
    outcome.err = Err::Ok;
    outcome.kek_material = static_cast<SecureBuffer&&>(out);
    outcome.arena_locked = g_arena_locked.load(std::memory_order_relaxed);
    return outcome;
}

KdfOutcome derive_kek_material(ByteView master_password, ByteView salt,
                               const KdfProfile& profile) noexcept {
    KdfOutcome outcome;
    if (salt.len != KDF_SALT_LEN) {
        outcome.err = Err::InvalidArgument;
        return outcome;
    }
    // MiB -> KiB; profiles are compile-time constants, no overflow possible.
    return argon2id_raw(master_password, salt, profile.iterations,
                        profile.memory_mib * 1024, profile.lanes, KDF_OUT_LEN);
}

}  // namespace secraxis
