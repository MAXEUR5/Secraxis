// entropy.cpp — every random byte Secraxis uses.
//
// Each call draws two independent sources afresh and mixes them:
//
//   IKM  = OS[64] || RDSEED[64]                        (always 128 bytes)
//   salt = lp(LBL_ENTROPY_MIX) || lp(VERSE_ENTROPY_MIX)
//   PRK  = HKDF-Extract(salt, IKM)                     (HMAC-SHA-512)
//   info = lp(label) || le64(counter) || le64(tsc) || le64(pid)
//   out  = HKDF-Expand(PRK, info, n)                   label LBL_ENTROPY_OUT
//          n > 16320: ChaCha20 keyed by HKDF-Expand(PRK, info, 32),
//                     label LBL_ENTROPY_STREAM
//
// The output is unpredictable if either source is sound, and a broken or
// hostile source cannot cancel the other without breaking SHA-512.
//   OS:     libsodium's randombytes_buf (RtlGenRandom / getrandom); it aborts
//           the process rather than return less.
//   RDSEED: the 64-bit form, health-checked below. Any failure is final for
//           the process, and nothing is ever made from the OS source alone.
// The counter, the time-stamp counter and the process id only make clones of
// one process (a copied virtual machine) diverge: they claim no entropy and
// stay out of the IKM. Between calls only the counter and the last RDSEED
// word (for the repetition check) are kept.
#include "secraxis/crypto.h"

#include <sodium.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>

#include "secraxis/crypto_profile.h"

#if defined(__x86_64__) || defined(_M_X64)
#define SX_HAVE_RDSEED_ISA 1
#include <cpuid.h>
#include <immintrin.h>
#include <x86intrin.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define SX_MSAN_UNPOISON(p, n) __msan_unpoison((p), (n))
#endif
#endif
#ifndef SX_MSAN_UNPOISON
#define SX_MSAN_UNPOISON(p, n) ((void)0)
#endif

namespace secraxis {

namespace {

constexpr size_t kSourceBytes = 64;          // from each source, every call
constexpr size_t kWords = kSourceBytes / 8;  // RDSEED words per call
constexpr size_t kSelfTestWords = 64;        // 4096 bits at start-up
constexpr int kMinBits = 2;                  // a word needs >= 2 zeros and >= 2 ones
constexpr int kBalanceLow = 2048 - 256;      // the self-test's ones in 4096 bits:
constexpr int kBalanceHigh = 2048 + 256;     // within 8 standard deviations
constexpr size_t kExpandMax = 255 * 64;      // HKDF-SHA-512's longest output
// RDSEED often answers "not ready" (about four times in five back to back on
// the test machines); a word that takes longer than this counts as RDSEED
// having stopped.
constexpr auto kWordTimeout = std::chrono::milliseconds(100);

// The working buffer, in secure memory: both sources, the PRK, the stream
// seed, and the previous draw's last RDSEED word.
constexpr size_t kOffOs = 0;
constexpr size_t kOffHw = 64;
constexpr size_t kOffPrk = 128;
constexpr size_t kOffSeed = 192;
constexpr size_t kOffLast = 224;
constexpr size_t kScratch = 232;
static_assert(kOffSeed + randombytes_SEEDBYTES == kOffLast, "scratch layout");

// Salt and info are built on the stack: labels and verse are short.
constexpr size_t kSaltMax = 128;
constexpr size_t kInfoMax = 64;
static_assert(8 + std::char_traits<char>::length(LBL_ENTROPY_MIX) +
                      std::char_traits<char>::length(VERSE_ENTROPY_MIX) <= kSaltMax,
              "salt buffer");
static_assert(4 + std::char_traits<char>::length(LBL_ENTROPY_STREAM) + 24 <= kInfoMax &&
                  4 + std::char_traits<char>::length(LBL_ENTROPY_OUT) + 24 <= kInfoMax,
              "info buffer");

struct Generator {
    std::mutex mu;
    bool tested = false;
    EntropyState state = EntropyState::NoRdseed;
    SecureBuffer scratch;
    uint64_t counter = 0;
#ifdef SECRAXIS_TEST_WEAK_KDF
    bool forced = false;  // every draw fails with forced_state
    EntropyState forced_state = EntropyState::Ready;
    long fail_in = 0;     // the fail_in-th next draw fails (0: none)
#endif
};

Generator& gen() {
    static Generator g;
    return g;
}

size_t put_lp(uint8_t* p, const char* s) noexcept {
    const size_t n = std::strlen(s);
    store_le32(p, static_cast<uint32_t>(n));
    std::memcpy(p + 4, s, n);
    // MemorySanitizer (clang 18) loses the copy's shadow when the source is
    // one of two constant strings picked at run time (mix()'s labels): the
    // bytes come from string literals, so they are initialized.
    SX_MSAN_UNPOISON(p + 4, n);
    return 4 + n;
}

bool word_ok(uint64_t w) noexcept {
    const int ones = __builtin_popcountll(w);
    return ones >= kMinBits && 64 - ones >= kMinBits;
}

// The words of one draw (little-endian): each sound, none repeated within
// the draw, none equal to the previous draw's last word (if given).
bool block_ok(const uint8_t* words, size_t n, const uint64_t* previous) noexcept {
    for (size_t i = 0; i < n; ++i) {
        const uint64_t w = load_le64(words + 8 * i);
        if (!word_ok(w)) return false;
        if (previous != nullptr && w == *previous) return false;
        for (size_t j = 0; j < i; ++j)
            if (load_le64(words + 8 * j) == w) return false;
    }
    return true;
}

// The start-up self-test's 64 words: as above, and their 4096 bits balanced.
bool selftest_ok(const uint8_t* words, size_t n) noexcept {
    if (n != kSelfTestWords || !block_ok(words, n, nullptr)) return false;
    int ones = 0;
    for (size_t i = 0; i < n; ++i) ones += __builtin_popcountll(load_le64(words + 8 * i));
    return ones >= kBalanceLow && ones <= kBalanceHigh;
}

bool cpu_has_rdseed() noexcept {
#ifdef SX_HAVE_RDSEED_ISA
    unsigned a = 0, b = 0, c = 0, d = 0;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) != 0 && (b & (1u << 18)) != 0;
#else
    return false;
#endif
}

#ifdef SX_HAVE_RDSEED_ISA
__attribute__((target("rdseed"))) int rdseed_step(unsigned long long* v) noexcept {
    return _rdseed64_step(v);
}
#endif

// One word, asked again while RDSEED answers "not ready". Only called once
// cpu_has_rdseed() said yes.
bool rdseed_word(uint64_t* out) noexcept {
#ifdef SX_HAVE_RDSEED_ISA
    const auto start = std::chrono::steady_clock::now();
    for (unsigned tries = 1;; ++tries) {
        unsigned long long v = 0;
        if (rdseed_step(&v) != 0) {
            SX_MSAN_UNPOISON(&v, sizeof(v));
            *out = static_cast<uint64_t>(v);
            sodium_memzero(&v, sizeof(v));
            return true;
        }
        _mm_pause();
        if ((tries & 255u) == 0 && std::chrono::steady_clock::now() - start > kWordTimeout)
            return false;
    }
#else
    (void)out;
    return false;
#endif
}

uint64_t timestamp() noexcept {
#ifdef SX_HAVE_RDSEED_ISA
    return static_cast<uint64_t>(__rdtsc());
#else
    return 0;
#endif
}

uint64_t process_id() noexcept {
#if defined(_WIN32)
    return static_cast<uint64_t>(GetCurrentProcessId());
#else
    return static_cast<uint64_t>(getpid());  // 32 bits: exact (C++ reduces mod 2^64)
#endif
}

// The construction in the header comment, on given inputs. ikm: 128 bytes;
// prk (64) and seed (32): working space in secure memory.
bool mix(const uint8_t* ikm, uint64_t counter, uint64_t tsc, uint64_t pid, uint8_t* prk,
         uint8_t* seed, uint8_t* out, size_t n) noexcept {
    uint8_t salt[kSaltMax];
    size_t sl = put_lp(salt, LBL_ENTROPY_MIX);
    sl += put_lp(salt + sl, VERSE_ENTROPY_MIX);
    if (!hkdf_extract(prk, ByteView(salt, sl), ByteView(ikm, 2 * kSourceBytes)).ok())
        return false;
    const bool stream = n > kExpandMax;
    uint8_t info[kInfoMax];
    size_t il = put_lp(info, stream ? LBL_ENTROPY_STREAM : LBL_ENTROPY_OUT);
    store_le64(info + il, counter);
    store_le64(info + il + 8, tsc);
    store_le64(info + il + 16, pid);
    il += 24;
    if (!stream) return hkdf_expand(out, n, prk, ByteView(info, il)).ok();
    if (!hkdf_expand(seed, randombytes_SEEDBYTES, prk, ByteView(info, il)).ok()) return false;
    randombytes_buf_deterministic(out, n, seed);
    return true;
}

// RDSEED's start-up self-test: 64 words. The caller holds g.mu.
EntropyState start_up(Generator& g) noexcept {
    if (!cpu_has_rdseed()) return EntropyState::NoRdseed;
    g.scratch = SecureBuffer::alloc(kScratch);
    SecureBuffer words = SecureBuffer::alloc(kSelfTestWords * 8);
    if (!g.scratch.valid() || !words.valid()) return EntropyState::NoMemory;
    for (size_t i = 0; i < kSelfTestWords; ++i) {
        uint64_t w = 0;
        if (!rdseed_word(&w)) return EntropyState::Failed;
        store_le64(words.data() + 8 * i, w);
    }
    if (!selftest_ok(words.data(), kSelfTestWords)) return EntropyState::Failed;
    // The repetition check's first reference: the self-test's last word.
    std::memcpy(g.scratch.data() + kOffLast, words.data() + 8 * (kSelfTestWords - 1), 8);
    return EntropyState::Ready;
}

// The caller holds g.mu.
bool ready(Generator& g) noexcept {
    if (!g.tested) {
        g.state = start_up(g);
        g.tested = true;
    }
#ifdef SECRAXIS_TEST_WEAK_KDF
    if (g.forced) return false;
#endif
    return g.state == EntropyState::Ready;
}

// One draw into out[0, n). The caller holds g.mu and saw ready(g).
bool draw(Generator& g, uint8_t* out, size_t n) noexcept {
    uint8_t* s = g.scratch.data();
#ifdef SECRAXIS_TEST_WEAK_KDF
    if (g.fail_in > 0 && --g.fail_in == 0) {
        g.state = EntropyState::Failed;
        return false;
    }
#endif
    randombytes_buf(s + kOffOs, kSourceBytes);
    bool ok = true;
    for (size_t i = 0; i < kWords && ok; ++i) {
        uint64_t w = 0;
        ok = rdseed_word(&w);
        store_le64(s + kOffHw + 8 * i, w);
    }
    const uint64_t previous = load_le64(s + kOffLast);
    ok = ok && block_ok(s + kOffHw, kWords, &previous);
    if (ok) {
        std::memcpy(s + kOffLast, s + kOffHw + 8 * (kWords - 1), 8);
        g.counter += 1;
        ok = mix(s + kOffOs, g.counter, timestamp(), process_id(), s + kOffPrk, s + kOffSeed,
                 out, n);
    } else {
        g.state = EntropyState::Failed;  // final until the program restarts
    }
    sodium_memzero(s, kOffLast);  // the sources, the PRK and the seed
    return ok;
}

}  // namespace

EntropyState entropy_state() noexcept {
    Generator& g = gen();
    std::lock_guard<std::mutex> lock(g.mu);
    ready(g);
#ifdef SECRAXIS_TEST_WEAK_KDF
    if (g.forced) return g.forced_state;
#endif
    return g.state;
}

const char* entropy_state_text(EntropyState s) noexcept {
    switch (s) {
        case EntropyState::Ready:
            return "Hardware random numbers (RDSEED) are working.";
        case EntropyState::NoRdseed:
            return "This processor offers no RDSEED (or the virtual machine hides it). "
                   "Secraxis makes every key and nonce from RDSEED and the system's "
                   "generator together, never from the system's alone, so it cannot open, "
                   "create or save vaults here.";
        case EntropyState::Failed:
            return "The processor's RDSEED failed its checks or stopped answering. "
                   "Secraxis never uses the system's generator alone, so nothing can be "
                   "opened, created or saved until it restarts and RDSEED passes its checks.";
        case EntropyState::NoMemory:
            return "Not enough secure memory to start the random number generator.";
    }
    return "Random numbers are unavailable.";
}

bool random_bytes(uint8_t* out, size_t n) noexcept {
    if (n == 0) return true;
    if (out == nullptr) return false;
    Generator& g = gen();
    std::lock_guard<std::mutex> lock(g.mu);
    if (ready(g) && draw(g, out, n)) return true;
    sodium_memzero(out, n);
    return false;
}

Result<SecureBuffer> random_secret(size_t n) {
    using R = Result<SecureBuffer>;
    SecureBuffer b = SecureBuffer::alloc(n);
    if (!b.valid()) return R::failure(Err::AllocationFailed);
    if (!random_bytes(b.data(), n)) return R::failure(Err::RngFailed);
    return R::success(static_cast<SecureBuffer&&>(b));
}

#ifdef SECRAXIS_TEST_WEAK_KDF
// Test builds only; the tests that use these declare them themselves.
// Anything but Ready: every draw fails and entropy_state() says s. Ready:
// back to the real generator, its self-test run again.
void entropy_force_state_for_test(EntropyState s) noexcept {
    Generator& g = gen();
    std::lock_guard<std::mutex> lock(g.mu);
    g.forced = s != EntropyState::Ready;
    g.forced_state = s;
    g.fail_in = 0;
    if (s == EntropyState::Ready) g.tested = false;
}

// The n-th next draw fails as a failed health check would: the generator
// stays failed until forced back to Ready.
void entropy_fail_nth_for_test(long n) noexcept {
    Generator& g = gen();
    std::lock_guard<std::mutex> lock(g.mu);
    g.fail_in = n;
}

bool rdseed_word_ok_for_test(uint64_t w) noexcept { return word_ok(w); }

bool rdseed_block_ok_for_test(const uint64_t* w, size_t n, const uint64_t* previous,
                              bool selftest) noexcept {
    std::string le(8 * n, '\0');
    for (size_t i = 0; i < n; ++i) store_le64(reinterpret_cast<uint8_t*>(&le[8 * i]), w[i]);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(le.data());
    return selftest ? selftest_ok(p, n) : block_ok(p, n, previous);
}

bool entropy_mix_for_test(const uint8_t* ikm, uint64_t counter, uint64_t tsc, uint64_t pid,
                          uint8_t* out, size_t n) noexcept {
    SecureBuffer work = SecureBuffer::alloc(64 + randombytes_SEEDBYTES);
    return work.valid() &&
           mix(ikm, counter, tsc, pid, work.data(), work.data() + 64, out, n);
}
#endif

}  // namespace secraxis
