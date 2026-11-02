// common.h — foundational types for Secraxis Vault Manager.
//
// Rules enforced here:
//  * std::vector<uint8_t> (Bytes) is for NON-SECRET data only. Secrets live in
//    SecureBuffer (secure_buffer.h).
//  * All multi-byte integers in .seis structures are little-endian, always
//    encoded through the helpers below — never through memcpy of host ints.
//  * User-facing failures collapse to generic codes; internal codes are
//    non-secret phase identifiers (agenda §17).
#ifndef SECRAXIS_COMMON_H
#define SECRAXIS_COMMON_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace secraxis {

using Bytes = std::vector<uint8_t>;  // non-secret data only

// ---------------------------------------------------------------------------
// Error model (agenda §17.2). No code carries secret data; no message strings
// derived from vault content.
// ---------------------------------------------------------------------------
enum class Err : uint32_t {
    Ok = 0,
    // Generic authentication/parse failure. The ONLY code the UI may show for
    // wrong password / tampered vault / corrupted vault (rendered as
    // "Wrong password or corrupted vault.").
    AuthGeneric = 1,

    FormatUnsupported = 2,   // bad magic / unknown version (safe to disclose)
    IoRead = 3,
    IoWrite = 4,
    MemoryLockUnavailable = 5,  // non-fatal warning path
    TerminalTooSmall = 6,
    ExportPermission = 7,
    InvalidArgument = 8,     // programmer error / precondition
    Internal = 9,
    RngFailed = 10,
    AllocationFailed = 11,
    Canceled = 12,
    ClipboardUnavailable = 13,
    NotFound = 14,
    Exists = 15,
    // A save found the vault file changed since this session loaded or last
    // wrote it (another window, or a sync tool, saved over it): nothing was
    // written. Only reachable after a successful unlock (no oracle).
    VaultChanged = 16,
    // This vault's master password, VMK or KDF was changed elsewhere since
    // this session opened it (passwd, rekey or upgrade in another program):
    // nothing this session writes may carry its old keys back, over the
    // vault or beside it. Nothing was written; only reachable after a
    // successful unlock (no oracle).
    VaultRekeyed = 17,
    // The vault opened with this password (every AEAD tag verified), but a
    // newer Secraxis wrote its contents, in a format this version cannot
    // read. Only reachable after full authentication (no oracle: a wrong
    // password or a tampered file never gets this far).
    NewerFormat = 18,
};

inline const char* err_name(Err e) noexcept {  // stable non-secret identifier
    switch (e) {
        case Err::Ok: return "OK";
        case Err::AuthGeneric: return "ERR_AUTH_GENERIC";
        case Err::FormatUnsupported: return "ERR_FORMAT_UNSUPPORTED";
        case Err::IoRead: return "ERR_IO_READ";
        case Err::IoWrite: return "ERR_IO_WRITE";
        case Err::MemoryLockUnavailable: return "ERR_MEMORY_LOCK_UNAVAILABLE";
        case Err::TerminalTooSmall: return "ERR_TUI_TERMINAL_TOO_SMALL";
        case Err::ExportPermission: return "ERR_EXPORT_PERMISSION";
        case Err::InvalidArgument: return "ERR_INVALID_ARGUMENT";
        case Err::Internal: return "ERR_INTERNAL";
        case Err::RngFailed: return "ERR_RNG_FAILED";
        case Err::AllocationFailed: return "ERR_ALLOCATION_FAILED";
        case Err::Canceled: return "ERR_CANCELED";
        case Err::ClipboardUnavailable: return "ERR_CLIPBOARD_UNAVAILABLE";
        case Err::NotFound: return "ERR_NOT_FOUND";
        case Err::Exists: return "ERR_EXISTS";
        case Err::VaultChanged: return "ERR_VAULT_CHANGED";
        case Err::VaultRekeyed: return "ERR_VAULT_REKEYED";
        case Err::NewerFormat: return "ERR_NEWER_FORMAT";
    }
    return "ERR_UNKNOWN";
}

// Minimal result type: Err + value. (No exceptions across module boundaries;
// exceptions must never carry secret text — we avoid them entirely for flow.)
template <typename T>
struct Result {
    Err err = Err::Internal;
    T value{};

    bool ok() const noexcept { return err == Err::Ok; }
    static Result success(T v) { return Result{Err::Ok, static_cast<T&&>(v)}; }
    static Result failure(Err e) { return Result{e, T{}}; }
};

struct Unit {};
using Status = Result<Unit>;
inline Status status_ok() { return Status::success(Unit{}); }
inline Status status_fail(Err e) { return Status::failure(e); }

// ---------------------------------------------------------------------------
// Byte views (C++17; no std::span). Non-owning.
// ---------------------------------------------------------------------------
struct ByteView {
    const uint8_t* ptr = nullptr;
    size_t len = 0;

    ByteView() = default;
    ByteView(const uint8_t* p, size_t n) : ptr(p), len(n) {}
    explicit ByteView(const Bytes& b) : ptr(b.data()), len(b.size()) {}
    ByteView(const char* s, size_t n) : ptr(reinterpret_cast<const uint8_t*>(s)), len(n) {}

    bool empty() const noexcept { return len == 0; }
    ByteView sub(size_t off, size_t n) const noexcept {
        if (off > len) return ByteView(ptr + len, 0);
        if (n > len - off) n = len - off;
        return ByteView(ptr + off, n);
    }
};

// Constructs a view over a string literal / label (excluding NUL).
inline ByteView label(const char* s) {
    size_t n = 0;
    while (s[n] != '\0') ++n;
    return ByteView(s, n);
}

struct MutByteView {
    uint8_t* ptr = nullptr;
    size_t len = 0;
    MutByteView() = default;
    MutByteView(uint8_t* p, size_t n) : ptr(p), len(n) {}
    explicit MutByteView(Bytes& b) : ptr(b.data()), len(b.size()) {}
};

// ---------------------------------------------------------------------------
// Little-endian encoding helpers. Checked arithmetic is the caller's job for
// sizes; these never read/write out of the given pointer's promised range.
// ---------------------------------------------------------------------------
inline void store_le16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}
inline void store_le32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}
inline void store_le64(uint8_t* p, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
inline uint16_t load_le16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}
inline uint32_t load_le32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t load_le64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

inline void append_bytes(Bytes& out, ByteView v) {
    out.insert(out.end(), v.ptr, v.ptr + v.len);
}
inline void append_le32(Bytes& out, uint32_t v) {
    uint8_t b[4];
    store_le32(b, v);
    out.insert(out.end(), b, b + 4);
}
inline void append_le64(Bytes& out, uint64_t v) {
    uint8_t b[8];
    store_le64(b, v);
    out.insert(out.end(), b, b + 8);
}
// Length-prefixed field: u32le(len) || bytes. The single canonical way any
// variable-length field enters a derivation context or an AAD blob.
inline void append_lp(Bytes& out, ByteView v) {
    append_le32(out, static_cast<uint32_t>(v.len));
    append_bytes(out, v);
}

// Checked size addition (overflow-safe): false on overflow.
inline bool checked_add(size_t a, size_t b, size_t* out) noexcept {
    if (a > SIZE_MAX - b) return false;
    *out = a + b;
    return true;
}
inline bool checked_mul(size_t a, size_t b, size_t* out) noexcept {
    if (b != 0 && a > SIZE_MAX / b) return false;
    *out = a * b;
    return true;
}

}  // namespace secraxis

#endif  // SECRAXIS_COMMON_H
