#include "secraxis/canonical_codec.h"

#include <cstring>

namespace secraxis {

// Layout:
//   u32 magic 'SXC1' | u32 entry_count
//   per entry (ascending entry_id, unique):
//     u8[16] entry_id | u64 created_at | u64 updated_at | u32 field_bytes
//     fields: (u16 field_id | u32 len | bytes)*  — ascending id, unique,
//             metadata (<32) before secrets (>=32) by the ordering rule
namespace {

constexpr uint32_t CANON_MAGIC = 0x31435853;  // "SXC1" little-endian
constexpr size_t ENTRY_FIXED = ENTRY_ID_LEN + 8 + 8 + 4;
constexpr size_t FIELD_HDR = 2 + 4;

struct FieldRef {
    uint16_t id;
    ByteView data;
};

// Enumerate an entry's present fields in canonical (ascending id) order.
// Encoder-side; lengths validated by the caller loop.
void collect_fields(const EntryRecord& e, std::vector<FieldRef>& out) {
    out.clear();
    auto add = [&](FieldId id, ByteView v) {
        if (v.len > 0) out.push_back({static_cast<uint16_t>(id), v});
    };
    add(FieldId::Name, ByteView(e.name));
    add(FieldId::Remark, ByteView(e.remark));
    add(FieldId::Username, ByteView(e.username));
    add(FieldId::Url, ByteView(e.url));
    add(FieldId::Tags, ByteView(e.tags));
    // pw_bucket always present (1 byte), even when 0/unknown.
    out.push_back({static_cast<uint16_t>(FieldId::PwLenBucket),
                   ByteView(&e.pw_bucket, 1)});
    add(FieldId::Password, e.password.view());
    add(FieldId::TotpSeed, e.totp_seed.view());
    add(FieldId::RecoveryCodes, e.recovery_codes.view());
    add(FieldId::SecretNote, e.secret_note.view());
}

}  // namespace

size_t field_max_len(uint16_t id) noexcept {
    switch (static_cast<FieldId>(id)) {
        case FieldId::Name: return 256;
        case FieldId::Remark: return 1024;
        case FieldId::Username: return 256;
        case FieldId::Url: return 1024;
        case FieldId::Tags: return 512;
        case FieldId::PwLenBucket: return 1;
        case FieldId::Password: return 512;
        case FieldId::TotpSeed: return 128;
        case FieldId::RecoveryCodes: return 4096;
        case FieldId::SecretNote: return 8192;
    }
    return 0;
}

uint8_t password_length_bucket(size_t len) noexcept {
    if (len == 0) return 0;
    if (len <= 8) return 1;
    if (len <= 16) return 2;
    if (len <= 32) return 3;
    if (len <= 64) return 4;
    return 5;
}

Result<SecureBuffer> canonical_encode(const std::vector<EntryRecord>& entries) {
    using R = Result<SecureBuffer>;
    if (entries.size() > CANONICAL_MAX_ENTRIES)
        return R::failure(Err::InvalidArgument);

    // Validate ordering/uniqueness and compute total size.
    std::vector<FieldRef> fields;
    size_t total = 8;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            int cmp = std::memcmp(entries[i - 1].entry_id, entries[i].entry_id,
                                  ENTRY_ID_LEN);
            if (cmp >= 0) return R::failure(Err::InvalidArgument);
        }
        collect_fields(entries[i], fields);
        size_t fbytes = 0;
        for (const FieldRef& f : fields) {
            const size_t maxlen = field_max_len(f.id);
            if (maxlen == 0 || f.data.len > maxlen)
                return R::failure(Err::InvalidArgument);
            fbytes += FIELD_HDR + f.data.len;
        }
        if (fbytes > (1u << 20)) return R::failure(Err::InvalidArgument);
        total += ENTRY_FIXED + fbytes;
    }

    SecureBuffer out = SecureBuffer::alloc(total);
    if (!out.valid()) return R::failure(Err::AllocationFailed);
    uint8_t* p = out.data();
    store_le32(p, CANON_MAGIC);
    store_le32(p + 4, static_cast<uint32_t>(entries.size()));
    p += 8;
    for (const EntryRecord& e : entries) {
        collect_fields(e, fields);
        size_t fbytes = 0;
        for (const FieldRef& f : fields) fbytes += FIELD_HDR + f.data.len;
        std::memcpy(p, e.entry_id, ENTRY_ID_LEN);
        store_le64(p + ENTRY_ID_LEN, e.created_at);
        store_le64(p + ENTRY_ID_LEN + 8, e.updated_at);
        store_le32(p + ENTRY_ID_LEN + 16, static_cast<uint32_t>(fbytes));
        p += ENTRY_FIXED;
        for (const FieldRef& f : fields) {
            store_le16(p, f.id);
            store_le32(p + 2, static_cast<uint32_t>(f.data.len));
            std::memcpy(p + FIELD_HDR, f.data.ptr, f.data.len);
            p += FIELD_HDR + f.data.len;
        }
    }
    if (p != out.data() + total) return R::failure(Err::Internal);
    return R::success(static_cast<SecureBuffer&&>(out));
}

Result<std::vector<EntryRecord>> canonical_decode(ByteView canonical) {
    using R = Result<std::vector<EntryRecord>>;
    const uint8_t* p = canonical.ptr;
    size_t rem = canonical.len;
    if (rem < 8) return R::failure(Err::AuthGeneric);
    if (load_le32(p) != CANON_MAGIC) return R::failure(Err::AuthGeneric);
    const uint32_t count = load_le32(p + 4);
    p += 8;
    rem -= 8;
    if (count > CANONICAL_MAX_ENTRIES) return R::failure(Err::AuthGeneric);
    // Every entry takes at least its fixed part and the length bucket: a
    // count the bytes cannot hold fails here (it would below, entry by
    // entry), before anything is allocated for it.
    constexpr size_t MIN_ENTRY = ENTRY_FIXED + FIELD_HDR + 1;
    if (count > rem / MIN_ENTRY) return R::failure(Err::AuthGeneric);

    std::vector<EntryRecord> entries;
    entries.reserve(count);
    const uint8_t* prev_id = nullptr;
    for (uint32_t i = 0; i < count; ++i) {
        if (rem < ENTRY_FIXED) return R::failure(Err::AuthGeneric);
        EntryRecord e;
        std::memcpy(e.entry_id, p, ENTRY_ID_LEN);
        if (prev_id != nullptr &&
            std::memcmp(prev_id, e.entry_id, ENTRY_ID_LEN) >= 0)
            return R::failure(Err::AuthGeneric);  // order + uniqueness
        e.created_at = load_le64(p + ENTRY_ID_LEN);
        e.updated_at = load_le64(p + ENTRY_ID_LEN + 8);
        const uint32_t fbytes = load_le32(p + ENTRY_ID_LEN + 16);
        p += ENTRY_FIXED;
        rem -= ENTRY_FIXED;
        if (fbytes > rem || fbytes > (1u << 20))
            return R::failure(Err::AuthGeneric);

        size_t frem = fbytes;
        const uint8_t* fp = p;
        uint32_t prev_field = 0;
        bool have_bucket = false;
        while (frem > 0) {
            if (frem < FIELD_HDR) return R::failure(Err::AuthGeneric);
            const uint16_t id = load_le16(fp);
            const uint32_t len = load_le32(fp + 2);
            fp += FIELD_HDR;
            frem -= FIELD_HDR;
            if (len > frem) return R::failure(Err::AuthGeneric);
            const size_t maxlen = field_max_len(id);
            if (maxlen == 0) return R::failure(Err::AuthGeneric);  // unknown
            if (len > maxlen) return R::failure(Err::AuthGeneric);
            if (id <= prev_field) return R::failure(Err::AuthGeneric);
            prev_field = id;
            // pw bucket must be present exactly once; others are optional
            // but never empty (empty field == absent field, canonically).
            if (static_cast<FieldId>(id) != FieldId::PwLenBucket && len == 0)
                return R::failure(Err::AuthGeneric);

            ByteView v(fp, len);
            switch (static_cast<FieldId>(id)) {
                case FieldId::Name:
                    e.name.assign(v.ptr, v.ptr + v.len);
                    break;
                case FieldId::Remark:
                    e.remark.assign(v.ptr, v.ptr + v.len);
                    break;
                case FieldId::Username:
                    e.username.assign(v.ptr, v.ptr + v.len);
                    break;
                case FieldId::Url:
                    e.url.assign(v.ptr, v.ptr + v.len);
                    break;
                case FieldId::Tags:
                    e.tags.assign(v.ptr, v.ptr + v.len);
                    break;
                case FieldId::PwLenBucket:
                    if (len != 1 || v.ptr[0] > 5)
                        return R::failure(Err::AuthGeneric);
                    e.pw_bucket = v.ptr[0];
                    have_bucket = true;
                    break;
                case FieldId::Password:
                case FieldId::TotpSeed:
                case FieldId::RecoveryCodes:
                case FieldId::SecretNote: {
                    SecureBuffer s = SecureBuffer::alloc(v.len);
                    if (!s.valid()) return R::failure(Err::AllocationFailed);
                    std::memcpy(s.data(), v.ptr, v.len);
                    if (static_cast<FieldId>(id) == FieldId::Password)
                        e.password = static_cast<SecureBuffer&&>(s);
                    else if (static_cast<FieldId>(id) == FieldId::TotpSeed)
                        e.totp_seed = static_cast<SecureBuffer&&>(s);
                    else if (static_cast<FieldId>(id) == FieldId::RecoveryCodes)
                        e.recovery_codes = static_cast<SecureBuffer&&>(s);
                    else
                        e.secret_note = static_cast<SecureBuffer&&>(s);
                    break;
                }
            }
            fp += len;
            frem -= len;
        }
        if (!have_bucket) return R::failure(Err::AuthGeneric);
        entries.push_back(static_cast<EntryRecord&&>(e));
        // reserve(count) above guarantees no reallocation: pointer stays valid
        prev_id = entries.back().entry_id;
        p += fbytes;
        rem -= fbytes;
    }
    if (rem != 0) return R::failure(Err::AuthGeneric);  // no trailing bytes
    return R::success(static_cast<std::vector<EntryRecord>&&>(entries));
}

}  // namespace secraxis
