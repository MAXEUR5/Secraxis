#include "secraxis/runtime_store.h"

#include <algorithm>
#include <cstddef>
#include <cstring>

#include "secraxis/aead.h"
#include "secraxis/crypto.h"
#include "secraxis/key_hierarchy.h"

namespace secraxis {

namespace {

// Runtime sealing always uses the always-available portable AEAD.
const AeadProfile& runtime_aead() { return AEAD_XCHACHA; }

// Mini-TLV for a segment: (u16 id | u32 len | bytes)*, ascending ids.
// Metadata segment carries ids < 32; secret segment ids >= 32.
void put_field(Bytes& out, uint16_t id, ByteView v) {
    uint8_t hdr[6];
    store_le16(hdr, id);
    store_le32(hdr + 2, static_cast<uint32_t>(v.len));
    out.insert(out.end(), hdr, hdr + 6);
    out.insert(out.end(), v.ptr, v.ptr + v.len);
}

// Secret-segment variant writing into a sized SecureBuffer cursor.
size_t put_field_secure(uint8_t* p, uint16_t id, ByteView v) {
    store_le16(p, id);
    store_le32(p + 2, static_cast<uint32_t>(v.len));
    if (v.len > 0) std::memcpy(p + 6, v.ptr, v.len);
    return 6 + v.len;
}

struct ParsedField {
    uint16_t id;
    ByteView data;
};

bool parse_fields(ByteView seg, std::vector<ParsedField>& out) {
    out.clear();
    const uint8_t* p = seg.ptr;
    size_t rem = seg.len;
    uint32_t prev = 0;
    while (rem > 0) {
        if (rem < 6) return false;
        uint16_t id = load_le16(p);
        uint32_t len = load_le32(p + 2);
        p += 6;
        rem -= 6;
        if (len > rem) return false;
        if (id <= prev) return false;
        const size_t maxlen = field_max_len(id);
        if (maxlen == 0 || len > maxlen) return false;
        prev = id;
        out.push_back({id, ByteView(p, len)});
        p += len;
        rem -= len;
    }
    return true;
}

Bytes segment_aad(const SeisHeader& h, const uint8_t* entry_id,
                  uint64_t reseal_epoch, const char* which) {
    Bytes aad;
    append_lp(aad, label("seis-runtime-seg-v1"));
    append_lp(aad, label(which));
    append_lp(aad, ByteView(h.vault_id, VAULT_ID_LEN));
    append_lp(aad, ByteView(entry_id, ENTRY_ID_LEN));
    append_le64(aad, reseal_epoch);
    return aad;
}

}  // namespace

Result<RuntimeStore> RuntimeStore::create(const SecureBuffer& vmk_prk,
                                          const SeisHeader& header) {
    using R = Result<RuntimeStore>;
    RuntimeStore rs;
    rs.header_ = header;
    // Fresh process/session nonce: runtime keys differ across unlock
    // sessions even for the same vault + epoch.
    uint8_t process_nonce[32];
    if (!random_bytes(process_nonce, sizeof(process_nonce))) return R::failure(Err::RngFailed);
    SecureBuffer root =
        derive_subkey(vmk_prk, LBL_RUNTIME_ROOT, header, 0, 64,
                      ByteView(process_nonce, sizeof(process_nonce)));
    if (!root.valid()) return R::failure(Err::AllocationFailed);
    // Extract a PRK from the runtime root for the per-entry expansions; its
    // salt carries the verse's second line (in memory only, never in a file).
    Bytes salt;
    append_lp(salt, label(LBL_RUNTIME_PRK));
    append_lp(salt, label(VERSE_RUNTIME_KEYS));
    rs.runtime_prk_ = SecureBuffer::alloc(HKDF_PRK_LEN);
    if (!rs.runtime_prk_.valid()) return R::failure(Err::AllocationFailed);
    if (!hkdf_extract(rs.runtime_prk_.data(), ByteView(salt), root.view()).ok())
        return R::failure(Err::Internal);
    return R::success(static_cast<RuntimeStore&&>(rs));
}

Status RuntimeStore::seal_segments(Slot& s, const EntryRecord& e) const {
    const AeadProfile& ap = runtime_aead();

    // --- metadata segment (non-secret contents, sealed anyway) ---
    Bytes meta;
    if (!e.name.empty()) put_field(meta, (uint16_t)FieldId::Name, ByteView(e.name));
    if (!e.remark.empty()) put_field(meta, (uint16_t)FieldId::Remark, ByteView(e.remark));
    if (!e.username.empty()) put_field(meta, (uint16_t)FieldId::Username, ByteView(e.username));
    if (!e.url.empty()) put_field(meta, (uint16_t)FieldId::Url, ByteView(e.url));
    if (!e.tags.empty()) put_field(meta, (uint16_t)FieldId::Tags, ByteView(e.tags));
    put_field(meta, (uint16_t)FieldId::PwLenBucket, ByteView(&e.pw_bucket, 1));
    if (e.color != 0) put_field(meta, (uint16_t)FieldId::EntryColor, ByteView(&e.color, 1));

    // --- secret segment (built inside secure memory) ---
    size_t sec_len = 0;
    auto add_len = [&](const SecureBuffer& b) {
        if (b.size() > 0) sec_len += 6 + b.size();
    };
    add_len(e.password);
    add_len(e.totp_seed);
    add_len(e.recovery_codes);
    add_len(e.secret_note);
    SecureBuffer secret = SecureBuffer::alloc(sec_len > 0 ? sec_len : 1);
    if (!secret.valid()) return status_fail(Err::AllocationFailed);
    {
        uint8_t* p = secret.data();
        if (e.password.size() > 0)
            p += put_field_secure(p, (uint16_t)FieldId::Password, e.password.view());
        if (e.totp_seed.size() > 0)
            p += put_field_secure(p, (uint16_t)FieldId::TotpSeed, e.totp_seed.view());
        if (e.recovery_codes.size() > 0)
            p += put_field_secure(p, (uint16_t)FieldId::RecoveryCodes,
                                  e.recovery_codes.view());
        if (e.secret_note.size() > 0)
            p += put_field_secure(p, (uint16_t)FieldId::SecretNote,
                                  e.secret_note.view());
    }

    // --- seal both under this slot's reseal_epoch ---
    Bytes id_extra(s.entry_id, s.entry_id + ENTRY_ID_LEN);
    SecureBuffer mkey =
        derive_subkey(runtime_prk_, LBL_ENTRY_META, header_, s.reseal_epoch,
                      AEAD_KEY_LEN, ByteView(id_extra));
    SecureBuffer skey =
        derive_subkey(runtime_prk_, LBL_ENTRY_SECRET, header_, s.reseal_epoch,
                      AEAD_KEY_LEN, ByteView(id_extra));
    if (!mkey.valid() || !skey.valid())
        return status_fail(Err::AllocationFailed);

    auto seal_one = [&](ByteView plain, const SecureBuffer& key,
                        const char* which, SecureBuffer& out) -> Status {
        SecureBuffer sealed =
            SecureBuffer::alloc(ap.nonce_len + plain.len + ap.tag_len);
        if (!sealed.valid()) return status_fail(Err::AllocationFailed);
        if (!random_bytes(sealed.data(), ap.nonce_len)) return status_fail(Err::RngFailed);
        Bytes aad = segment_aad(header_, s.entry_id, s.reseal_epoch, which);
        Status st = aead_seal(ap, sealed.data() + ap.nonce_len, plain,
                              ByteView(aad), sealed.data(), key.data());
        if (!st.ok()) return st;
        out = static_cast<SecureBuffer&&>(sealed);
        return status_ok();
    };
    Status st = seal_one(ByteView(meta), mkey, "meta", s.sealed_meta);
    secure_wipe(meta.data(), meta.size());
    if (!st.ok()) return st;
    st = seal_one(ByteView(secret.data(), sec_len), skey, "secret",
                  s.sealed_secret);
    if (!st.ok()) return st;
    return status_ok();
}

Result<size_t> RuntimeStore::seal_entry(const EntryRecord& e) {
    using R = Result<size_t>;
    Slot s;
    std::memcpy(s.entry_id, e.entry_id, ENTRY_ID_LEN);
    s.created_at = e.created_at;
    s.updated_at = e.updated_at;
    s.reseal_epoch = 1;
    Status st = seal_segments(s, e);
    if (!st.ok()) return R::failure(st.err);
    slots_.push_back(static_cast<Slot&&>(s));
    return R::success(slots_.size() - 1);
}

Result<RuntimeStore::Handle> RuntimeStore::handle(size_t index) const {
    using R = Result<Handle>;
    if (index >= slots_.size()) return R::failure(Err::NotFound);
    const Slot& s = slots_[index];
    Handle h{};
    std::memcpy(h.entry_id, s.entry_id, ENTRY_ID_LEN);
    h.created_at = s.created_at;
    h.updated_at = s.updated_at;
    h.access_count = s.access_count;
    h.reseal_epoch = s.reseal_epoch;
    return R::success(static_cast<Handle&&>(h));
}

namespace {

// Key and plaintext buffers for opening many segments in a row (a search):
// secure memory like any other, wiped after every segment, but allocated once
// instead of twice per entry (each guard-paged allocation costs system calls).
struct OpenScratch {
    SecureBuffer key;
    SecureBuffer plain;
};

// Wipes [p, p+n) when it goes out of scope (scratch is reused, not freed).
struct WipeOnExit {
    uint8_t* p;
    size_t n;
    ~WipeOnExit() {
        if (p != nullptr) secure_wipe(p, n);
    }
};

// Shared open helper: decrypts one segment and dispatches fields into e.
// With `scratch`, its buffers stand in for fresh ones.
Status open_segment(const SeisHeader& header, const SecureBuffer& prk,
                    const RuntimeStore* /*unused*/, const uint8_t* entry_id,
                    uint64_t reseal_epoch, const SecureBuffer& sealed,
                    const char* which, const char* key_label, EntryRecord& e,
                    OpenScratch* scratch = nullptr) {
    const AeadProfile& ap = runtime_aead();
    if (sealed.size() < ap.nonce_len + ap.tag_len)
        return status_fail(Err::Internal);
    const size_t plain_len = sealed.size() - ap.nonce_len - ap.tag_len;
    SecureBuffer own_key, own_plain;
    SecureBuffer& key = scratch != nullptr ? scratch->key : own_key;
    SecureBuffer& plain = scratch != nullptr ? scratch->plain : own_plain;
    if (key.size() < AEAD_KEY_LEN) key = SecureBuffer::alloc(AEAD_KEY_LEN);
    if (plain.size() < (plain_len > 0 ? plain_len : 1))
        plain = SecureBuffer::alloc(plain_len > 256 ? plain_len : 256);
    if (!key.valid() || !plain.valid()) return status_fail(Err::AllocationFailed);
    WipeOnExit wipe_key{key.data(), AEAD_KEY_LEN};
    WipeOnExit wipe_plain{plain.data(), plain_len};
    Bytes id_extra(entry_id, entry_id + ENTRY_ID_LEN);
    if (!derive_subkey_into(key.data(), AEAD_KEY_LEN, prk, key_label, header, reseal_epoch,
                            ByteView(id_extra)))
        return status_fail(Err::AllocationFailed);
    Bytes aad = segment_aad(header, entry_id, reseal_epoch, which);
    Status st = aead_open(
        ap, plain.data(),
        ByteView(sealed.data() + ap.nonce_len, sealed.size() - ap.nonce_len),
        ByteView(aad), sealed.data(), key.data());
    if (!st.ok()) return status_fail(Err::Internal);  // runtime corruption

    std::vector<ParsedField> fields;
    if (!parse_fields(ByteView(plain.data(), plain_len), fields))
        return status_fail(Err::Internal);
    for (const ParsedField& f : fields) {
        switch (static_cast<FieldId>(f.id)) {
            case FieldId::Name: e.name.assign(f.data.ptr, f.data.ptr + f.data.len); break;
            case FieldId::Remark: e.remark.assign(f.data.ptr, f.data.ptr + f.data.len); break;
            case FieldId::Username: e.username.assign(f.data.ptr, f.data.ptr + f.data.len); break;
            case FieldId::Url: e.url.assign(f.data.ptr, f.data.ptr + f.data.len); break;
            case FieldId::Tags: e.tags.assign(f.data.ptr, f.data.ptr + f.data.len); break;
            case FieldId::PwLenBucket:
                if (f.data.len == 1) e.pw_bucket = f.data.ptr[0];
                break;
            case FieldId::EntryColor:
                if (f.data.len == 1) e.color = f.data.ptr[0];
                break;
            case FieldId::Password:
            case FieldId::TotpSeed:
            case FieldId::RecoveryCodes:
            case FieldId::SecretNote: {
                SecureBuffer s2 = SecureBuffer::alloc(f.data.len);
                if (!s2.valid()) return status_fail(Err::AllocationFailed);
                std::memcpy(s2.data(), f.data.ptr, f.data.len);
                if (static_cast<FieldId>(f.id) == FieldId::Password)
                    e.password = static_cast<SecureBuffer&&>(s2);
                else if (static_cast<FieldId>(f.id) == FieldId::TotpSeed)
                    e.totp_seed = static_cast<SecureBuffer&&>(s2);
                else if (static_cast<FieldId>(f.id) == FieldId::RecoveryCodes)
                    e.recovery_codes = static_cast<SecureBuffer&&>(s2);
                else
                    e.secret_note = static_cast<SecureBuffer&&>(s2);
                break;
            }
        }
    }
    return status_ok();
}

}  // namespace

Result<EntryRecord> RuntimeStore::open_metadata(size_t index) const {
    using R = Result<EntryRecord>;
    if (index >= slots_.size()) return R::failure(Err::NotFound);
    const Slot& s = slots_[index];
    EntryRecord e;
    std::memcpy(e.entry_id, s.entry_id, ENTRY_ID_LEN);
    e.created_at = s.created_at;
    e.updated_at = s.updated_at;
    Status st = open_segment(header_, runtime_prk_, this, s.entry_id,
                             s.reseal_epoch, s.sealed_meta, "meta",
                             LBL_ENTRY_META, e);
    if (!st.ok()) return R::failure(st.err);
    return R::success(static_cast<EntryRecord&&>(e));
}

Result<EntryRecord> RuntimeStore::open_full(size_t index) {
    using R = Result<EntryRecord>;
    if (index >= slots_.size()) return R::failure(Err::NotFound);
    Slot& s = slots_[index];
    Result<EntryRecord> r = open_metadata(index);
    if (!r.ok()) return r;
    Status st = open_segment(header_, runtime_prk_, this, s.entry_id,
                             s.reseal_epoch, s.sealed_secret, "secret",
                             LBL_ENTRY_SECRET, r.value);
    if (!st.ok()) return R::failure(st.err);
    s.access_count += 1;
    return r;
}

Status RuntimeStore::replace_entry(size_t index, const EntryRecord& e) {
    if (index >= slots_.size()) return status_fail(Err::NotFound);
    Slot& s = slots_[index];
    // Sealed under fresh keys into fresh regions. The old ones are wiped only
    // once the new ones exist: a seal that fails (no secure memory, no random
    // numbers) leaves the entry as it was.
    Slot fresh;
    std::memcpy(fresh.entry_id, e.entry_id, ENTRY_ID_LEN);
    fresh.reseal_epoch = s.reseal_epoch + 1;
    Status st = seal_segments(fresh, e);
    if (!st.ok()) return st;
    std::memcpy(s.entry_id, e.entry_id, ENTRY_ID_LEN);
    s.created_at = e.created_at;
    s.updated_at = e.updated_at;
    s.reseal_epoch = fresh.reseal_epoch;
    s.sealed_meta = static_cast<SecureBuffer&&>(fresh.sealed_meta);  // wipes the old
    s.sealed_secret = static_cast<SecureBuffer&&>(fresh.sealed_secret);
    return status_ok();
}

Status RuntimeStore::remove_entry(size_t index) {
    if (index >= slots_.size()) return status_fail(Err::NotFound);
    slots_[index].sealed_meta.reset();
    slots_[index].sealed_secret.reset();
    slots_.erase(slots_.begin() + static_cast<ptrdiff_t>(index));
    return status_ok();
}

Status RuntimeStore::reseal(size_t index) {
    if (index >= slots_.size()) return status_fail(Err::NotFound);
    Slot& s = slots_[index];
    // Open under current epoch...
    EntryRecord e;
    std::memcpy(e.entry_id, s.entry_id, ENTRY_ID_LEN);
    e.created_at = s.created_at;
    e.updated_at = s.updated_at;
    Status st = open_segment(header_, runtime_prk_, this, s.entry_id,
                             s.reseal_epoch, s.sealed_meta, "meta",
                             LBL_ENTRY_META, e);
    if (!st.ok()) return st;
    st = open_segment(header_, runtime_prk_, this, s.entry_id, s.reseal_epoch,
                      s.sealed_secret, "secret", LBL_ENTRY_SECRET, e);
    if (!st.ok()) return st;
    // ...reseal under epoch+1 into fresh regions; the old ones are wiped only
    // once the new ones exist, so a failed reseal leaves the entry as it was.
    Slot fresh;
    std::memcpy(fresh.entry_id, s.entry_id, ENTRY_ID_LEN);
    fresh.reseal_epoch = s.reseal_epoch + 1;
    st = seal_segments(fresh, e);
    if (!st.ok()) return st;
    s.reseal_epoch = fresh.reseal_epoch;
    s.sealed_meta = static_cast<SecureBuffer&&>(fresh.sealed_meta);  // wipes the old
    s.sealed_secret = static_cast<SecureBuffer&&>(fresh.sealed_secret);
    return status_ok();
}

Status RuntimeStore::reseal_all() {
    for (size_t i = 0; i < slots_.size(); ++i) {
        Status st = reseal(i);
        if (!st.ok()) return st;
    }
    return status_ok();
}

namespace {

bool ci_contains(const Bytes& hay, ByteView needle) {
    if (needle.len == 0 || needle.len > hay.size()) return false;
    auto lower = [](uint8_t c) -> uint8_t {
        return (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c + 32) : c;
    };
    for (size_t i = 0; i + needle.len <= hay.size(); ++i) {
        size_t j = 0;
        while (j < needle.len && lower(hay[i + j]) == lower(needle.ptr[j])) ++j;
        if (j == needle.len) return true;
    }
    return false;
}

}  // namespace

Result<std::vector<size_t>> RuntimeStore::query(ByteView needle) const {
    std::vector<size_t> all(slots_.size());
    for (size_t i = 0; i < all.size(); ++i) all[i] = i;
    return query_within(needle, all);
}

Result<std::vector<size_t>> RuntimeStore::query_within(ByteView needle,
                                                       const std::vector<size_t>& within) const {
    using R = Result<std::vector<size_t>>;
    std::vector<size_t> hits;
    if (needle.len == 0 || needle.len > 256) return R::success({});
    OpenScratch scratch;  // one key and one plaintext buffer for the whole search
    for (const size_t i : within) {
        if (i >= slots_.size()) return R::failure(Err::NotFound);
        const Slot& s = slots_[i];
        EntryRecord e;  // metadata only: secrets never decrypted
        Status st = open_segment(header_, runtime_prk_, this, s.entry_id, s.reseal_epoch,
                                 s.sealed_meta, "meta", LBL_ENTRY_META, e, &scratch);
        if (!st.ok()) return R::failure(st.err);
        if (ci_contains(e.name, needle) || ci_contains(e.remark, needle) ||
            ci_contains(e.username, needle) || ci_contains(e.url, needle) ||
            ci_contains(e.tags, needle)) {
            hits.push_back(i);
        }
        // e goes out of scope with its metadata copies; the scratch was
        // wiped after the segment; secret fields were never populated.
    }
    return R::success(static_cast<std::vector<size_t>&&>(hits));
}

Result<SecureBuffer> RuntimeStore::to_canonical() const {
    using R = Result<SecureBuffer>;
    std::vector<EntryRecord> entries;
    entries.reserve(slots_.size());
    for (size_t i = 0; i < slots_.size(); ++i) {
        Result<EntryRecord> e = open_metadata(i);
        if (!e.ok()) return R::failure(e.err);
        Status st = open_segment(header_, runtime_prk_, this,
                                 slots_[i].entry_id, slots_[i].reseal_epoch,
                                 slots_[i].sealed_secret, "secret",
                                 LBL_ENTRY_SECRET, e.value);
        if (!st.ok()) return R::failure(st.err);
        entries.push_back(static_cast<EntryRecord&&>(e.value));
    }
    // Canonical order: ascending entry_id (insertion order is not trusted).
    std::sort(entries.begin(), entries.end(),
              [](const EntryRecord& a, const EntryRecord& b) {
                  return std::memcmp(a.entry_id, b.entry_id, ENTRY_ID_LEN) < 0;
              });
    return canonical_encode(entries);
}

uint32_t RuntimeStore::entry_count_bucket() const noexcept {
    const size_t n = slots_.size();
    if (n == 0) return 0;
    uint32_t b = 1;
    size_t cap = 8;
    while (cap < n && b < 16) {
        cap *= 2;
        ++b;
    }
    return b;
}

}  // namespace secraxis
