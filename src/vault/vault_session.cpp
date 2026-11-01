#include "secraxis/vault_session.h"

#include <cstring>

#include "secraxis/crypto.h"
#include "secraxis/fs_atomic.h"

namespace secraxis {

namespace {

void wipe_bytes(Bytes& b) noexcept {
    if (!b.empty()) secure_wipe(b.data(), b.size());
    b.clear();
    b.shrink_to_fit();
}

// The vault file at `path` is this vault (same id) under other keys than `h`
// describes: its master password, VMK or KDF was changed since (passwd,
// rekey and upgrade each draw a fresh KDF salt). A file that is gone, is
// not readable or not a vault, or is another vault, is not that.
bool rekeyed_on_disk(const std::string& path, const SeisHeader& h) {
    if (!file_exists(path)) return false;
    uint64_t size = 0;
    Result<Bytes> head = read_file_head(path, SEIS_HEADER_SIZE, &size);
    if (!head.ok()) return false;
    Result<SeisHeader> disk = seis_header_parse(ByteView(head.value), size);
    if (!disk.ok()) return false;
    const SeisHeader& d = disk.value;
    if (std::memcmp(d.vault_id, h.vault_id, VAULT_ID_LEN) != 0) return false;
    return std::memcmp(d.kdf_salt, h.kdf_salt, KDF_SALT_LEN) != 0 ||
           d.kdf_profile_id != h.kdf_profile_id || d.aead_profile_id != h.aead_profile_id;
}

}  // namespace

void VaultSession::wipe_record(EntryRecord& e) noexcept {
    wipe_bytes(e.name);
    wipe_bytes(e.remark);
    wipe_bytes(e.username);
    wipe_bytes(e.url);
    wipe_bytes(e.tags);
    e.pw_bucket = 0;
    e.password.reset();
    e.totp_seed.reset();
    e.recovery_codes.reset();
    e.secret_note.reset();
    secure_wipe(e.entry_id, ENTRY_ID_LEN);
}

Status VaultSession::seal_from_canonical(ByteView canonical) {
    Result<std::vector<EntryRecord>> dec = canonical_decode(canonical);
    if (!dec.ok()) return status_fail(dec.err);
    Result<RuntimeStore> rs = RuntimeStore::create(vault_.prk, vault_.header);
    if (!rs.ok()) return status_fail(rs.err);
    store_ = static_cast<RuntimeStore&&>(rs.value);
    for (EntryRecord& e : dec.value) {
        Result<size_t> idx = store_.seal_entry(e);
        wipe_record(e);  // plaintext scratch dies as soon as it is sealed
        if (!idx.ok()) return status_fail(idx.err);
    }
    return status_ok();
}

Result<VaultSession> VaultSession::create_new(const CreateParams& p,
                                              ByteView master_password) {
    using R = Result<VaultSession>;
    // Empty canonical vault.
    Result<SecureBuffer> canon = canonical_encode({});
    if (!canon.ok()) return R::failure(canon.err);

    VaultSession s;
    Status st = seis_create(p, master_password, canon.value.view(), &s.vault_);
    if (!st.ok()) return R::failure(st.err);
    s.path_ = p.path;
    Status ss = s.seal_from_canonical(canon.value.view());
    if (!ss.ok()) return R::failure(ss.err);
    s.open_ = true;
    s.dirty_ = false;  // file on disk matches the (empty) live model
    return R::success(static_cast<VaultSession&&>(s));
}

Result<VaultSession> VaultSession::unlock(const std::string& path,
                                          ByteView master_password,
                                          const std::atomic<bool>* cancel) {
    using R = Result<VaultSession>;
    // Opening seals every entry under fresh random keys and nonces. Without
    // RDSEED it is refused here, before the file is read or the password
    // tried, so the refusal says nothing about the password.
    if (entropy_state() != EntropyState::Ready) return R::failure(Err::RngFailed);
    Result<Bytes> file = read_file(path);
    if (!file.ok()) return R::failure(file.err);
    if (cancel != nullptr && cancel->load()) return R::failure(Err::Canceled);
    Result<UnlockedVault> v = seis_unlock_bytes(ByteView(file.value), master_password);
    if (!v.ok()) return R::failure(v.err);
    VaultSession s;
    s.vault_ = static_cast<UnlockedVault&&>(v.value);
    s.path_ = path;
    Status ss = s.seal_from_canonical(s.vault_.canonical.view());
    // Canonical plaintext is wiped the moment entries are sealed (§12.1).
    s.vault_.canonical.reset();
    if (!ss.ok()) return R::failure(ss.err);
    s.open_ = true;
    s.dirty_ = false;
    return R::success(static_cast<VaultSession&&>(s));
}

Result<size_t> VaultSession::add_entry(EntryRecord&& e, uint64_t now) {
    using R = Result<size_t>;
    if (!open_) return R::failure(Err::InvalidArgument);

    // Field caps enforced here so the failure is immediate, not at save.
    if (e.name.size() > field_max_len((uint16_t)FieldId::Name) ||
        e.remark.size() > field_max_len((uint16_t)FieldId::Remark) ||
        e.username.size() > field_max_len((uint16_t)FieldId::Username) ||
        e.url.size() > field_max_len((uint16_t)FieldId::Url) ||
        e.tags.size() > field_max_len((uint16_t)FieldId::Tags) ||
        e.password.size() > field_max_len((uint16_t)FieldId::Password) ||
        e.totp_seed.size() > field_max_len((uint16_t)FieldId::TotpSeed) ||
        e.recovery_codes.size() >
            field_max_len((uint16_t)FieldId::RecoveryCodes) ||
        e.secret_note.size() > field_max_len((uint16_t)FieldId::SecretNote)) {
        wipe_record(e);
        return R::failure(Err::InvalidArgument);
    }

    // Fresh unique id; identity is never caller-controlled.
    for (;;) {
        if (!random_bytes(e.entry_id, ENTRY_ID_LEN)) {
            wipe_record(e);
            return R::failure(Err::RngFailed);
        }
        bool clash = false;
        for (size_t i = 0; i < store_.size() && !clash; ++i) {
            Result<RuntimeStore::Handle> h = store_.handle(i);
            if (h.ok() && std::memcmp(h.value.entry_id, e.entry_id,
                                      ENTRY_ID_LEN) == 0)
                clash = true;
        }
        if (!clash) break;
    }
    e.created_at = now;
    e.updated_at = now;
    // Bucket is COMPUTED; exact length never stored (agenda §9.2).
    e.pw_bucket = password_length_bucket(e.password.size());

    Result<size_t> idx = store_.seal_entry(e);
    wipe_record(e);  // consume-and-wipe contract
    if (!idx.ok()) return idx;
    dirty_ = true;
    return idx;
}

Status VaultSession::modify_entry(size_t index, EntryRecord&& e,
                                  uint64_t now) {
    if (!open_) {
        wipe_record(e);
        return status_fail(Err::InvalidArgument);
    }
    Result<RuntimeStore::Handle> h = store_.handle(index);
    if (!h.ok()) {
        wipe_record(e);
        return status_fail(Err::NotFound);
    }
    // Identity and history are preserved from the existing entry.
    std::memcpy(e.entry_id, h.value.entry_id, ENTRY_ID_LEN);
    e.created_at = h.value.created_at;
    e.updated_at = now;
    e.pw_bucket = password_length_bucket(e.password.size());

    Status st = store_.replace_entry(index, e);
    wipe_record(e);
    if (!st.ok()) return st;
    dirty_ = true;
    return status_ok();
}

Status VaultSession::delete_entry(size_t index, bool confirmed) {
    if (!open_) return status_fail(Err::InvalidArgument);
    // Confirmation enforced at the API (ENTRY_LIFECYCLE.md §3.1): without it
    // NOTHING changes.
    if (!confirmed) return status_fail(Err::Canceled);
    Status st = store_.remove_entry(index);
    if (!st.ok()) return st;
    dirty_ = true;
    return status_ok();
}

Result<RuntimeStore::Handle> VaultSession::handle(size_t index) const {
    if (!open_) return Result<RuntimeStore::Handle>::failure(Err::InvalidArgument);
    return store_.handle(index);
}

Result<EntryRecord> VaultSession::view_metadata(size_t index) const {
    if (!open_) return Result<EntryRecord>::failure(Err::InvalidArgument);
    return store_.open_metadata(index);
}

Result<EntryRecord> VaultSession::open_entry_secrets(size_t index) {
    using R = Result<EntryRecord>;
    if (!open_) return R::failure(Err::InvalidArgument);
    Result<EntryRecord> r = store_.open_full(index);
    if (!r.ok()) return r;
    // Access-count reseal trigger (ENTRY_LIFECYCLE.md §5).
    Result<RuntimeStore::Handle> h = store_.handle(index);
    if (h.ok() && h.value.access_count % ACCESS_RESEAL_THRESHOLD == 0) {
        Status st = store_.reseal(index);
        if (!st.ok()) return R::failure(st.err);
    }
    return r;
}

Result<std::vector<size_t>> VaultSession::query(ByteView needle) const {
    if (!open_)
        return Result<std::vector<size_t>>::failure(Err::InvalidArgument);
    return store_.query(needle);
}

Result<std::vector<size_t>> VaultSession::query_within(ByteView needle,
                                                       const std::vector<size_t>& within) const {
    if (!open_)
        return Result<std::vector<size_t>>::failure(Err::InvalidArgument);
    return store_.query_within(needle, within);
}

Status VaultSession::note_secret_exposure(size_t index) {
    if (!open_) return status_fail(Err::InvalidArgument);
    return store_.reseal(index);
}

Status VaultSession::reseal_all() {
    if (!open_) return status_fail(Err::InvalidArgument);
    return store_.reseal_all();
}

Result<SecureBuffer> VaultSession::export_canonical() const {
    if (!open_) return Result<SecureBuffer>::failure(Err::InvalidArgument);
    return store_.to_canonical();
}

Status VaultSession::save(uint64_t now) { return save_to(path_, SaveTarget::Same, now); }

Status VaultSession::save_overwrite(uint64_t now) {
    return save_to(path_, SaveTarget::Overwrite, now);
}

Status VaultSession::save_copy(const std::string& new_path, uint64_t now) {
    Status st = save_to(new_path, SaveTarget::NewFile, now);
    if (st.ok()) path_ = new_path;
    return st;
}

Status VaultSession::save_to(const std::string& path, SaveTarget target, uint64_t now) {
    if (!open_) return status_fail(Err::InvalidArgument);
    // Whatever the target (in place, over it, a copy beside it), never write
    // this session's keys while its vault file holds new ones: its password
    // was changed elsewhere, perhaps because the old one leaked.
    if (rekeyed_on_disk(path_, vault_.header)) return status_fail(Err::VaultRekeyed);
    Result<SecureBuffer> canon = store_.to_canonical();
    if (!canon.ok()) return status_fail(canon.err);
    Status st = seis_save(path, vault_, canon.value.view(), now, ByteView(), target);
    canon.value.reset();  // wipe canonical scratch regardless of outcome
    if (!st.ok()) return st;  // on failure: disk untouched, still dirty
    dirty_ = false;
    // Post-save reseal (moving-target trigger "after save").
    return store_.reseal_all();
}

void VaultSession::lock() noexcept {
    // Ordered destruction: sealed store, then PRK, then VMK.
    store_ = RuntimeStore();
    vault_.prk.reset();
    vault_.vmk.reset();
    vault_.canonical.reset();
    vault_.vmk_envelope.clear();
    open_ = false;
    dirty_ = false;
}

}  // namespace secraxis
