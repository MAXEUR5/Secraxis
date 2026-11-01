// vault_session.h — the entry-mutation lifecycle owner (docs/ENTRY_LIFECYCLE.md).
//
// The ONLY layer the TUI may call for CRUD. Enforces, in code:
//   * confirmation-gated deletion (ERR_CANCELED without confirmed=true)
//   * dirty-state tracking (mutations never touch disk; only save() does)
//   * computed pw buckets (exact password length never stored)
//   * identity/history preservation on edit (entry_id, created_at)
//   * consume-and-wipe mutation inputs
//   * moving-target reseal triggers (access count, exposure, edit, save)
//   * lock() = ordered destruction of store, PRK, VMK
#ifndef SECRAXIS_VAULT_SESSION_H
#define SECRAXIS_VAULT_SESSION_H

#include <string>
#include <vector>

#include "secraxis/canonical_codec.h"
#include "secraxis/common.h"
#include "secraxis/runtime_store.h"
#include "secraxis/seis_container.h"

namespace secraxis {

// Reseal an entry after this many secret opens (docs/ENTRY_LIFECYCLE.md §5).
constexpr uint32_t ACCESS_RESEAL_THRESHOLD = 4;

class VaultSession final {
  public:
    VaultSession() = default;
    VaultSession(VaultSession&&) = default;
    VaultSession& operator=(VaultSession&&) = default;
    VaultSession(const VaultSession&) = delete;
    VaultSession& operator=(const VaultSession&) = delete;
    ~VaultSession() { lock(); }

    // Create a new vault file (empty) and open a live session on it.
    static Result<VaultSession> create_new(const CreateParams& p,
                                           ByteView master_password);
    // Unlock an existing vault into a live session. `cancel` (not owned),
    // when set by another thread while the file is being read (a stalled
    // network drive), skips the KDF: Err::Canceled.
    static Result<VaultSession> unlock(const std::string& path,
                                       ByteView master_password,
                                       const std::atomic<bool>* cancel = nullptr);

    bool is_open() const noexcept { return open_; }
    bool dirty() const noexcept { return dirty_; }
    size_t entry_count() const noexcept { return store_.size(); }
    const SeisHeader& header() const noexcept { return vault_.header; }
    const std::string& path() const noexcept { return path_; }

    // ---- CRUD (see ENTRY_LIFECYCLE.md for the normative contract) ----
    // Consumes and wipes `e`. Returns the new entry's index.
    Result<size_t> add_entry(EntryRecord&& e, uint64_t now);
    // Consumes and wipes `e`; preserves entry_id/created_at of the target.
    Status modify_entry(size_t index, EntryRecord&& e, uint64_t now);
    // Refuses (ERR_CANCELED, no changes) unless confirmed.
    Status delete_entry(size_t index, bool confirmed);

    // ---- read paths ----
    Result<RuntimeStore::Handle> handle(size_t index) const;
    Result<EntryRecord> view_metadata(size_t index) const;
    // Opens secrets (entry-scoped); auto-reseals every
    // ACCESS_RESEAL_THRESHOLD opens.
    Result<EntryRecord> open_entry_secrets(size_t index);
    // Metadata-only search; never decrypts secret segments.
    Result<std::vector<size_t>> query(ByteView needle) const;
    Result<std::vector<size_t>> query_within(ByteView needle,
                                             const std::vector<size_t>& within) const;

    // ---- reseal triggers ----
    Status note_secret_exposure(size_t index);  // after reveal/copy
    Status reseal_all();                        // manual refresh / timer

    // ---- persistence ----
    // Atomic; clears dirty; reseals all. Err::VaultChanged: another window
    // or program saved the file since this session opened or last saved it
    // (nothing written, still dirty); the caller then lets the user choose:
    Status save(uint64_t now);
    Status save_overwrite(uint64_t now);  // replace what they saved
    // Save to `new_path` (must not exist: Err::Exists) and continue there.
    Status save_copy(const std::string& new_path, uint64_t now);

    // Reassemble the canonical plaintext (secure memory) for export flows.
    // Caller wipes. Opening secrets counts as exposure; caller should be an
    // explicit, consented export path.
    Result<SecureBuffer> export_canonical() const;

    // Wipe and drop all secret state; session becomes inert.
    void lock() noexcept;

  private:
    bool open_ = false;
    bool dirty_ = false;
    std::string path_;
    UnlockedVault vault_;   // header, envelope, vmk, prk (canonical unused)
    RuntimeStore store_;

    Status seal_from_canonical(ByteView canonical);
    Status save_to(const std::string& path, SaveTarget target, uint64_t now);
    static void wipe_record(EntryRecord& e) noexcept;
};

}  // namespace secraxis

#endif  // SECRAXIS_VAULT_SESSION_H
