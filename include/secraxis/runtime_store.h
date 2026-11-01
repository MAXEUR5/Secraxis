// runtime_store.h — runtime encrypted entry storage + moving-target sealing
// (agenda §12). After unlock, entries live ONLY as per-entry AEAD-sealed
// segments; the full canonical plaintext buffer is parsed, sealed, and wiped.
//
// Keys: runtime_root = HKDF(VMK-PRK, "seis-runtime-root-v1", header,
// extra=process_nonce). Per entry and per reseal-epoch:
//   meta_key_i   = HKDF(runtime_root_prk, "seis-entry-metadata-v1",
//                       entry_id, reseal_epoch)
//   secret_key_i = HKDF(runtime_root_prk, "seis-entry-secret-v1",
//                       entry_id, reseal_epoch)
// Sealing AEAD is always XChaCha20-Poly1305 (in-memory only, profile-
// independent, always compiled in), random 24-byte nonce per seal.
//
// Moving-target resealing re-encrypts a segment under reseal_epoch+1 into a
// freshly allocated region and wipes the old one (agenda §12.4). It reduces
// stable-address exposure and secret density; it does NOT defeat a malicious
// kernel or in-process code — documented honestly in RUNTIME_MEMORY_SECURITY.
//
// Metadata and secret payloads are sealed SEPARATELY: overview/query decrypt
// only metadata segments; secret segments are opened only for entry-scoped
// actions (reveal/copy/edit/save).
#ifndef SECRAXIS_RUNTIME_STORE_H
#define SECRAXIS_RUNTIME_STORE_H

#include <vector>

#include "secraxis/canonical_codec.h"
#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"
#include "secraxis/seis_format.h"

namespace secraxis {

class RuntimeStore final {
  public:
    RuntimeStore() = default;
    RuntimeStore(RuntimeStore&&) = default;
    RuntimeStore& operator=(RuntimeStore&&) = default;
    RuntimeStore(const RuntimeStore&) = delete;
    RuntimeStore& operator=(const RuntimeStore&) = delete;

    // Derive the runtime root from the unlocked hierarchy (fresh process
    // nonce per unlock session).
    static Result<RuntimeStore> create(const SecureBuffer& vmk_prk,
                                       const SeisHeader& header);

    // Seal one entry (consumes/wipes nothing from the caller's record —
    // caller wipes its own copies). Returns the entry index.
    Result<size_t> seal_entry(const EntryRecord& e);

    size_t size() const noexcept { return slots_.size(); }

    // Non-secret handle data for listings.
    struct Handle {
        uint8_t entry_id[ENTRY_ID_LEN];
        uint64_t created_at;
        uint64_t updated_at;
        uint32_t access_count;   // secret-open count since unlock
        uint64_t reseal_epoch;
    };
    Result<Handle> handle(size_t index) const;

    // Decrypt ONLY the metadata segment into an EntryRecord (secret members
    // stay empty). Used by overview/query.
    Result<EntryRecord> open_metadata(size_t index) const;

    // Decrypt metadata + secrets (entry-scoped actions). Bumps access_count.
    Result<EntryRecord> open_full(size_t index);

    // Replace an entry in place (edit): reseals both segments under a new
    // reseal epoch.
    Status replace_entry(size_t index, const EntryRecord& e);

    // Remove an entry (wipes its sealed segments).
    Status remove_entry(size_t index);

    // Moving-target reseal: one entry or all. New keys (epoch+1), new
    // buffers, old ones wiped.
    Status reseal(size_t index);
    Status reseal_all();

    // Query: ASCII-case-insensitive substring over display metadata ONLY
    // (name, remark, username, url, tags — agenda §14.5). Secret segments
    // are never decrypted here, so password/TOTP/notes can never match.
    Result<std::vector<size_t>> query(ByteView needle) const;
    // The same search over the given entries only (ascending indices), e.g.
    // the hits of a shorter needle this one extends.
    Result<std::vector<size_t>> query_within(ByteView needle,
                                             const std::vector<size_t>& within) const;

    // Rebuild the full canonical plaintext (for save/export). Caller wipes.
    Result<SecureBuffer> to_canonical() const;

    // Entry-count bucket for the manifest (coarse, non-exact).
    uint32_t entry_count_bucket() const noexcept;

  private:
    struct Slot {
        uint8_t entry_id[ENTRY_ID_LEN] = {};
        uint64_t created_at = 0;
        uint64_t updated_at = 0;
        uint64_t reseal_epoch = 0;
        uint32_t access_count = 0;
        // nonce || ct(meta TLV) and nonce || ct(secret TLV), each in its own
        // guarded allocation so it can be independently wiped/reallocated.
        SecureBuffer sealed_meta;
        SecureBuffer sealed_secret;
    };

    SecureBuffer runtime_prk_;   // HKDF-extracted from runtime root
    SeisHeader header_{};        // binding context (ids only, no secrets)
    std::vector<Slot> slots_;

    Status seal_segments(Slot& s, const EntryRecord& e) const;
};

}  // namespace secraxis

#endif  // SECRAXIS_RUNTIME_STORE_H
