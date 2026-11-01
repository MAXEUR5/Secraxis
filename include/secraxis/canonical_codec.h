// canonical_codec.h — SEIS-CANON-v1: the deterministic plaintext vault
// encoding (agenda §9). This is what padding/A2ONT/AEAD protect.
//
// Properties (agenda §9.4):
//  * exactly ONE valid byte encoding for a given logical vault: fields are
//    tagged, length-prefixed, and MUST appear in strictly ascending field-id
//    order with no duplicates; entries MUST appear in strictly ascending
//    entry_id order; parser rejects everything else
//  * explicit field IDs, explicit lengths, strict per-field maximum sizes
//  * versioned; unknown field IDs are rejected in v1 (no silent extension)
//  * metadata (ids < 32) and secrets (ids >= 32) are separated: within an
//    entry all metadata fields precede all secret fields, and the split
//    offset is computable without touching secret bytes
//
// The decoder is designed to run ONLY on authenticated plaintext (post-AEAD,
// post-A2ONT), but is still written to fuzz-target standards: bounded, total,
// no allocation from attacker-controlled lengths beyond the input size.
#ifndef SECRAXIS_CANONICAL_CODEC_H
#define SECRAXIS_CANONICAL_CODEC_H

#include <vector>

#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"

namespace secraxis {

constexpr uint32_t ENTRY_ID_LEN = 16;

// Field IDs. Metadata < 32, secrets >= 32. Never renumber; only append.
enum class FieldId : uint16_t {
    Name = 1,
    Remark = 2,
    Username = 3,
    Url = 4,
    Tags = 5,
    PwLenBucket = 6,  // 1 byte: 0..5 (unknown,1-8,9-16,17-32,33-64,65+)
    Password = 32,
    TotpSeed = 33,
    RecoveryCodes = 34,
    SecretNote = 35,
};

constexpr uint16_t FIELD_SECRET_THRESHOLD = 32;

// Strict per-field maximum lengths (bytes).
size_t field_max_len(uint16_t id) noexcept;  // 0 = unknown field

// Password length -> coarse bucket (never store exact length).
uint8_t password_length_bucket(size_t len) noexcept;

// One decoded entry. Metadata lives in ordinary Bytes (display data);
// secret fields live in SecureBuffers.
struct EntryRecord {
    uint8_t entry_id[ENTRY_ID_LEN] = {};
    uint64_t created_at = 0;
    uint64_t updated_at = 0;
    // metadata (optional fields are empty when absent)
    Bytes name, remark, username, url, tags;
    uint8_t pw_bucket = 0;
    // secrets
    SecureBuffer password, totp_seed, recovery_codes, secret_note;

    EntryRecord() = default;
    EntryRecord(EntryRecord&&) = default;
    EntryRecord& operator=(EntryRecord&&) = default;
    EntryRecord(const EntryRecord&) = delete;
    EntryRecord& operator=(const EntryRecord&) = delete;
};

// Encode entries (must already be sorted by entry_id ascending, unique ids)
// into canonical bytes inside secure memory. Fails on: unsorted/duplicate
// ids, oversize fields, too many entries.
Result<SecureBuffer> canonical_encode(const std::vector<EntryRecord>& entries);

// Strict decode. Any deviation from the canonical form fails with
// AuthGeneric (upstream reports the generic error).
Result<std::vector<EntryRecord>> canonical_decode(ByteView canonical);

constexpr uint32_t CANONICAL_MAX_ENTRIES = 100000;

}  // namespace secraxis

#endif  // SECRAXIS_CANONICAL_CODEC_H
