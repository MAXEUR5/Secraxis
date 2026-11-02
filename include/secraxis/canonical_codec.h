// canonical_codec.h — SEIS-CANON: the deterministic plaintext vault encoding
// (agenda §9). This is what padding/A2ONT/AEAD protect.
//
// Properties (agenda §9.4):
//  * exactly ONE valid byte encoding for a given logical vault in each
//    revision: fields are tagged, length-prefixed, and MUST appear in
//    strictly ascending field-id order with no duplicates; entries MUST
//    appear in strictly ascending entry_id order; parser rejects everything
//    else
//  * explicit field IDs, explicit lengths, strict per-field maximum sizes
//  * versioned by the leading magic: "SXC1" (v1, 0.9.1 and 0.9.2) and
//    "SXC2" (v2, from 0.9.3: v1 plus the entry's Color). Each revision
//    rejects the field IDs it does not define (no silent extension); a
//    later revision ("SXC3" and up) is reported as Err::NewerFormat. The
//    encoder writes the current revision.
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

// Revisions (the magic's last digit). Never reuse one.
constexpr uint32_t CANON_V1 = 1;
constexpr uint32_t CANON_V2 = 2;
constexpr uint32_t CANON_CURRENT = CANON_V2;

// The palette an entry's color picks from (Color holds 1..ENTRY_COLORS; an
// entry without the field is colored automatically).
constexpr uint8_t ENTRY_COLORS = 8;

// What the user is told for Err::NewerFormat (the CLI and the vault screen).
inline constexpr const char* NEWER_FORMAT_TEXT =
    "This vault was saved by a newer version of Secraxis. Update Secraxis to open it.";
// What the user is told once the first save has upgraded an older vault's
// contents (the vault screen, `import`).
inline constexpr const char* FORMAT_UPGRADED_TEXT =
    "Saved in the 0.9.3 vault format: Secraxis 0.9.2 and older can no longer open this vault.";

// Field IDs. Metadata < 32, secrets >= 32. Never renumber; only append.
enum class FieldId : uint16_t {
    Name = 1,
    Remark = 2,
    Username = 3,
    Url = 4,
    Tags = 5,
    PwLenBucket = 6,  // 1 byte: 0..5 (unknown,1-8,9-16,17-32,33-64,65+)
    EntryColor = 7,   // v2: 1 byte, 1..ENTRY_COLORS; absent = automatic
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
    uint8_t color = 0;  // 0 automatic, else 1..ENTRY_COLORS (v2)
    // secrets
    SecureBuffer password, totp_seed, recovery_codes, secret_note;

    EntryRecord() = default;
    EntryRecord(EntryRecord&&) = default;
    EntryRecord& operator=(EntryRecord&&) = default;
    EntryRecord(const EntryRecord&) = delete;
    EntryRecord& operator=(const EntryRecord&) = delete;
};

// Encode entries (must already be sorted by entry_id ascending, unique ids)
// into canonical bytes inside secure memory, in revision `version` (the
// current one unless a test needs an older file). Fails on: unsorted/
// duplicate ids, oversize fields, too many entries, a color outside the
// palette, a color in v1.
Result<SecureBuffer> canonical_encode(const std::vector<EntryRecord>& entries,
                                      uint32_t version = CANON_CURRENT);

// Strict decode of any revision this version reads; *version (if given)
// receives it. Any deviation from the canonical form fails with AuthGeneric
// (upstream reports the generic error); a later revision fails with
// NewerFormat.
Result<std::vector<EntryRecord>> canonical_decode(ByteView canonical,
                                                  uint32_t* version = nullptr);

constexpr uint32_t CANONICAL_MAX_ENTRIES = 100000;

}  // namespace secraxis

#endif  // SECRAXIS_CANONICAL_CODEC_H
