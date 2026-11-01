// seis_format.h — the .seis on-disk container (agenda §8; SEIS_FORMAT.md).
//
// Layout (all integers little-endian):
//
//   [ SeisHeader        ]  fixed-size public header, CRC32-tailed
//   [ VMK envelope      ]  AEAD(KEK_wrap_key): VMK_512 + metadata
//   [ Encrypted manifest]  AEAD(manifest_key): page table + lengths + bindings
//   [ Encrypted pages   ]  AEAD(page_key_i) each, page_i of the A2ONT output
//
// Authentication model:
//   * AAD_immutable  = serialization of the header fields that never change
//     without the master password present (identity + KDF + profile block).
//     Used as AAD for the VMK envelope (rewritten only on password change /
//     rekey, when the KEK is available).
//   * AAD_full       = the exact full header bytes as stored (including
//     epoch, save_salt, offsets, updated_at, with the CRC field zeroed).
//     The manifest's AAD is AAD_full || lp("seis-manifest-region-v1")
//     (rewritten every save).
//   * Pages use AAD_full || lp("seis-page-v1") || u64(index) ||
//     u64(page_count) || u64(body_len), binding every page to this exact
//     header (so to this save), its position and the page layout.
//   * The manifest body carries the VMK envelope tag, welding manifest to
//     envelope. Any mix-and-match of regions from different files or saves
//     fails authentication. (Whole-file rollback to an older valid vault is
//     not detectable without external state — documented in THREAT_MODEL.md.)
//
// The CRC32 exists ONLY to distinguish accidental corruption for nicer
// diagnostics in logs; it has no security role. All security decisions rest
// on AEAD tags, and the user-facing error is the same generic message.
#ifndef SECRAXIS_SEIS_FORMAT_H
#define SECRAXIS_SEIS_FORMAT_H

#include "secraxis/common.h"
#include "secraxis/crypto_profile.h"

namespace secraxis {

// Fixed header size, bytes. Reserved space included for future extension
// (parsers of version 1 require exactly this size).
constexpr size_t SEIS_HEADER_SIZE = 256;

struct SeisHeader {
    // -- identity / immutable block (part of AAD_immutable) --
    uint16_t format_version = SEIS_FORMAT_VERSION;
    uint8_t vault_id[VAULT_ID_LEN] = {};
    uint64_t created_at = 0;  // unix seconds, informational
    uint32_t kdf_profile_id = 0;
    uint32_t kdf_memory_mib = 0;  // must match the registered profile exactly
    uint32_t kdf_iterations = 0;
    uint32_t kdf_lanes = 0;
    uint8_t kdf_salt[KDF_SALT_LEN] = {};
    uint32_t aead_profile_id = 0;
    uint32_t a2ont_profile_id = 0;
    uint32_t padding_policy_id = 0;
    uint32_t canonical_version = 0;

    // -- per-save block (in AAD_full only) --
    uint64_t updated_at = 0;
    uint64_t epoch = 0;             // strictly increasing across saves
    uint8_t save_salt[32] = {};     // fresh CSPRNG per save (nonce hygiene)
    uint32_t page_size = 0;         // SEIS_PAGE_SIZE in v1
    uint32_t page_count = 0;
    uint64_t vmk_env_off = 0;
    uint32_t vmk_env_len = 0;
    uint64_t manifest_off = 0;
    uint32_t manifest_len = 0;
    uint64_t pages_off = 0;
    uint64_t pages_len = 0;  // sum of all encrypted page lengths
};

// Serialize to exactly SEIS_HEADER_SIZE bytes (CRC computed over the rest).
Bytes seis_header_encode(const SeisHeader& h);

// Strict parse: magic, version, size, CRC, registered profile IDs, KDF params
// exactly matching the registered profile, page_size, bounded/ordered/
// non-overlapping regions that fit file_size. Returns FormatUnsupported for
// wrong magic/version (safe to disclose) and AuthGeneric for everything else
// suspicious, so parse failures are not a tampering oracle.
Result<SeisHeader> seis_header_parse(ByteView raw, uint64_t file_size);

// AAD builders (see model above).
Bytes seis_aad_immutable(const SeisHeader& h);
Bytes seis_aad_full(const SeisHeader& h);  // stored bytes with CRC zeroed

// Region length rules.
constexpr uint32_t VMK_ENVELOPE_PLAIN_LEN =
    VMK_LEN + 8 /*vmk_version*/ + 8 /*created_at*/ + VAULT_ID_LEN;
// envelope ciphertext = nonce(profile) || AEAD(plain) — length depends on the
// AEAD profile's nonce length; computed at runtime.

// Manifest plaintext layout (fixed prefix + page table):
//   u32 manifest_version (=1)
//   u8  vmk_envelope_tag[16]
//   u64 canonical_len          (true canonical bytes before padding)
//   u64 padded_len             (bucket size after padding)
//   u64 a2ont_out_len          (padded_len + 32 + a2ont container header)
//   u32 entry_count_bucket     (coarse, internal)
//   u32 page_count
//   u32 page_ct_len[page_count]
constexpr uint32_t MANIFEST_FIXED_LEN = 4 + 16 + 8 + 8 + 8 + 4 + 4;
constexpr uint32_t MANIFEST_MAX_PAGES = 4096;  // 4096*64KiB = 256 MiB cap

}  // namespace secraxis

#endif  // SECRAXIS_SEIS_FORMAT_H
