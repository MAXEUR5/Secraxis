// export_import.h — export/import + key-management workflows (agenda §15.8-11).
//
// Export modes, from safest to most dangerous:
//   1. Encrypted full .seis backup       — copy the current file (re-encrypted
//                                           under a new epoch/seed).
//   2. Encrypted re-key backup           — same VMK, new master password.
//   3. Encrypted single-entry package    — one entry under a passphrase.
//   4. PLAINTEXT single entry / full     — explicit unsafe; caller must pass
//                                           an unlock token proving the warning
//                                           was shown.
//
// Import: encrypted Secraxis package, CSV, JSON. CSV/JSON parsers are the
// primary fuzz targets — total, bounded, no allocation from attacker length
// fields, strict field caps.
//
// Key management: change_master_password (rewrap same VMK), rekey (fresh VMK,
// re-encrypt), upgrade_profile (KDF/AEAD/A2ONT/padding — never downgrade).
#ifndef SECRAXIS_EXPORT_IMPORT_H
#define SECRAXIS_EXPORT_IMPORT_H

#include <string>
#include <vector>

#include "secraxis/canonical_codec.h"
#include "secraxis/common.h"
#include "secraxis/crypto_profile.h"
#include "secraxis/seis_container.h"

namespace secraxis {

// ---- CSV / JSON import parsers (fuzzed) -----------------------------------
// Parse untrusted bytes into entries. Never throws; returns NotFound/
// InvalidArgument on malformed input; enforces field caps and a max row/entry
// count. Secrets land in SecureBuffers. Column mapping (CSV): a header row is
// required; recognized headers (case-insensitive): name,title / url,website /
// username,user,login / password,pass / notes,note / totp,otp_secret.
Result<std::vector<EntryRecord>> import_csv(ByteView data);
Result<std::vector<EntryRecord>> import_json(ByteView data);

// Serialize entries to CSV / JSON PLAINTEXT (unsafe export bodies), in secure
// memory (an invalid buffer if none is left). The caller is responsible for
// the warning + secure file handling.
SecureBuffer export_csv_plaintext(const std::vector<EntryRecord>& entries);
SecureBuffer export_json_plaintext(const std::vector<EntryRecord>& entries);

// ---- unsafe plaintext export gating ---------------------------------------
// A token the UI must construct ONLY after showing the warning and getting an
// explicit confirmation; passing it is the code-level proof of consent.
struct UnsafeExportConsent {
    bool acknowledged = false;
    static UnsafeExportConsent grant() { return UnsafeExportConsent{true}; }
};

// Writes plaintext CSV/JSON to `out_path`, a NEW file only the current user
// can read (0600 / Windows owner-only DACL; see write_file_private): never
// over an existing file or through a link (Err::Exists), and nothing is left
// behind if the write fails. Refuses without consent.acknowledged.
Status export_plaintext_file(const std::string& out_path,
                             const std::vector<EntryRecord>& entries,
                             bool as_json, UnsafeExportConsent consent);

// Encrypted backup: the vault file's bytes as they are (a whole authenticated
// container), read once. Those very bytes must open with master_password and
// decode (the unlock path's errors otherwise), and are then written to
// backup_path, which must not exist yet (Err::Exists: a backup never
// replaces a file, the vault itself included).
Status backup_vault_file(const std::string& path, ByteView master_password,
                         const std::string& backup_path);

// ---- key management (operate on an unlocked vault file) -------------------
// Change the master password: unlock with old, rewrap the SAME VMK under a
// new KEK/salt, advance epoch, atomic save. Vault body keys are unchanged
// (fast — no re-encryption of pages beyond the epoch bump).
Status change_master_password(const std::string& path, ByteView old_password,
                              ByteView new_password, uint64_t now_unix);

// Full rekey: fresh VMK_512, re-encrypt everything, new envelope. Old file
// copies remain crackable under the OLD master password — documented.
Status rekey_vault(const std::string& path, ByteView master_password,
                   uint64_t now_unix);

// Upgrade the KDF profile (and re-derive KEK). Never downgrades below the
// current profile's strength ordering (Floor < Default < Strong).
Status upgrade_kdf_profile(const std::string& path, ByteView master_password,
                           KdfProfileId new_profile, uint64_t now_unix);

}  // namespace secraxis

#endif  // SECRAXIS_EXPORT_IMPORT_H
