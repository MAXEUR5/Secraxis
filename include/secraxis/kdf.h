// kdf.h — Argon2id master-password KDF (agenda §5).
//
// Uses the PHC reference implementation via the low-level argon2_context API:
// 32-byte salt, 64-byte output, profile-mandated lanes — parameters libsodium's
// crypto_pwhash cannot express (it hardcodes p=1, salt=16).
//
// The Argon2 memory arena (up to 1 GiB) is allocated through a custom
// allocator that applies best-effort page locking + no-dump hints and
// guarantees a wipe on release (in addition to Argon2's own internal-memory
// clearing). Lock failure is a non-secret warning, not an error (§5.3).
#ifndef SECRAXIS_KDF_H
#define SECRAXIS_KDF_H

#include "secraxis/common.h"
#include "secraxis/crypto_profile.h"
#include "secraxis/secure_buffer.h"

namespace secraxis {

struct KdfOutcome {
    Err err = Err::Internal;
    SecureBuffer kek_material;  // 64 bytes on success
    bool arena_locked = false;  // best-effort mlock result (non-secret)
    bool ok() const noexcept { return err == Err::Ok; }
};

// Derive 512-bit KEK material from the master password using a registered
// profile. salt must be KDF_SALT_LEN bytes.
KdfOutcome derive_kek_material(ByteView master_password, ByteView salt,
                               const KdfProfile& profile) noexcept;

// Raw-parameter variant for KATs, calibration, and tests only.
// out_len in [4, 1024]; mem_kib >= 8*lanes (Argon2 minimum).
KdfOutcome argon2id_raw(ByteView password, ByteView salt, uint32_t t_cost,
                        uint32_t mem_kib, uint32_t lanes, size_t out_len) noexcept;

}  // namespace secraxis

#endif  // SECRAXIS_KDF_H
