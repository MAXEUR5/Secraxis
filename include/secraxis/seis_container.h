// seis_container.h — create / unlock / save for .seis vaults (agenda §8, §15).
//
// Unlock order (verify-before-parse, §7.4): fixed header parse -> Argon2id ->
// VMK envelope AEAD -> manifest AEAD -> page AEADs -> A2ONT inverse ->
// unpad -> canonical bytes. Nothing behind an AEAD tag is ever parsed before
// that tag verifies, and every failure after the header collapses to
// Err::AuthGeneric ("Wrong password or corrupted vault.").
//
// Save pipeline (§8.7): epoch+1, fresh save_salt, fresh A2ONT seed, fresh
// page keys/nonces, temp file + flush + atomic rename. The VMK envelope
// bytes are carried through saves verbatim (rewrapping requires the KEK,
// i.e. the master password — change-password/rekey paths only).
#ifndef SECRAXIS_SEIS_CONTAINER_H
#define SECRAXIS_SEIS_CONTAINER_H

#include <atomic>
#include <string>

#include "secraxis/common.h"
#include "secraxis/crypto_profile.h"
#include "secraxis/secure_buffer.h"
#include "secraxis/seis_format.h"

namespace secraxis {

struct UnlockedVault {
    SeisHeader header;      // as stored on disk (current epoch etc.)
    Bytes vmk_envelope;     // ciphertext, reused verbatim across normal saves
    SecureBuffer vmk;       // 64 B
    SecureBuffer prk;       // cached HKDF-Extract(VMK)
    SecureBuffer canonical; // decoded canonical vault bytes
    bool kdf_arena_locked = false;  // non-secret diagnostics
};

struct CreateParams {
    std::string path;
    KdfProfileId kdf = KdfProfileId::Default;
    // 0 = pick aead_default_profile() (GCM-SIV where available, else XChaCha).
    uint32_t aead_profile_id = 0;
    A2ontProfileId a2ont = A2ontProfileId::Default;
    uint64_t now_unix = 0;
    // Set (by another thread) to give up: checked before the KDF and before
    // the file is written (Err::Canceled). Not owned.
    const std::atomic<bool>* cancel = nullptr;
};

// Create a new vault file containing `canonical` (may be empty bytes for an
// empty vault — the codec's empty encoding, supplied by the caller).
// If `out` is non-null it receives the unlocked state (header, envelope,
// VMK, PRK) so creation does not require a second KDF run to start a
// session. out->canonical is NOT populated (the caller already has it).
// An empty master password is refused (Err::InvalidArgument, no file).
Status seis_create(const CreateParams& p, ByteView master_password,
                   ByteView canonical, UnlockedVault* out = nullptr);

// Unlock an existing vault. Errors: FormatUnsupported (bad magic/version or
// AEAD profile not in this build), IoRead, AuthGeneric (everything else).
Result<UnlockedVault> seis_unlock(const std::string& path,
                                  ByteView master_password);

// Unlock directly from an in-memory image (skips the file read). Same
// semantics/errors as seis_unlock; used by the whole-file unlock fuzzer.
Result<UnlockedVault> seis_unlock_bytes(ByteView file,
                                        ByteView master_password);

// Save `canonical` as the new vault content: epoch+1, fresh save_salt/seed/
// keys. Before the atomic rename the assembled container is fully decrypted
// and compared against `canonical` in memory — an encode/transform bug can
// therefore never replace a good vault file with an unopenable one.
//
// verify_password: for key-rotation paths (change master password / rekey /
// KDF upgrade) that rebuild the VMK envelope and/or KDF header, pass the
// credential the file must open with. seis_save then runs a FULL
// unlock-from-password on the assembled image before the rename, so a broken
// envelope or KDF-header binding can never lock the user out. Leave empty for
// ordinary saves (the envelope is carried verbatim and is already proven).
// Updates v.header on success.
//
// target: Same (the default) requires the file at `path` to still be the
// save v.header describes (vault id, epoch, per-save salt); if another
// window or program saved over it since, nothing is written and the result
// is Err::VaultChanged (a missing file is simply written). Overwrite replaces
// whatever is there (the user's explicit choice after VaultChanged). NewFile
// writes a file that must not exist yet (Err::Exists otherwise).
enum class SaveTarget : uint8_t { Same, Overwrite, NewFile };
Status seis_save(const std::string& path, UnlockedVault& v, ByteView canonical,
                 uint64_t now_unix, ByteView verify_password = ByteView(),
                 SaveTarget target = SaveTarget::Same);

// Full integrity validation of a vault file (agenda §6 "validate vault"):
// header, KDF, envelope, manifest, every page tag, A2ONT inverse, padding.
// Returns Ok or the same generic failure surface as unlock; retains nothing.
Status seis_validate(const std::string& path, ByteView master_password);

// The A2ONT stage inverse that unlock/validate run once every page tag has
// verified: parses the A2ONT container header against h's profile, requires
// its length to equal expected_padded_len, and decodes under the context
// bound to h (vault_id, epoch, save_salt, padded length, profile ids).
// AuthGeneric on any mismatch. Exposed for the A2ONT fuzz target and tests;
// production paths reach it only through unlock/validate/save.
Result<SecureBuffer> seis_a2ont_decode(const SecureBuffer& body,
                                       const SeisHeader& h,
                                       uint64_t expected_padded_len);

}  // namespace secraxis

#endif  // SECRAXIS_SEIS_CONTAINER_H
