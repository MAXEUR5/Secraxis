// key_hierarchy.h — KEK/VMK/subkey hierarchy (agenda §6; CRYPTO_PROFILES.md §2).
//
//   master password --Argon2id--> KEK_512
//   KEK_512 --HKDF(salt=kdf_salt, info=immutable bindings)--> wrap_key_256
//   wrap_key_256 --AEAD--> VMK envelope  (rewritten only when KEK is present)
//   VMK_512 --HKDF-Extract--> PRK (cached per unlock)
//   PRK --Expand(label, format_version, vault_id, epoch, save_salt, index)-->
//       manifest key/nonce, page keys/nonces, runtime root
//
// Every derivation mixes (epoch, save_salt), so all page/manifest keys and
// nonces are single-use per save — including across forked/snapshotted
// process timelines (save_salt is fresh CSPRNG each save).
#ifndef SECRAXIS_KEY_HIERARCHY_H
#define SECRAXIS_KEY_HIERARCHY_H

#include "secraxis/aead.h"
#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"
#include "secraxis/seis_format.h"

namespace secraxis {

// ---- KEK side (requires master password / Argon2id output) ----------------

// wrap_key = HKDF(salt=h.kdf_salt, ikm=KEK_512, info=immutable bindings).
SecureBuffer derive_vmk_wrap_key(ByteView kek512, const SeisHeader& h);

// Envelope bytes = nonce || AEAD_ct(plaintext(VMK||version||created||vault_id)).
// AAD = seis_aad_immutable(h). Returns empty on failure.
Bytes vmk_envelope_seal(const SeisHeader& h, const AeadProfile& ap,
                        ByteView kek512, const SecureBuffer& vmk,
                        uint64_t vmk_version, uint64_t vmk_created_at);

// Opens and validates the envelope. Any failure -> AuthGeneric.
Result<SecureBuffer> vmk_envelope_open(const SeisHeader& h,
                                       const AeadProfile& ap, ByteView kek512,
                                       ByteView envelope);

// ---- VMK side (post-unlock) ------------------------------------------------

// PRK = HKDF-Extract(salt="seis-vmk-prk-v1"||vault_id, ikm=VMK). 64 bytes.
SecureBuffer vmk_prk(const SecureBuffer& vmk, const SeisHeader& h);

// Expand a domain-separated subkey bound to (label, format_version, vault_id,
// epoch, save_salt, index, extra). `index` disambiguates pages/entries;
// pass 0 when not applicable.
SecureBuffer derive_subkey(const SecureBuffer& prk, const char* purpose_label,
                           const SeisHeader& h, uint64_t index, size_t out_len,
                           ByteView extra = ByteView());
// The same subkey written into `out` (caller-owned secure memory), for loops
// that reuse one key buffer. False (and `out` wiped) on failure.
bool derive_subkey_into(uint8_t* out, size_t out_len, const SecureBuffer& prk,
                        const char* purpose_label, const SeisHeader& h, uint64_t index,
                        ByteView extra = ByteView());

}  // namespace secraxis

#endif  // SECRAXIS_KEY_HIERARCHY_H
