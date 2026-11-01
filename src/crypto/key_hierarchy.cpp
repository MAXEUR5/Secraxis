#include "secraxis/key_hierarchy.h"

#include <cstring>

#include "secraxis/crypto.h"

namespace secraxis {

namespace {

// Canonical info blob: every field length-prefixed or fixed-width — no
// ambiguity, no concatenation collisions.
Bytes binding_info(const char* purpose_label, const SeisHeader& h,
                   uint64_t index, ByteView extra) {
    Bytes info;
    info.reserve(96 + extra.len);
    append_lp(info, label(purpose_label));
    append_le64(info, h.format_version);
    append_lp(info, ByteView(h.vault_id, VAULT_ID_LEN));
    append_le64(info, h.epoch);
    append_lp(info, ByteView(h.save_salt, sizeof(h.save_salt)));
    append_le64(info, index);
    append_lp(info, extra);
    return info;
}

}  // namespace

SecureBuffer derive_vmk_wrap_key(ByteView kek512, const SeisHeader& h) {
    if (kek512.len != KDF_OUT_LEN) return SecureBuffer();
    Bytes info;
    append_lp(info, label(LBL_VMK_WRAP));
    append_le64(info, h.format_version);
    append_lp(info, ByteView(h.vault_id, VAULT_ID_LEN));
    append_le64(info, h.kdf_profile_id);
    append_le64(info, h.aead_profile_id);
    return hkdf_derive(ByteView(h.kdf_salt, KDF_SALT_LEN), kek512,
                       ByteView(info), AEAD_KEY_LEN);
}

Bytes vmk_envelope_seal(const SeisHeader& h, const AeadProfile& ap,
                        ByteView kek512, const SecureBuffer& vmk,
                        uint64_t vmk_version, uint64_t vmk_created_at) {
    Bytes empty;
    if (vmk.size() != VMK_LEN) return empty;
    SecureBuffer wrap = derive_vmk_wrap_key(kek512, h);
    if (!wrap.valid()) return empty;

    SecureBuffer plain = SecureBuffer::alloc(VMK_ENVELOPE_PLAIN_LEN);
    if (!plain.valid()) return empty;
    uint8_t* pp = plain.data();
    std::memcpy(pp, vmk.data(), VMK_LEN);
    store_le64(pp + VMK_LEN, vmk_version);
    store_le64(pp + VMK_LEN + 8, vmk_created_at);
    std::memcpy(pp + VMK_LEN + 16, h.vault_id, VAULT_ID_LEN);

    Bytes aad = seis_aad_immutable(h);
    Bytes env(ap.nonce_len + VMK_ENVELOPE_PLAIN_LEN + ap.tag_len);
    if (!random_bytes(env.data(), ap.nonce_len)) return empty;  // fresh nonce per (re)wrap
    Status s = aead_seal(ap, env.data() + ap.nonce_len, plain.view(),
                         ByteView(aad), env.data(), wrap.data());
    if (!s.ok()) return empty;
    return env;
}

Result<SecureBuffer> vmk_envelope_open(const SeisHeader& h,
                                       const AeadProfile& ap, ByteView kek512,
                                       ByteView envelope) {
    using R = Result<SecureBuffer>;
    if (envelope.len != ap.nonce_len + VMK_ENVELOPE_PLAIN_LEN + ap.tag_len)
        return R::failure(Err::AuthGeneric);
    SecureBuffer wrap = derive_vmk_wrap_key(kek512, h);
    if (!wrap.valid()) return R::failure(Err::AuthGeneric);

    SecureBuffer plain = SecureBuffer::alloc(VMK_ENVELOPE_PLAIN_LEN);
    if (!plain.valid()) return R::failure(Err::AllocationFailed);
    Bytes aad = seis_aad_immutable(h);
    Status s = aead_open(ap, plain.data(),
                         envelope.sub(ap.nonce_len, envelope.len - ap.nonce_len),
                         ByteView(aad), envelope.ptr, wrap.data());
    if (!s.ok()) return R::failure(Err::AuthGeneric);

    // Internal consistency (defense in depth; AAD already binds vault_id).
    if (!ct_equal(plain.data() + VMK_LEN + 16, h.vault_id, VAULT_ID_LEN))
        return R::failure(Err::AuthGeneric);

    SecureBuffer vmk = SecureBuffer::alloc(VMK_LEN);
    if (!vmk.valid()) return R::failure(Err::AllocationFailed);
    std::memcpy(vmk.data(), plain.data(), VMK_LEN);
    return R::success(static_cast<SecureBuffer&&>(vmk));
}

SecureBuffer vmk_prk(const SecureBuffer& vmk, const SeisHeader& h) {
    if (vmk.size() != VMK_LEN) return SecureBuffer();
    Bytes salt;
    append_lp(salt, label("seis-vmk-prk-v1"));
    append_lp(salt, ByteView(h.vault_id, VAULT_ID_LEN));
    SecureBuffer prk = SecureBuffer::alloc(HKDF_PRK_LEN);
    if (!prk.valid()) return prk;
    if (!hkdf_extract(prk.data(), ByteView(salt), vmk.view()).ok())
        prk.reset();
    return prk;
}

SecureBuffer derive_subkey(const SecureBuffer& prk, const char* purpose_label,
                           const SeisHeader& h, uint64_t index, size_t out_len,
                           ByteView extra) {
    SecureBuffer out;
    if (prk.size() != HKDF_PRK_LEN) return out;
    out = SecureBuffer::alloc(out_len);
    if (!out.valid()) return out;
    if (!derive_subkey_into(out.data(), out_len, prk, purpose_label, h, index, extra))
        out.reset();
    return out;
}

bool derive_subkey_into(uint8_t* out, size_t out_len, const SecureBuffer& prk,
                        const char* purpose_label, const SeisHeader& h, uint64_t index,
                        ByteView extra) {
    if (prk.size() != HKDF_PRK_LEN || out == nullptr) return false;
    Bytes info = binding_info(purpose_label, h, index, extra);
    if (hkdf_expand(out, out_len, prk.data(), ByteView(info)).ok()) return true;
    secure_wipe(out, out_len);
    return false;
}

}  // namespace secraxis
