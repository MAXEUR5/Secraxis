#include "secraxis/seis_container.h"

#include <cstring>

#include "secraxis/a2ont.h"
#include "secraxis/aead.h"
#include "secraxis/crypto.h"
#include "secraxis/fs_atomic.h"
#include "secraxis/kdf.h"
#include "secraxis/key_hierarchy.h"
#include "secraxis/padding.h"

// A2ONT_TEST_ONLY compiles in caller-chosen-seed entry points for the vector
// tests. Production must only ever seed A2ONT from the OS CSPRNG.
#if defined(A2ONT_TEST_ONLY)
#error "A2ONT_TEST_ONLY must never be defined for secraxis_core"
#endif

namespace secraxis {

// ---------------------------------------------------------------------------
// A2ONT stage (docs/A2ONT_INTEGRATION.md). A2ONT is NOT encryption: its
// output is reversible from the public context alone, so everything it
// produces stays in SecureBuffer and is AEAD-sealed before reaching disk.
// ---------------------------------------------------------------------------
namespace {

// Only the two .seis profiles resolve. The A2ONT component also defines
// weakened research/ablation profiles (ids 3-9: r1, no-core, xor-chains,
// ...); a file's id must never reach a2ont_profile_init unchecked.
bool seis_a2ont_profile(uint32_t seis_a2ont_id, a2ont_profile_t* out) {
    uint32_t lib_id;
    switch (static_cast<A2ontProfileId>(seis_a2ont_id)) {
        case A2ontProfileId::Default:
            lib_id = A2ONT_PROFILE_V1_DEFAULT;
            break;
        case A2ontProfileId::Strong:
            lib_id = A2ONT_PROFILE_V1_STRONG;
            break;
        default:
            return false;
    }
    return a2ont_profile_init(out, lib_id) == A2ONT_OK;
}

// Public, deterministic context binding. Mirrors CRYPTO_PROFILES.md §4 and
// A2ONT_INTEGRATION.md; any change to this layout is a format change.
Bytes seis_a2ont_ctx(const SeisHeader& h, uint64_t padded_len) {
    Bytes ctx;
    ctx.reserve(128);
    append_lp(ctx, label(LBL_A2ONT_CTX));
    append_le64(ctx, h.format_version);
    append_lp(ctx, ByteView(h.vault_id, VAULT_ID_LEN));
    append_le64(ctx, h.epoch);
    append_lp(ctx, ByteView(h.save_salt, sizeof(h.save_salt)));
    append_le64(ctx, padded_len);
    append_le64(ctx, h.a2ont_profile_id);
    append_le64(ctx, h.aead_profile_id);
    append_le64(ctx, h.padding_policy_id);
    append_le64(ctx, h.canonical_version);
    return ctx;
}

// Paged body length for a padded input: A2ONT container header + L + seed.
// 0 on unsupported profile/length.
size_t seis_a2ont_body_len(uint32_t a2ont_profile_id, size_t padded_len) {
    a2ont_profile_t prof;
    if (!seis_a2ont_profile(a2ont_profile_id, &prof)) return 0;
    if (a2ont_check_input_len(padded_len, &prof) != A2ONT_OK) return 0;
    const size_t header = a2ont_header_len(&prof, padded_len);
    const size_t package = a2ont_output_len(padded_len, &prof);
    if (header == 0 || package == 0) return 0;
    return header + package;
}

// padded -> A2ONT container bytes (a2ont_header || Y || Y_extra). Empty on
// failure.
SecureBuffer seis_a2ont_encode(const SecureBuffer& padded, const SeisHeader& h) {
    SecureBuffer out;
    a2ont_profile_t prof;
    if (!seis_a2ont_profile(h.a2ont_profile_id, &prof)) return out;
    if (a2ont_check_input_len(padded.size(), &prof) != A2ONT_OK) return out;

    const size_t header_len = a2ont_header_len(&prof, padded.size());
    const size_t package_len = a2ont_output_len(padded.size(), &prof);
    if (header_len == 0 || package_len == 0) return out;

    out = SecureBuffer::alloc(header_len + package_len);
    if (!out.valid()) return out;

    if (a2ont_header_build(&prof, padded.size(), out.data(), header_len) !=
        A2ONT_OK) {
        out.reset();
        return out;
    }
    Bytes ctx = seis_a2ont_ctx(h, padded.size());
    // Fresh OS-CSPRNG seed inside a2ont_encode — one per save, never reused.
    if (a2ont_encode(padded.data(), padded.size(), ctx.data(), ctx.size(),
                     &prof, out.data() + header_len, package_len) != A2ONT_OK) {
        out.reset();
        return out;
    }
    return out;
}

}  // namespace

Result<SecureBuffer> seis_a2ont_decode(const SecureBuffer& body,
                                       const SeisHeader& h,
                                       uint64_t expected_padded_len) {
    using R = Result<SecureBuffer>;
    a2ont_profile_t prof;
    if (!seis_a2ont_profile(h.a2ont_profile_id, &prof))
        return R::failure(Err::AuthGeneric);

    size_t body_offset = 0;
    size_t body_len = 0;  // = L (padded length)
    if (a2ont_header_parse(body.data(), body.size(), &prof, &body_offset,
                           &body_len) != A2ONT_OK)
        return R::failure(Err::AuthGeneric);
    if (body_len != expected_padded_len)
        return R::failure(Err::AuthGeneric);
    const size_t package_len = a2ont_output_len(body_len, &prof);
    if (package_len == 0 || body_offset + package_len != body.size())
        return R::failure(Err::AuthGeneric);

    SecureBuffer padded = SecureBuffer::alloc(body_len);
    if (!padded.valid() && body_len > 0) return R::failure(Err::AllocationFailed);

    Bytes ctx = seis_a2ont_ctx(h, body_len);
    if (a2ont_decode(body.data() + body_offset, package_len, ctx.data(),
                     ctx.size(), &prof, padded.data(), body_len) != A2ONT_OK)
        return R::failure(Err::AuthGeneric);
    return R::success(static_cast<SecureBuffer&&>(padded));
}

namespace {

constexpr uint32_t MANIFEST_VERSION = 1;
constexpr size_t PAGE_ENTRY_LEN = 4 + AEAD_TAG_LEN;  // u32 ct_len + tag copy
// How long a save waits for another process's save of the same file (one
// takes well under a second; the hangup path has 5 s in all).
constexpr unsigned kReplaceLockWaitMs = 3000;

Bytes page_aad(const Bytes& aad_full, uint64_t index, uint64_t page_count,
               uint64_t body_len) {
    Bytes aad = aad_full;
    append_lp(aad, label("seis-page-v1"));
    append_le64(aad, index);
    append_le64(aad, page_count);
    append_le64(aad, body_len);
    return aad;
}

Bytes manifest_aad(const Bytes& aad_full) {
    Bytes aad = aad_full;
    append_lp(aad, label("seis-manifest-region-v1"));
    return aad;
}

struct PagePlan {
    uint32_t count = 0;
    uint64_t body_len = 0;
    uint64_t pages_len = 0;  // sum of ciphertext lengths
    uint32_t manifest_len = 0;
};

bool plan_pages(uint64_t body_len, const AeadProfile& ap, PagePlan* out) {
    if (body_len == 0) return false;
    const uint64_t pc = (body_len + SEIS_PAGE_SIZE - 1) / SEIS_PAGE_SIZE;
    if (pc == 0 || pc > MANIFEST_MAX_PAGES) return false;
    out->count = static_cast<uint32_t>(pc);
    out->body_len = body_len;
    out->pages_len = body_len + pc * AEAD_TAG_LEN;
    const uint64_t mlen = ap.nonce_len /*stored? no: derived*/;
    (void)mlen;
    out->manifest_len = static_cast<uint32_t>(
        MANIFEST_FIXED_LEN + pc * PAGE_ENTRY_LEN + AEAD_TAG_LEN);
    return true;
}

// Derives (key, nonce) and seals/opens one region with a purpose label.
struct RegionKeys {
    SecureBuffer key;
    SecureBuffer nonce;
    bool ok = false;
};

RegionKeys region_keys(const SecureBuffer& prk, const SeisHeader& h,
                       const AeadProfile& ap, const char* key_label,
                       const char* nonce_label, uint64_t index) {
    RegionKeys rk;
    rk.key = derive_subkey(prk, key_label, h, index, AEAD_KEY_LEN);
    rk.nonce = derive_subkey(prk, nonce_label, h, index, ap.nonce_len);
    rk.ok = rk.key.valid() && rk.nonce.valid();
    return rk;
}

// Serialize + encrypt everything after the header. On success appends the
// envelope, manifest ciphertext, and page ciphertexts to `file`.
Status build_body(Bytes& file, const SeisHeader& h, const AeadProfile& ap,
                  const SecureBuffer& prk, const Bytes& vmk_envelope,
                  ByteView canonical) {
    // 1. pad
    const uint64_t padded_len = padding_bucket_for(canonical.len);
    if (padded_len == 0) return status_fail(Err::InvalidArgument);
    Result<SecureBuffer> pad = pad_to_bucket(canonical, padded_len);
    if (!pad.ok()) return status_fail(pad.err);
    SecureBuffer padded = static_cast<SecureBuffer&&>(pad.value);

    // 2. A2ONT (fresh seed inside)
    SecureBuffer body = seis_a2ont_encode(padded, h);
    padded.reset();
    if (!body.valid()) return status_fail(Err::Internal);

    // 3. plan + sanity vs header fields (must already be final)
    PagePlan plan;
    if (!plan_pages(body.size(), ap, &plan)) return status_fail(Err::Internal);
    if (plan.count != h.page_count || plan.pages_len != h.pages_len ||
        plan.manifest_len != h.manifest_len)
        return status_fail(Err::Internal);

    const Bytes aad_full = seis_aad_full(h);

    // 4. encrypt pages
    Bytes pages;
    pages.reserve(static_cast<size_t>(plan.pages_len));
    Bytes manifest_plain;
    manifest_plain.reserve(plan.manifest_len);
    append_le32(manifest_plain, MANIFEST_VERSION);
    if (vmk_envelope.size() < AEAD_TAG_LEN) return status_fail(Err::Internal);
    append_bytes(manifest_plain,
                 ByteView(vmk_envelope.data() + vmk_envelope.size() - AEAD_TAG_LEN,
                          AEAD_TAG_LEN));
    append_le64(manifest_plain, canonical.len);
    append_le64(manifest_plain, padded_len);
    append_le64(manifest_plain, body.size());
    append_le32(manifest_plain, 0 /*entry_count_bucket: wired in Phase 3*/);
    append_le32(manifest_plain, plan.count);

    for (uint32_t i = 0; i < plan.count; ++i) {
        const size_t off = static_cast<size_t>(i) * SEIS_PAGE_SIZE;
        const size_t n = (off + SEIS_PAGE_SIZE <= body.size())
                             ? SEIS_PAGE_SIZE
                             : body.size() - off;
        RegionKeys rk =
            region_keys(prk, h, ap, LBL_PAGE_AEAD, LBL_PAGE_NONCE, i);
        if (!rk.ok) return status_fail(Err::AllocationFailed);
        Bytes aad = page_aad(aad_full, i, plan.count, body.size());
        const size_t ct_len = n + AEAD_TAG_LEN;
        size_t old = pages.size();
        pages.resize(old + ct_len);
        Status s = aead_seal(ap, pages.data() + old,
                             ByteView(body.data() + off, n), ByteView(aad),
                             rk.nonce.data(), rk.key.data());
        if (!s.ok()) return s;
        append_le32(manifest_plain, static_cast<uint32_t>(ct_len));
        append_bytes(manifest_plain,
                     ByteView(pages.data() + old + n, AEAD_TAG_LEN));
    }
    body.reset();

    // 5. manifest
    if (manifest_plain.size() + AEAD_TAG_LEN != plan.manifest_len)
        return status_fail(Err::Internal);
    RegionKeys mk =
        region_keys(prk, h, ap, LBL_MANIFEST, LBL_MANIFEST_NONCE, 0);
    if (!mk.ok) return status_fail(Err::AllocationFailed);
    Bytes maad = manifest_aad(aad_full);
    Bytes manifest_ct(plan.manifest_len);
    Status s = aead_seal(ap, manifest_ct.data(), ByteView(manifest_plain),
                         ByteView(maad), mk.nonce.data(), mk.key.data());
    secure_wipe(manifest_plain.data(), manifest_plain.size());
    if (!s.ok()) return s;

    // 6. assemble (header must already be in `file`)
    append_bytes(file, ByteView(vmk_envelope));
    append_bytes(file, ByteView(manifest_ct));
    append_bytes(file, ByteView(pages));
    return status_ok();
}

// Fill the per-save header fields for a body of `canonical_len` bytes.
Status finalize_header(SeisHeader& h, const AeadProfile& ap,
                       uint32_t envelope_len, uint64_t canonical_len,
                       uint64_t now_unix) {
    const uint64_t padded_len = padding_bucket_for(canonical_len);
    if (padded_len == 0) return status_fail(Err::InvalidArgument);
    const size_t body_len =
        seis_a2ont_body_len(h.a2ont_profile_id, static_cast<size_t>(padded_len));
    if (body_len == 0) return status_fail(Err::Internal);
    PagePlan plan;
    if (!plan_pages(body_len, ap, &plan)) return status_fail(Err::Internal);

    h.updated_at = now_unix;
    if (!random_bytes(h.save_salt, sizeof(h.save_salt))) return status_fail(Err::RngFailed);
    h.page_size = SEIS_PAGE_SIZE;
    h.page_count = plan.count;
    h.vmk_env_off = SEIS_HEADER_SIZE;
    h.vmk_env_len = envelope_len;
    h.manifest_off = h.vmk_env_off + h.vmk_env_len;
    h.manifest_len = plan.manifest_len;
    h.pages_off = h.manifest_off + h.manifest_len;
    h.pages_len = plan.pages_len;
    return status_ok();
}


// Authenticate manifest + pages, run the A2ONT inverse, and unpad — shared by
// unlock, seis_validate, and the pre-rename save verification. `file` must
// already have a parsed/validated header `h`. Any failure -> AuthGeneric
// (uniform), except allocation.
Status open_body(ByteView file, const SeisHeader& h, const AeadProfile& ap,
                 const SecureBuffer& prk, SecureBuffer* canonical_out) {
    const Bytes aad_full = seis_aad_full(h);

    if (h.manifest_len < AEAD_TAG_LEN) return status_fail(Err::AuthGeneric);
    SecureBuffer manifest = SecureBuffer::alloc(h.manifest_len - AEAD_TAG_LEN);
    if (!manifest.valid()) return status_fail(Err::AllocationFailed);
    {
        RegionKeys mk =
            region_keys(prk, h, ap, LBL_MANIFEST, LBL_MANIFEST_NONCE, 0);
        if (!mk.ok) return status_fail(Err::AllocationFailed);
        Bytes maad = manifest_aad(aad_full);
        Status s = aead_open(
            ap, manifest.data(),
            ByteView(file.ptr + h.manifest_off, h.manifest_len),
            ByteView(maad), mk.nonce.data(), mk.key.data());
        if (!s.ok()) return status_fail(Err::AuthGeneric);
    }
    const uint8_t* m = manifest.data();
    size_t mlen = manifest.size();
    if (mlen < MANIFEST_FIXED_LEN) return status_fail(Err::AuthGeneric);
    if (load_le32(m) != MANIFEST_VERSION) return status_fail(Err::AuthGeneric);
    if (h.vmk_env_len < AEAD_TAG_LEN ||
        !ct_equal(m + 4,
                  file.ptr + h.vmk_env_off + h.vmk_env_len - AEAD_TAG_LEN,
                  AEAD_TAG_LEN))
        return status_fail(Err::AuthGeneric);
    const uint64_t canonical_len = load_le64(m + 20);
    const uint64_t padded_len = load_le64(m + 28);
    const uint64_t body_len = load_le64(m + 36);
    const uint32_t page_count = load_le32(m + 48);
    if (page_count != h.page_count ||
        mlen != MANIFEST_FIXED_LEN +
                    static_cast<size_t>(page_count) * PAGE_ENTRY_LEN)
        return status_fail(Err::AuthGeneric);
    if (padded_len != padding_bucket_for(canonical_len) ||
        canonical_len > padded_len)
        return status_fail(Err::AuthGeneric);
    if (body_len != seis_a2ont_body_len(h.a2ont_profile_id,
                                        static_cast<size_t>(padded_len)))
        return status_fail(Err::AuthGeneric);

    SecureBuffer body = SecureBuffer::alloc(static_cast<size_t>(body_len));
    if (!body.valid()) return status_fail(Err::AllocationFailed);
    uint64_t file_off = h.pages_off;
    uint64_t body_off = 0;
    const uint8_t* entry = m + MANIFEST_FIXED_LEN;
    for (uint32_t i = 0; i < page_count; ++i, entry += PAGE_ENTRY_LEN) {
        const uint32_t ct_len = load_le32(entry);
        if (ct_len < AEAD_TAG_LEN + 1 || ct_len > SEIS_PAGE_SIZE + AEAD_TAG_LEN)
            return status_fail(Err::AuthGeneric);
        const uint64_t pt_len = ct_len - AEAD_TAG_LEN;
        if (file_off + ct_len > h.pages_off + h.pages_len ||
            body_off + pt_len > body_len)
            return status_fail(Err::AuthGeneric);
        if (!ct_equal(entry + 4, file.ptr + file_off + pt_len, AEAD_TAG_LEN))
            return status_fail(Err::AuthGeneric);
        RegionKeys rk = region_keys(prk, h, ap, LBL_PAGE_AEAD, LBL_PAGE_NONCE, i);
        if (!rk.ok) return status_fail(Err::AllocationFailed);
        Bytes aad = page_aad(aad_full, i, page_count, body_len);
        Status s = aead_open(ap, body.data() + body_off,
                             ByteView(file.ptr + file_off, ct_len),
                             ByteView(aad), rk.nonce.data(), rk.key.data());
        if (!s.ok()) return status_fail(Err::AuthGeneric);
        file_off += ct_len;
        body_off += pt_len;
    }
    if (file_off != h.pages_off + h.pages_len || body_off != body_len)
        return status_fail(Err::AuthGeneric);

    Result<SecureBuffer> pr = seis_a2ont_decode(body, h, padded_len);
    body.reset();
    if (!pr.ok()) return status_fail(Err::AuthGeneric);
    SecureBuffer canonical =
        SecureBuffer::alloc(static_cast<size_t>(canonical_len));
    if (canonical_len > 0) {
        if (!canonical.valid()) return status_fail(Err::AllocationFailed);
        std::memcpy(canonical.data(), pr.value.data(),
                    static_cast<size_t>(canonical_len));
    }
    pr.value.reset();
    *canonical_out = static_cast<SecureBuffer&&>(canonical);
    return status_ok();
}

// Decrypt-and-compare self-check run on every assembled container BEFORE the
// atomic rename: an encode/transform bug must never replace a good vault
// file with an unopenable one (ENTRY_LIFECYCLE.md section 4; data-loss
// hardening).
Status verify_assembled(ByteView file, const SeisHeader& h,
                        const AeadProfile& ap, const SecureBuffer& prk,
                        ByteView expected_canonical) {
    SecureBuffer roundtrip;
    Status st = open_body(file, h, ap, prk, &roundtrip);
    if (!st.ok()) return status_fail(Err::Internal);
    if (roundtrip.size() != expected_canonical.len)
        return status_fail(Err::Internal);
    if (expected_canonical.len > 0 && !roundtrip.ct_equals(expected_canonical))
        return status_fail(Err::Internal);
    return status_ok();
}

}  // namespace

// The file at `path` must still be the save `h` describes (seis_save,
// SaveTarget::Same). A missing file is fine: it is written anew.
Status check_unchanged(const std::string& path, const SeisHeader& h) {
    if (!file_exists(path)) return status_ok();
    uint64_t size = 0;
    Result<Bytes> head = read_file_head(path, SEIS_HEADER_SIZE, &size);
    if (!head.ok()) return status_fail(Err::IoRead);
    Result<SeisHeader> disk = seis_header_parse(ByteView(head.value), size);
    if (!disk.ok() || disk.value.epoch != h.epoch ||
        std::memcmp(disk.value.vault_id, h.vault_id, VAULT_ID_LEN) != 0 ||
        std::memcmp(disk.value.save_salt, h.save_salt, sizeof(h.save_salt)) != 0)
        return status_fail(Err::VaultChanged);
    return status_ok();
}

namespace {

// The file at `path` must not hold this vault with other keys (seis_save,
// SaveTarget::Overwrite): passwd, rekey or upgrade ran elsewhere, and
// writing over it would bring the old, perhaps leaked, password back.
// VaultSession::save_to checks the same before building the image; this
// runs again under the replace lock, for a key change that finished
// meanwhile. Another vault, or a file that is not a vault, is the user's
// explicit overwrite.
Status check_not_rekeyed(const std::string& path, const SeisHeader& h) {
    if (!file_exists(path)) return status_ok();
    uint64_t size = 0;
    Result<Bytes> head = read_file_head(path, SEIS_HEADER_SIZE, &size);
    if (!head.ok()) return status_ok();
    Result<SeisHeader> disk = seis_header_parse(ByteView(head.value), size);
    if (!disk.ok()) return status_ok();
    const SeisHeader& d = disk.value;
    if (std::memcmp(d.vault_id, h.vault_id, VAULT_ID_LEN) != 0) return status_ok();
    if (std::memcmp(d.kdf_salt, h.kdf_salt, KDF_SALT_LEN) != 0 ||
        d.kdf_profile_id != h.kdf_profile_id || d.aead_profile_id != h.aead_profile_id)
        return status_fail(Err::VaultRekeyed);
    return status_ok();
}

}  // namespace

Status seis_create(const CreateParams& p, ByteView master_password,
                   ByteView canonical, UnlockedVault* out) {
    if (!crypto_init()) return status_fail(Err::Internal);
    // Never a vault anyone can open, whatever went wrong upstream.
    if (master_password.empty()) return status_fail(Err::InvalidArgument);
    const KdfProfile* kp = kdf_profile_by_id(static_cast<uint32_t>(p.kdf));
    if (kp == nullptr) return status_fail(Err::InvalidArgument);
    const AeadProfile* ap = (p.aead_profile_id == 0)
                                ? &aead_default_profile()
                                : aead_profile_by_id(p.aead_profile_id);
    if (ap == nullptr || !aead_profile_available(ap->id))
        return status_fail(Err::InvalidArgument);
    if (file_exists(p.path)) return status_fail(Err::Exists);
    auto canceled = [&p]() { return p.cancel != nullptr && p.cancel->load(); };
    if (canceled()) return status_fail(Err::Canceled);

    SeisHeader h;
    h.format_version = SEIS_FORMAT_VERSION;
    // Before the KDF: without random numbers nothing is derived or written.
    if (!random_bytes(h.vault_id, VAULT_ID_LEN) || !random_bytes(h.kdf_salt, KDF_SALT_LEN))
        return status_fail(Err::RngFailed);
    h.created_at = p.now_unix;
    h.kdf_profile_id = static_cast<uint32_t>(kp->id);
    h.kdf_memory_mib = kp->memory_mib;
    h.kdf_iterations = kp->iterations;
    h.kdf_lanes = kp->lanes;
    h.aead_profile_id = static_cast<uint32_t>(ap->id);
    h.a2ont_profile_id = static_cast<uint32_t>(p.a2ont);
    h.padding_policy_id = static_cast<uint32_t>(PaddingPolicyId::BucketV1);
    h.canonical_version = CANONICAL_VERSION;
    h.epoch = 1;

    // KDF -> KEK -> VMK envelope
    KdfOutcome kdf = derive_kek_material(
        master_password, ByteView(h.kdf_salt, KDF_SALT_LEN), *kp);
    if (!kdf.ok()) return status_fail(kdf.err);
    Result<SecureBuffer> fresh_vmk = random_secret(VMK_LEN);
    if (!fresh_vmk.ok()) return status_fail(fresh_vmk.err);
    SecureBuffer vmk = static_cast<SecureBuffer&&>(fresh_vmk.value);
    Bytes envelope = vmk_envelope_seal(h, *ap, kdf.kek_material.view(), vmk,
                                       /*vmk_version=*/1, p.now_unix);
    if (envelope.empty()) {
        kdf.kek_material.reset();
        return status_fail(entropy_state() == EntropyState::Ready ? Err::Internal
                                                                   : Err::RngFailed);
    }
    // Every later save carries this envelope as it is: prove now, with the
    // KEK in hand (no second KDF), that it opens to this very VMK.
    {
        Result<SecureBuffer> back =
            vmk_envelope_open(h, *ap, kdf.kek_material.view(), ByteView(envelope));
        kdf.kek_material.reset();
        if (!back.ok() || back.value.size() != vmk.size() || !back.value.ct_equals(vmk.view()))
            return status_fail(Err::Internal);
    }

    Status fs = finalize_header(h, *ap, static_cast<uint32_t>(envelope.size()),
                                canonical.len, p.now_unix);
    if (!fs.ok()) return fs;

    SecureBuffer prk = vmk_prk(vmk, h);
    if (!prk.valid()) return status_fail(Err::AllocationFailed);

    Bytes file = seis_header_encode(h);
    Status bs = build_body(file, h, *ap, prk, envelope, canonical);
    if (!bs.ok()) return bs;
    Status vs = verify_assembled(ByteView(file), h, *ap, prk, canonical);
    if (!vs.ok()) return vs;
    // Given up during the KDF (or, in write_file_new, while the file is
    // written): nothing is put in place.
    if (canceled()) return status_fail(Err::Canceled);
    // Never replaces: a file that appeared during the KDF (another window,
    // a sync tool) is not overwritten by an empty vault.
    Status ws = write_file_new(p.path, ByteView(file), p.cancel);
    if (!ws.ok()) return ws;
    if (out != nullptr) {
        out->header = h;
        out->vmk_envelope = envelope;
        out->vmk = static_cast<SecureBuffer&&>(vmk);
        out->prk = static_cast<SecureBuffer&&>(prk);
        out->canonical.reset();
        out->kdf_arena_locked = kdf.arena_locked;
    }
    return status_ok();
}

Result<UnlockedVault> seis_unlock(const std::string& path,
                                  ByteView master_password) {
    using R = Result<UnlockedVault>;
    if (!crypto_init()) return R::failure(Err::Internal);
    Result<Bytes> fr = read_file(path);
    if (!fr.ok()) return R::failure(fr.err);
    return seis_unlock_bytes(ByteView(fr.value), master_password);
}

Result<UnlockedVault> seis_unlock_bytes(ByteView file,
                                        ByteView master_password) {
    using R = Result<UnlockedVault>;
    if (!crypto_init()) return R::failure(Err::Internal);

    Result<SeisHeader> hr =
        seis_header_parse(file, file.len);
    if (!hr.ok()) return R::failure(hr.err);
    const SeisHeader& h = hr.value;
    const AeadProfile* ap = aead_profile_by_id(h.aead_profile_id);
    if (ap == nullptr) return R::failure(Err::AuthGeneric);

    // KDF (worker-thread integration arrives with the TUI; blocking here).
    const KdfProfile* kp = kdf_profile_by_id(h.kdf_profile_id);
    if (kp == nullptr) return R::failure(Err::AuthGeneric);
    KdfOutcome kdf = derive_kek_material(
        master_password, ByteView(h.kdf_salt, KDF_SALT_LEN), *kp);
    if (!kdf.ok()) return R::failure(kdf.err);

    // VMK envelope
    ByteView env(file.ptr + h.vmk_env_off, h.vmk_env_len);
    Result<SecureBuffer> vr =
        vmk_envelope_open(h, *ap, kdf.kek_material.view(), env);
    kdf.kek_material.reset();
    if (!vr.ok()) return R::failure(Err::AuthGeneric);
    SecureBuffer vmk = static_cast<SecureBuffer&&>(vr.value);
    SecureBuffer prk = vmk_prk(vmk, h);
    if (!prk.valid()) return R::failure(Err::AllocationFailed);

    SecureBuffer canonical;
    Status ob = open_body(file, h, *ap, prk, &canonical);
    if (!ob.ok())
        return R::failure(ob.err == Err::AllocationFailed
                              ? Err::AllocationFailed
                              : Err::AuthGeneric);

    UnlockedVault v;
    v.header = h;
    v.vmk_envelope.assign(file.ptr + h.vmk_env_off,
                          file.ptr + h.vmk_env_off + h.vmk_env_len);
    v.vmk = static_cast<SecureBuffer&&>(vmk);
    v.prk = static_cast<SecureBuffer&&>(prk);
    v.canonical = static_cast<SecureBuffer&&>(canonical);
    v.kdf_arena_locked = kdf.arena_locked;
    return R::success(static_cast<UnlockedVault&&>(v));
}

Status seis_save(const std::string& path, UnlockedVault& v, ByteView canonical,
                 uint64_t now_unix, ByteView verify_password, SaveTarget target) {
    if (!crypto_init()) return status_fail(Err::Internal);
    const AeadProfile* ap = aead_profile_by_id(v.header.aead_profile_id);
    if (ap == nullptr || !aead_profile_available(ap->id))
        return status_fail(Err::FormatUnsupported);
    if (v.header.epoch == UINT64_MAX) return status_fail(Err::Internal);

    SeisHeader h = v.header;
    h.epoch += 1;
    Status fs = finalize_header(h, *ap, static_cast<uint32_t>(v.vmk_envelope.size()),
                                canonical.len, now_unix);
    if (!fs.ok()) return fs;

    // PRK depends only on (VMK, vault_id) — reuse across saves.
    Bytes file = seis_header_encode(h);
    Status bs = build_body(file, h, *ap, v.prk, v.vmk_envelope, canonical);
    if (!bs.ok()) return bs;
    // Never replace a good vault with an unopenable one: full decrypt-and-
    // compare of the assembled container before the atomic rename.
    Status vs = verify_assembled(ByteView(file), h, *ap, v.prk, canonical);
    if (!vs.ok()) return vs;
    // Key-rotation paths: prove the assembled image opens with the credential
    // it is supposed to (covers the envelope + KDF-from-password path that
    // verify_assembled cannot, since verify_assembled reuses the in-memory
    // PRK). A broken rotation can never lock the user out — the old file is
    // still intact here.
    if (!verify_password.empty()) {
        Result<UnlockedVault> chk = seis_unlock_bytes(ByteView(file), verify_password);
        if (!chk.ok()) return status_fail(Err::Internal);
        if (chk.value.canonical.size() != canonical.len ||
            (canonical.len > 0 && !chk.value.canonical.ct_equals(canonical)))
            return status_fail(Err::Internal);
    }
    // Last: is the file still the one this state was loaded from or last
    // wrote? (Another window or a sync tool may have saved over it.) The
    // replace lock, held from that check through the rename, keeps another
    // Secraxis process from saving in between: of two windows saving the
    // same state at once, one writes and the other sees the change.
    //
    // A vault reached through a symbolic link: the file it points to is
    // locked, checked and replaced. A rename over the link would replace the
    // link itself, leaving the real vault (in a synced folder, say) as it was.
    const std::string vault_file = target == SaveTarget::NewFile ? path : resolve_symlink(path);
    ReplaceLock lock;
    if (target != SaveTarget::NewFile) {
        Status ls = lock.acquire(vault_file, kReplaceLockWaitMs);
        if (!ls.ok()) return ls;
    }
    if (target == SaveTarget::Same) {
        Status cs = check_unchanged(vault_file, v.header);
        if (!cs.ok()) return cs;
    }
    if (target == SaveTarget::Overwrite) {
        Status rs = check_not_rekeyed(vault_file, v.header);
        if (!rs.ok()) return rs;
    }
    Status ws = target == SaveTarget::NewFile ? write_file_new(path, ByteView(file))
                                              : write_file_atomic(vault_file, ByteView(file));
    if (!ws.ok()) return ws;
    v.header = h;
    return status_ok();
}

Status seis_validate(const std::string& path, ByteView master_password) {
    if (!crypto_init()) return status_fail(Err::Internal);
    Result<Bytes> fr = read_file(path);
    if (!fr.ok()) return status_fail(fr.err);
    Result<SeisHeader> hr =
        seis_header_parse(ByteView(fr.value), fr.value.size());
    if (!hr.ok()) return status_fail(hr.err);
    const SeisHeader& h = hr.value;
    const AeadProfile* ap = aead_profile_by_id(h.aead_profile_id);
    const KdfProfile* kp = kdf_profile_by_id(h.kdf_profile_id);
    if (ap == nullptr || kp == nullptr) return status_fail(Err::AuthGeneric);
    KdfOutcome kdf = derive_kek_material(
        master_password, ByteView(h.kdf_salt, KDF_SALT_LEN), *kp);
    if (!kdf.ok()) return status_fail(kdf.err);
    ByteView env(fr.value.data() + h.vmk_env_off, h.vmk_env_len);
    Result<SecureBuffer> vr =
        vmk_envelope_open(h, *ap, kdf.kek_material.view(), env);
    kdf.kek_material.reset();
    if (!vr.ok()) return status_fail(Err::AuthGeneric);
    SecureBuffer prk = vmk_prk(vr.value, h);
    vr.value.reset();
    if (!prk.valid()) return status_fail(Err::AllocationFailed);
    SecureBuffer canonical;
    Status ob = open_body(ByteView(fr.value), h, *ap, prk, &canonical);
    canonical.reset();
    if (!ob.ok()) return status_fail(Err::AuthGeneric);
    return status_ok();
}

}  // namespace secraxis
