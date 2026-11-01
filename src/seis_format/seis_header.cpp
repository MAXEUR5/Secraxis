#include "secraxis/seis_format.h"

#include <cstring>

#include "secraxis/aead.h"

namespace secraxis {

namespace {

// CRC-32 (IEEE, reflected). Accidental-corruption check only — no security
// role (that is the AEAD's job); implemented locally to keep it out of the
// crypto dependency surface.
uint32_t crc32_ieee(ByteView data) noexcept {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < data.len; ++i)
        c = table[(c ^ data.ptr[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// Field offsets inside the fixed 256-byte header. A single table keeps
// encode, parse, and the AAD builders in exact agreement.
enum : size_t {
    OFF_MAGIC = 0,             // 4
    OFF_VERSION = 4,           // 2
    OFF_HEADER_LEN = 6,        // 2  (= SEIS_HEADER_SIZE)
    OFF_VAULT_ID = 8,          // 16
    OFF_CREATED = 24,          // 8
    OFF_KDF_ID = 32,           // 4
    OFF_KDF_MEM = 36,          // 4
    OFF_KDF_ITER = 40,         // 4
    OFF_KDF_LANES = 44,        // 4
    OFF_KDF_SALT = 48,         // 32
    OFF_AEAD_ID = 80,          // 4
    OFF_A2ONT_ID = 84,         // 4
    OFF_PAD_ID = 88,           // 4
    OFF_CANON_VER = 92,        // 4
    IMMUTABLE_END = 96,        // [0, 96) is the immutable block
    OFF_UPDATED = 96,          // 8
    OFF_EPOCH = 104,           // 8
    OFF_SAVE_SALT = 112,       // 32
    OFF_PAGE_SIZE = 144,       // 4
    OFF_PAGE_COUNT = 148,      // 4
    OFF_VMK_OFF = 152,         // 8
    OFF_VMK_LEN = 160,         // 4
    OFF_MANIFEST_OFF = 164,    // 8
    OFF_MANIFEST_LEN = 172,    // 4
    OFF_PAGES_OFF = 176,       // 8
    OFF_PAGES_LEN = 184,       // 8
    OFF_RESERVED = 192,        // 60 (zero in v1; parser requires zero)
    OFF_CRC = 252,             // 4
};
static_assert(OFF_CRC + 4 == SEIS_HEADER_SIZE, "header layout must be 256 B");

}  // namespace

Bytes seis_header_encode(const SeisHeader& h) {
    Bytes b(SEIS_HEADER_SIZE, 0);
    std::memcpy(b.data() + OFF_MAGIC, SEIS_MAGIC, 4);
    store_le16(b.data() + OFF_VERSION, h.format_version);
    store_le16(b.data() + OFF_HEADER_LEN, static_cast<uint16_t>(SEIS_HEADER_SIZE));
    std::memcpy(b.data() + OFF_VAULT_ID, h.vault_id, VAULT_ID_LEN);
    store_le64(b.data() + OFF_CREATED, h.created_at);
    store_le32(b.data() + OFF_KDF_ID, h.kdf_profile_id);
    store_le32(b.data() + OFF_KDF_MEM, h.kdf_memory_mib);
    store_le32(b.data() + OFF_KDF_ITER, h.kdf_iterations);
    store_le32(b.data() + OFF_KDF_LANES, h.kdf_lanes);
    std::memcpy(b.data() + OFF_KDF_SALT, h.kdf_salt, KDF_SALT_LEN);
    store_le32(b.data() + OFF_AEAD_ID, h.aead_profile_id);
    store_le32(b.data() + OFF_A2ONT_ID, h.a2ont_profile_id);
    store_le32(b.data() + OFF_PAD_ID, h.padding_policy_id);
    store_le32(b.data() + OFF_CANON_VER, h.canonical_version);
    store_le64(b.data() + OFF_UPDATED, h.updated_at);
    store_le64(b.data() + OFF_EPOCH, h.epoch);
    std::memcpy(b.data() + OFF_SAVE_SALT, h.save_salt, 32);
    store_le32(b.data() + OFF_PAGE_SIZE, h.page_size);
    store_le32(b.data() + OFF_PAGE_COUNT, h.page_count);
    store_le64(b.data() + OFF_VMK_OFF, h.vmk_env_off);
    store_le32(b.data() + OFF_VMK_LEN, h.vmk_env_len);
    store_le64(b.data() + OFF_MANIFEST_OFF, h.manifest_off);
    store_le32(b.data() + OFF_MANIFEST_LEN, h.manifest_len);
    store_le64(b.data() + OFF_PAGES_OFF, h.pages_off);
    store_le64(b.data() + OFF_PAGES_LEN, h.pages_len);
    // reserved [192,252) stays zero
    store_le32(b.data() + OFF_CRC,
               crc32_ieee(ByteView(b.data(), OFF_CRC)));
    return b;
}

Result<SeisHeader> seis_header_parse(ByteView raw, uint64_t file_size) {
    using R = Result<SeisHeader>;
    if (raw.len < SEIS_HEADER_SIZE) return R::failure(Err::FormatUnsupported);
    const uint8_t* p = raw.ptr;

    if (std::memcmp(p + OFF_MAGIC, SEIS_MAGIC, 4) != 0)
        return R::failure(Err::FormatUnsupported);
    if (load_le16(p + OFF_VERSION) != SEIS_FORMAT_VERSION)
        return R::failure(Err::FormatUnsupported);
    if (load_le16(p + OFF_HEADER_LEN) != SEIS_HEADER_SIZE)
        return R::failure(Err::FormatUnsupported);

    // Accidental-corruption check; deliberate tampering is caught by AEAD.
    if (load_le32(p + OFF_CRC) != crc32_ieee(ByteView(p, OFF_CRC)))
        return R::failure(Err::AuthGeneric);

    SeisHeader h;
    h.format_version = load_le16(p + OFF_VERSION);
    std::memcpy(h.vault_id, p + OFF_VAULT_ID, VAULT_ID_LEN);
    h.created_at = load_le64(p + OFF_CREATED);
    h.kdf_profile_id = load_le32(p + OFF_KDF_ID);
    h.kdf_memory_mib = load_le32(p + OFF_KDF_MEM);
    h.kdf_iterations = load_le32(p + OFF_KDF_ITER);
    h.kdf_lanes = load_le32(p + OFF_KDF_LANES);
    std::memcpy(h.kdf_salt, p + OFF_KDF_SALT, KDF_SALT_LEN);
    h.aead_profile_id = load_le32(p + OFF_AEAD_ID);
    h.a2ont_profile_id = load_le32(p + OFF_A2ONT_ID);
    h.padding_policy_id = load_le32(p + OFF_PAD_ID);
    h.canonical_version = load_le32(p + OFF_CANON_VER);
    h.updated_at = load_le64(p + OFF_UPDATED);
    h.epoch = load_le64(p + OFF_EPOCH);
    std::memcpy(h.save_salt, p + OFF_SAVE_SALT, 32);
    h.page_size = load_le32(p + OFF_PAGE_SIZE);
    h.page_count = load_le32(p + OFF_PAGE_COUNT);
    h.vmk_env_off = load_le64(p + OFF_VMK_OFF);
    h.vmk_env_len = load_le32(p + OFF_VMK_LEN);
    h.manifest_off = load_le64(p + OFF_MANIFEST_OFF);
    h.manifest_len = load_le32(p + OFF_MANIFEST_LEN);
    h.pages_off = load_le64(p + OFF_PAGES_OFF);
    h.pages_len = load_le64(p + OFF_PAGES_LEN);

    // Reserved bytes must be zero in v1 (no covert downgrade channel).
    for (size_t i = OFF_RESERVED; i < OFF_CRC; ++i)
        if (p[i] != 0) return R::failure(Err::AuthGeneric);

    // --- profile validation: registered IDs only; no downgrade below floor.
    const KdfProfile* kp = kdf_profile_by_id(h.kdf_profile_id);
    if (kp == nullptr) return R::failure(Err::AuthGeneric);
    // Parameters must match the registered profile EXACTLY: the file cannot
    // smuggle weaker parameters under a strong profile id or vice versa.
    if (h.kdf_memory_mib != kp->memory_mib ||
        h.kdf_iterations != kp->iterations || h.kdf_lanes != kp->lanes)
        return R::failure(Err::AuthGeneric);
    const AeadProfile* ap = aead_profile_by_id(h.aead_profile_id);
    if (ap == nullptr) return R::failure(Err::AuthGeneric);
    if (!aead_profile_available(ap->id))
        return R::failure(Err::FormatUnsupported);  // honest: build lacks it
    if (h.a2ont_profile_id != static_cast<uint32_t>(A2ontProfileId::Default) &&
        h.a2ont_profile_id != static_cast<uint32_t>(A2ontProfileId::Strong))
        return R::failure(Err::AuthGeneric);
    if (h.padding_policy_id != static_cast<uint32_t>(PaddingPolicyId::BucketV1))
        return R::failure(Err::AuthGeneric);
    if (h.canonical_version != CANONICAL_VERSION)
        return R::failure(Err::AuthGeneric);
    if (h.page_size != SEIS_PAGE_SIZE) return R::failure(Err::AuthGeneric);
    if (h.page_count == 0 || h.page_count > MANIFEST_MAX_PAGES)
        return R::failure(Err::AuthGeneric);
    if (h.epoch == 0) return R::failure(Err::AuthGeneric);

    // --- region sanity: ordered, non-overlapping, in-bounds, exact-fit.
    const uint64_t hs = SEIS_HEADER_SIZE;
    if (h.vmk_env_off != hs) return R::failure(Err::AuthGeneric);
    if (h.vmk_env_len == 0 || h.vmk_env_len > 4096)
        return R::failure(Err::AuthGeneric);
    if (h.manifest_off != h.vmk_env_off + h.vmk_env_len)
        return R::failure(Err::AuthGeneric);
    if (h.manifest_len < MANIFEST_FIXED_LEN + AEAD_TAG_LEN ||
        h.manifest_len > (1u << 20))
        return R::failure(Err::AuthGeneric);
    if (h.pages_off != h.manifest_off + h.manifest_len)
        return R::failure(Err::AuthGeneric);
    if (h.pages_len == 0 ||
        h.pages_len > static_cast<uint64_t>(MANIFEST_MAX_PAGES) *
                          (static_cast<uint64_t>(SEIS_PAGE_SIZE) + AEAD_TAG_LEN))
        return R::failure(Err::AuthGeneric);
    if (h.pages_off + h.pages_len != file_size)
        return R::failure(Err::AuthGeneric);

    return R::success(h);
}

Bytes seis_aad_immutable(const SeisHeader& h) {
    // Serialized immutable block, domain-tagged. Built from the struct (not
    // raw file bytes) so create and parse paths agree by construction.
    Bytes b;
    b.reserve(IMMUTABLE_END + 16);
    append_lp(b, label("seis-aad-immutable-v1"));
    Bytes full = seis_header_encode(h);
    append_bytes(b, ByteView(full.data(), IMMUTABLE_END));
    return b;
}

Bytes seis_aad_full(const SeisHeader& h) {
    Bytes b;
    b.reserve(SEIS_HEADER_SIZE + 24);
    append_lp(b, label("seis-aad-full-v1"));
    Bytes full = seis_header_encode(h);
    // CRC excluded (zeroed) so AAD does not depend on the checksum field.
    store_le32(full.data() + OFF_CRC, 0);
    append_bytes(b, ByteView(full.data(), full.size()));
    return b;
}

}  // namespace secraxis
