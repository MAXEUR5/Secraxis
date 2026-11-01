#include "secraxis/padding.h"

#include <cstring>

#include "secraxis/crypto.h"

namespace secraxis {

uint64_t padding_bucket_for(uint64_t canonical_len) noexcept {
    static const uint64_t kBuckets[] = {
        64ull << 10, 128ull << 10, 256ull << 10, 512ull << 10,
        1ull << 20,  2ull << 20,   4ull << 20,   8ull << 20,
    };
    constexpr uint64_t kCap = 256ull << 20;  // matches MANIFEST_MAX_PAGES
    if (canonical_len > kCap) return 0;
    for (uint64_t b : kBuckets)
        if (canonical_len <= b) return b;
    // Above 8 MiB: next multiple of 4 MiB.
    const uint64_t step = 4ull << 20;
    uint64_t r = ((canonical_len + step - 1) / step) * step;
    return (r > kCap) ? 0 : r;
}

Result<SecureBuffer> pad_to_bucket(ByteView canonical, uint64_t padded_len) {
    using R = Result<SecureBuffer>;
    if (padded_len < canonical.len || padded_len % 16 != 0)
        return R::failure(Err::InvalidArgument);
    SecureBuffer out = SecureBuffer::alloc(static_cast<size_t>(padded_len));
    if (!out.valid()) return R::failure(Err::AllocationFailed);
    if (canonical.len > 0)
        std::memcpy(out.data(), canonical.ptr, canonical.len);
    const size_t fill = static_cast<size_t>(padded_len) - canonical.len;
    if (fill > 0 && !random_bytes(out.data() + canonical.len, fill))
        return R::failure(Err::RngFailed);
    return R::success(static_cast<SecureBuffer&&>(out));
}

}  // namespace secraxis
