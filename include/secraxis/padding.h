// padding.h — length-bucket padding (agenda §11; policy "vault-bucket-v1").
//
// Buckets: 64K 128K 256K 512K 1M 2M 4M 8M, then next multiple of 4 MiB.
// Padding bytes are OS-CSPRNG (never zeros). The true canonical length is
// stored ONLY inside the encrypted, authenticated manifest. All bucket sizes
// are multiples of 16 (A2ONT input requirement).
#ifndef SECRAXIS_PADDING_H
#define SECRAXIS_PADDING_H

#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"

namespace secraxis {

// Smallest bucket >= n. 0 on overflow/absurd sizes (> 256 MiB cap).
uint64_t padding_bucket_for(uint64_t canonical_len) noexcept;

// canonical || CSPRNG-fill, in secure memory. Empty buffer on failure.
Result<SecureBuffer> pad_to_bucket(ByteView canonical, uint64_t padded_len);

}  // namespace secraxis

#endif  // SECRAXIS_PADDING_H
