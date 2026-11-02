# `.seis` File Format (v1)

Authoritative description of the Secraxis Vault Manager container.
Implemented by `src/seis_format/seis_header.cpp` and `seis_container.cpp`;
exercised by `tests/unit/test_seis_phase2.cpp` and fuzzed by `fuzz_header`.
The exact byte encodings of the HKDF inputs and AAD domain tags (length
prefixes, integer widths) are defined by `src/crypto/key_hierarchy.cpp` and
`src/seis_format/seis_container.cpp`; this document gives their structure.

All multi-byte integers are **little-endian**. The file is:

```
[ SeisHeader     ]  256 bytes, fixed, public, CRC32-tailed
[ VMK envelope   ]  AEAD(KEK_wrap_key): VMK_512 + metadata
[ EncryptedManifest ] AEAD(manifest_key): page table + lengths + welds
[ EncryptedPages ]  page_i = AEAD(page_key_i): the A2ONT container, chunked
```

There is no plaintext anywhere after the 256-byte public header. A probe test
(`no_plaintext_or_transform_markers_on_disk`) asserts the file contains no
A2ONT magic, no canonical-codec magic, and no planted plaintext.

## 1. Public header (256 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic `"SEIS"` | |
| 4 | 2 | format_version | must be 1 |
| 6 | 2 | header_length | must be 256 |
| 8 | 16 | vault_id | random per vault, non-secret |
| 24 | 8 | created_at | unix seconds, informational |
| 32 | 4 | kdf_profile_id | 1/2/3; must match a registered profile |
| 36 | 4 | kdf_memory_mib | must equal the profile's value exactly |
| 40 | 4 | kdf_iterations | must equal the profile's value exactly |
| 44 | 4 | kdf_lanes | must equal the profile's value exactly |
| 48 | 32 | kdf_salt | random |
| 80 | 4 | aead_profile_id | 1=XChaCha20-Poly1305, 2=AES-256-GCM-SIV |
| 84 | 4 | a2ont_profile_id | 1=default, 2=strong |
| 88 | 4 | padding_policy_id | 1=bucket-v1 |
| 92 | 4 | canonical_version | 1 (see §8: the contents carry their own revision) |
| 96 | 8 | updated_at | unix seconds |
| 104 | 8 | epoch | strictly increasing across saves; ≥1 |
| 112 | 32 | save_salt | fresh CSPRNG per save (nonce hygiene) |
| 144 | 4 | page_size | 65536 in v1 |
| 148 | 4 | page_count | 1..4096 |
| 152 | 8 | vmk_env_off | = 256 |
| 160 | 4 | vmk_env_len | ≤ 4096 |
| 164 | 8 | manifest_off | = vmk_env_off + vmk_env_len |
| 172 | 4 | manifest_len | |
| 176 | 8 | pages_off | = manifest_off + manifest_len |
| 184 | 8 | pages_len | pages_off+pages_len must equal file size |
| 192 | 60 | reserved | must be all-zero in v1 |
| 252 | 4 | header_crc32 | IEEE CRC over bytes [0,252); accident check only |

Bytes [0, 96) are the **immutable block**: the identity + KDF + profile fields
that only change when the master password is present. The parser
(`seis_header_parse`) is strict: unknown/mismatched profile IDs, KDF
parameters other than the registered profile's, wrong page size, zero epoch,
non-zero reserved bytes, and any region that is misordered / overlapping /
out-of-bounds all fail. The CRC is only an early check for accidental
corruption (nothing logs it); **all security decisions rest on the AEAD
tags**, and both CRC failure and AEAD failure surface as the same generic
error.

## 2. Authentication model (AAD)

- **AAD_immutable** = domain-tag ‖ header bytes [0,96). Used as AEAD AAD for
  the **VMK envelope**, which is only rewritten when the KEK is available
  (create / change-password / rekey / KDF upgrade).
- **AAD_full** = domain-tag ‖ full 256-byte header with the CRC field zeroed.
  The **manifest**'s AAD is AAD_full ‖ "seis-manifest-region-v1" (rewritten
  every save).
- **Pages**: AAD = AAD_full ‖ "seis-page-v1" ‖ page_index ‖ page_count ‖
  body_len. Every page is welded to this exact save.
- **Cross-region welds**: the manifest plaintext carries the VMK envelope's
  AEAD tag, and one copy of each page's AEAD tag. Mixing regions from
  different files/saves fails authentication.

Downgrade/rollback resistance: because every crypto-affecting header field is
in one of the two AAD blobs, flipping any of them (KDF/AEAD/A2ONT profile,
epoch, salt, page geometry, offsets) breaks the relevant AEAD tag. Whole-file
rollback to an *older internally-consistent* vault is not detectable without
external state — documented in `THREAT_MODEL.md`.

## 3. VMK envelope

Plaintext (96 bytes): `VMK(64) ‖ vmk_version(8) ‖ vmk_created_at(8) ‖
vault_id(16)`. Ciphertext: `nonce(profile) ‖ AEAD_seal`.
The wrap key is `HKDF-SHA512(salt=kdf_salt, ikm=KEK_512, info="seis-vmk-wrap-v1"
‖ version ‖ vault_id ‖ kdf_profile_id ‖ aead_profile_id)` truncated to 32
bytes.

## 4. Manifest plaintext

```
u32 manifest_version (=1)
u8  vmk_envelope_tag[16]      (weld to the envelope)
u64 canonical_len            (true plaintext length, pre-padding)
u64 padded_len               (bucket size)
u64 a2ont_out_len            (page body length = a2ont header + L + 32)
u32 entry_count_bucket       (always 0 in v1; not read)
u32 page_count
{ u32 ct_len; u8 tag[16] } × page_count
```

The manifest is decrypted, then parsed **strictly**: version, envelope-tag
weld, `padded_len == bucket(canonical_len)`, `a2ont_out_len` consistency and
the page_count match are checked before any page is opened; each page's
`ct_len` is checked against the remaining pages region just before that page
is opened, and the pages must end exactly at the end of the region.

## 5. Pages

The A2ONT container (`a2ont_header ‖ Y ‖ Y_extra`) is split into 64 KiB
chunks; each chunk is `AEAD_seal(page_key_i, nonce_i, chunk, page_aad_i)`.
`page_key_i` and `nonce_i` are `HKDF-SHA512(PRK, label ‖ format_version ‖
vault_id ‖ epoch ‖ save_salt ‖ page_index)` — unique per (vault, save, page).

## 6. Save pipeline (crash-safe)

0. Unless this is a key change (`passwd`, `rekey`, `upgrade`), a session
   whose vault file now holds other keys writes nothing, anywhere:
   `VaultRekeyed` (`VaultSession::save_to`, before anything is built).
   Another vault id is a different file; the same id with another KDF salt
   or profile means the password or keys were changed elsewhere.
1. epoch+1 and a fresh save_salt (both enter the A2ONT context and every
   derived key and nonce).
2. Serialize the canonical vault (secure buffer) and pad it to the bucket
   with random bytes (both random sources, `CRYPTO_PROFILES.md` §5).
3. A2ONT with a **fresh seed**.
4. Derive fresh page keys/nonces; AEAD each page.
5. Build the manifest, AEAD it; assemble the full file image in memory.
6. **verify_assembled**: fully decrypt the in-memory image and byte-compare to
   the canonical input — a transform/encode bug can never produce an
   unopenable file that replaces a good one. Key changes (`passwd`,
   `rekey`, `upgrade`) also unlock the assembled image from the password.
7. If the vault path is a symbolic link, the file it points to is the one
   locked, checked and replaced from here on (a rename over the link would
   replace the link itself and leave the real vault as it was). Take the
   replace lock (`ReplaceLock`: POSIX `flock` on the vault file; Windows an
   exclusive, delete-on-close `<name>.lock` beside it), held through step
   9, so another Secraxis process saving the same file waits (at most 3 s,
   then `IoWrite`, nothing written). For an ordinary save, check that the
   file on disk is still the save this state describes (vault id, epoch and
   `save_salt` from its header); if another program saved over it, stop
   with `VaultChanged`: nothing is written. A missing file is fine. For an
   overwrite the user chose (after `VaultChanged`), check step 0's
   condition again here, so a key change that finished in the meantime is
   never undone. A copy to a new file takes no lock and never replaces a
   file.
8. Write to a temp file in the same directory, flush, fsync.
9. Atomic rename over the target; fsync the directory (POSIX). Creating a
   vault never replaces a file (`MoveFileEx` without `REPLACE_EXISTING`;
   `link()` on POSIX, and where the file system has no hard links, such as
   FAT, a check and then a rename: a narrow race at worst), and never uses
   an empty master password (refused, `InvalidArgument`); it checks that the
   envelope it just sealed opens with the KEK before writing.

The old file is never partially overwritten: a crash at any point leaves the
old valid file or the new one (tested by killing a saving process at random
moments: 1000 times on Linux, 400 on Windows, no acknowledged save lost and
no torn vault). A crash between the temp file and the rename also leaves
that temp file (`<name>.tmp-` and 16 hex digits): a whole copy, openable
with the master password it had then. The next write of the same file
removes such leftovers before writing its own (under the replace lock, so
no other save's temporary file can be among them).

## 7. Unlock pipeline (verify-before-parse)

Header parse → Argon2id → KEK → **AEAD-open VMK envelope** → derive PRK →
**AEAD-open manifest**, parse strictly → **AEAD-open every page** (verify tag
+ manifest weld) → reassemble → A2ONT inverse → remove padding → canonical
parse → seal into the runtime store → wipe the canonical buffer. No structure
behind an AEAD tag is parsed before that tag verifies. Every failure after the
header collapses to the generic `Wrong password or corrupted vault.`; only
running out of secure memory, or a missing or failed RDSEED (refused before
the KDF: opening seals every entry under fresh random keys and nonces), is
reported as such, and neither says anything about the password. Header failures that come before the KDF (an unknown magic or
format version, an AEAD profile this build cannot run) are refused as
unsupported; the screen shows the same generic message for them.

The one other exception is a vault a **newer** Secraxis wrote (§8): once the
envelope and the manifest have authenticated, a manifest version above 1, or
contents in a later revision, is reported as `Err::NewerFormat` ("This vault
was saved by a newer version of Secraxis. Update Secraxis to open it.").
It cannot be reached without the right password: a wrong password, or any
tampering, fails an AEAD tag first and stays the generic error.

## 8. Contents (SEIS-CANON)

The bytes A2ONT reshapes and the pages carry are the vault's entries in one
exact byte form. `src/seis_format/canonical_codec.cpp` defines it:

```
u32 magic "SXC1" or "SXC2" (the revision) | u32 entry_count
per entry, in strictly ascending entry_id order, each id once:
  u8 entry_id[16] | u64 created_at | u64 updated_at | u32 field_bytes
  fields: { u16 field_id | u32 len | bytes } in strictly ascending id order
```

| Id | Field | Revision | Notes |
|---|---|---|---|
| 1 | Name | v1 | |
| 2 | Remark | v1 | |
| 3 | Username | v1 | |
| 4 | URL | v1 | |
| 5 | Tags | v1 | |
| 6 | Password length bucket | v1 | 1 byte, 0..5; in every entry |
| 7 | Color | v2 | 1 byte, 1..8 (Red, Amber, Green, Teal, Blue, Violet, Pink, Grey); absent = Auto |
| 32 | Password | v1 | secret |
| 33 | TOTP secret | v1 | secret |
| 34 | Recovery codes | v1 | secret |
| 35 | Secret note | v1 | secret |

Ids below 32 are metadata, 32 and up secrets; within an entry every
metadata field precedes every secret. Absent fields are omitted (no field is
ever empty), each field has a fixed maximum length, and there is
exactly one valid encoding: anything out of order, duplicated, too long,
unknown or left over is rejected.

**Revisions.** SEIS-CANON-v1 (`SXC1`) is what 0.9.1 and 0.9.2 write.
SEIS-CANON-v2 (`SXC2`, from 0.9.3) is v1 plus field 7. Each revision
rejects the fields it does not define, so v1 contents with a Color are not
valid, and Color 0 or above 8 is not valid either. 0.9.3 reads both and
**always writes v2**: a vault from 0.9.2 or earlier is upgraded on its first
save, after which those versions refuse it (with their generic message: they
know no other). A later revision (`SXC3` to `SXC9`) is `NewerFormat`; any
other magic is the generic error. The header's `canonical_version` stays 1
in every revision: it lies in the immutable block that the VMK envelope
authenticates (§2), which an ordinary save does not rewrite.
