# Secraxis Vault Manager — Entry Mutation Lifecycle (normative)

This document is the formal CRUD contract for vault entries. It complements
`SEIS_FORMAT.md` (the at-rest container) and `RUNTIME_MEMORY_SECURITY.md`
(memory handling): the container layer defines *how bytes are protected*;
this document defines *how the live entry set may change* and what every
mutation guarantees. The enforcing implementation is `VaultSession`
(`include/secraxis/vault_session.h`) — the only layer the TUI is allowed to
call for mutations; tests in `tests/unit/test_vault_session.cpp` exercise
every clause below.

## 0. Session states and the dirty flag

```
   [Locked] --unlock/create--> [Clean] --add/modify/delete--> [Dirty]
       ^                          |  ^                            |
       |                          |  +---------- save ------------+
       +---------- lock ----------+--------------------------------
```

* `Clean`: the runtime entry set is byte-equivalent to the `.seis` file on
  disk (canonical re-serialization would be identical).
* `Dirty`: at least one mutation has not been persisted. The TUI must render
  the dirty indicator and must warn on lock/exit while dirty.
* Mutations NEVER touch the `.seis` file directly; only `save()` does.
  A crash while `Dirty` loses unsaved mutations but can never corrupt the
  on-disk vault (atomic save; the previous file remains valid).

## 1. Add entry

Contract of `VaultSession::add_entry(record, now)`:

1. Validation: field lengths are enforced against the canonical caps
   (`field_max_len`), and the color must be one the format defines (0 for
   Auto, or 1..`ENTRY_COLORS`, from 0.9.3); anything else is refused with
   `InvalidArgument`, nothing added. `add_entry` itself accepts an empty password (an
   import can carry one); the TUI refuses one for a new entry ("Password
   must not be empty."). An empty password is visible as password-length
   bucket 0.
2. `entry_id` = 16 bytes from the OS CSPRNG, regenerated until unique within
   the vault (collision is astronomically unlikely; the check is cheap).
3. `created_at = updated_at = now`.
4. `pw_bucket` is COMPUTED from the password length
   (`password_length_bucket`); any caller-supplied value is overwritten.
   The exact length is never stored anywhere (agenda §9.2).
5. The record is sealed into the runtime store (metadata segment and secret
   segment separately, fresh per-entry keys at reseal-epoch 1).
6. The caller's plaintext record is WIPED by the API (metadata byte vectors
   zeroized, secret buffers destroyed) — add consumes its argument.
7. The vault is marked `Dirty`.

## 2. Modify entry

Contract of `VaultSession::modify_entry(index, record, now)`:

1. The target slot must exist; `entry_id` and `created_at` are preserved
   from the existing entry (the caller cannot forge identity or history).
   The record is validated as in Add (from 0.9.3; before, an over-long
   field was only refused by the next save): `InvalidArgument`, the entry
   unchanged, the record still wiped.
2. `updated_at = now`; `pw_bucket` recomputed as in Add.
3. The runtime store replaces the sealed segments under `reseal_epoch + 1`
   (fresh keys, fresh buffers); the OLD sealed segments are wiped and freed
   (moving-target property extends to edits).
4. The caller's plaintext record is WIPED by the API (as in Add). Old secret
   plaintext held by the TUI (e.g. the pre-edit password in an input buffer)
   must be in `SecureBuffer`s, which the TUI destroys on field commit — no
   long-lived old-password copies survive an edit (agenda §15.4).
5. Vault marked `Dirty`.
6. `modify_entry` replaces the whole record. A caller that edits only some
   fields must carry the others over: the TUI's form shows the metadata
   (the color included) and the password only, so an edit takes the entry's other secrets (TOTP seed,
   recovery codes, secret note) from the stored entry, whether or not the
   password changes (`editing_the_password_keeps_the_other_secrets`). A
   secret that cannot be copied into secure memory fails the edit; the entry
   is never stored without it.

## 3. Delete entry

Contract of `VaultSession::delete_entry(index, confirmed)`:

1. **Confirmation is enforced at the API**, not just in the UI: the call
   fails with `Err::Canceled` and changes nothing unless `confirmed == true`.
   The TUI may only set `confirmed` from the `DeleteConfirm` state.
2. On confirmation, the entry is removed from the live model: both sealed
   segments (metadata + secret) are wiped and their guarded allocations
   freed; the slot disappears from all listings and handles immediately.
3. Any open scratch buffers for that entry (a revealed password, an open
   edit record) are independently owned `SecureBuffer`s and are destroyed by
   their owners; the TUI must leave `RevealSecret`/`EditEntry` state for the
   deleted entry before or upon deletion (state machine rule, tested in the
   TUI suite).
4. Indexes/caches: **Secraxis maintains no persistent search index or query
   cache by design** — `query()` recomputes over the sealed store every
   time, so there is nothing stale to invalidate after a delete. If a cache
   is ever introduced, it must be invalidated on every mutation and treated
   as metadata-sensitive memory (wiped, non-dumpable). This is a standing
   design constraint.
5. Vault marked `Dirty`. The entry stops existing in the NEXT saved `.seis`
   file: the save pipeline re-serializes the canonical vault from the live
   store only (there is no incremental page reuse — every save re-pads,
   re-A2ONTs with a fresh seed, and re-encrypts everything under a new
   epoch + save_salt), so no trace of the deleted entry's ciphertext
   survives in the new file.
6. Deletion does NOT save (no mutation touches the file). The TUI shows
   dirty state; an explicit save persists the removal, and locking with
   unsaved changes asks (save, discard, cancel). Rationale: destructive
   operations remain reversible until the user commits. Only if the user
   chose "Save changes: automatically" (TUI Settings) does the TUI save
   right after the confirmed delete; the confirmation is then the commit.

### 3.1 Honest deletion boundary (what delete does NOT do)

Deleting an entry (and saving) guarantees removal from the live model and
from the newly written `.seis` file. It does **not** and cannot guarantee
erasure of:

* previous versions of the vault file retained by filesystem snapshots
  (VSS, btrfs/ZFS snapshots, APFS), journaling, or copy-on-write remnants;
* backups, file-history services, or sync copies (cloud drives, rsync
  targets) made while the entry existed;
* the freed disk blocks of earlier atomic-save generations (the old file is
  replaced by rename; its blocks are not scrubbed — SSD wear leveling makes
  in-place scrubbing unreliable anyway);
* swapped or hibernated memory pages from past sessions: memory locking is
  best-effort (secure memory past the system's lock limit is not locked),
  and hibernation writes even locked pages to disk;
* copies the user exported (including plaintext exports) or put on the
  clipboard before the TTL cleared.

Old copies of the vault file remain protected by the encryption they were
written with (AEAD under the then-current keys). Plaintext exports, clipboard
contents and swapped or hibernated memory have no such protection.
If an entry's secret is believed compromised, the correct response is to
rotate the real-world credential, not merely delete the entry; if the master
password is compromised, change it (`passwd`) and rekey the vault (`rekey`,
a fresh VMK: `passwd` alone keeps the VMK, which anyone who opened an old
copy with the leaked password already holds, and `rekey` alone keeps the
password), and treat old file copies as crackable-by-that-password. This
boundary is restated in `THREAT_MODEL.md`.

## 4. Save behavior

`VaultSession::save(now)`:

1. Re-serializes the canonical vault from the runtime store (decrypting all
   entries into short-lived scratch at once, canonical order by `entry_id`;
   so a save needs more secure memory than an open vault: on Linux about 12
   memory maps per entry, 15 with a TOTP secret, against 8 when open).
2. Runs the full save pipeline: epoch+1 + fresh `save_salt` → bucket
   padding (fresh CSPRNG fill) → A2ONT (fresh seed) → fresh page
   keys/nonces → AEAD → temp file → flush → atomic rename (agenda §8.7;
   `SEIS_FORMAT.md` §6).
3. Wipes the canonical scratch, then clears `Dirty`.
4. Post-save, all runtime entries are RESEALED (moving-target trigger
   "after save", agenda §12.4) so runtime keys do not outlive the save
   boundary. If that reseal fails (no secure memory left), the file is
   already written and `Dirty` cleared, but the error is still returned.
5. On any failure before the rename the on-disk file is untouched (the
   previous version stays valid) and the session remains `Dirty`.

`save()` writes only over the save it knows. Before the rename it checks
that the file is still the save the session loaded or last wrote (vault id,
epoch and per-save salt from its header). If another window or a sync tool
saved over it, nothing is written and the result is `Err::VaultChanged`
(still `Dirty`). The caller then lets the user choose:

- `save_copy(new_path, now)`: a file that must not exist yet (`Err::Exists`
  otherwise); on success the session continues in it, and both versions
  survive.
- `save_overwrite(now)`: replace what the other side saved.

A vault file that is gone is written again. These errors come only after a
successful unlock; the unlock path keeps its single generic failure.

All three calls (`save`, `save_copy`, `save_overwrite`) return
`Err::VaultRekeyed` and write nothing when the vault file holds this vault
with other keys (`passwd`, `rekey` or `upgrade` ran elsewhere): writing this
session's keys anywhere would bring the old password back. For
`save_overwrite` the check runs again under the replace lock, so a key change
that finished meanwhile is not undone.

The check and the rename happen under a replace lock (`ReplaceLock`,
fs_atomic.h) that other Secraxis processes honor: POSIX `flock()` on the
vault file itself, Windows an exclusive `<name>.lock` beside it, deleted
with its holder. Of two windows saving the same state at the same moment,
exactly one writes and the other gets `Err::VaultChanged`; without the lock,
both could pass the check before either renamed, and one window's reported save
would silently vanish (measured: 2 to 4 of 4 simultaneous saves "succeeded"
in every round on Windows, in half the rounds on Linux). A save waits at
most 3 s for another one (`Err::IoWrite` after that, nothing written). A
sync tool does not take the lock; the check still catches what it puts in
place, except between the check and the rename.

The TUI saves through the same calls by itself only where the user's
settings say so (TUI_SPEC, Settings): after each change ("save changes
automatically"), and with nobody there to ask (the idle lock, the terminal
going away; "save" by default, or "discard").

## 5. Runtime resealing triggers

The moving-target mechanism re-encrypts sealed segments under fresh keys in
fresh allocations and wipes the old ones. Triggers implemented in
`VaultSession`:

| Trigger | Mechanism |
|---|---|
| entry access count | every `ACCESS_RESEAL_THRESHOLD` (4) secret opens auto-reseals that entry |
| after secret reveal / copy | TUI calls `note_secret_exposure(index)` → reseal |
| after edit | `replace_entry` reseals by construction (`reseal_epoch` + 1) |
| after save | `save()` reseals all entries |
| manual refresh | `reseal_all()` bound to a TUI command |
| time interval | the TUI calls `reseal_all()` every 60 s while a vault is open |

Honest scope: resealing reduces stable-address exposure and secret density
in process memory. It does not defeat a malicious kernel, DMA, or code
already inside the process.

## 6. Wiping discipline for mutation paths

* Every secret plaintext involved in a mutation lives in `SecureBuffer`
  (guarded allocation, wipe-on-destroy). Metadata plaintext in mutation
  scratch is zeroized explicitly before the buffers are released.
* Mutation APIs CONSUME their input record and wipe it — callers cannot
  accidentally keep a live copy after the call returns.
* `lock()` destroys, in order: runtime store (all sealed segments), PRK,
  VMK, and any session scratch; the session object is then inert.
