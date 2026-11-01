// fs_atomic.h — crash-safe file IO (agenda §8.7).
//
// write_file_atomic: write to a random-suffixed temp file in the SAME
// directory, flush to stable storage, then atomically rename over the target
// (MoveFileEx REPLACE|WRITE_THROUGH on Windows; rename+dir-fsync on POSIX).
// On any failure the temp file is removed and the original is untouched.
// A partially updated target file can never exist. A process killed between
// creating and renaming its temp file leaves that file behind (a whole copy
// of what it was writing); every write first removes such leftovers of the
// same target ("<name>.tmp-" + 16 hex digits, nothing else), before writing
// its own (a vault save holds its replace lock then, so no other save's
// temporary file can be among them).
#ifndef SECRAXIS_FS_ATOMIC_H
#define SECRAXIS_FS_ATOMIC_H

#include <atomic>
#include <cstdint>
#include <string>

#include "secraxis/common.h"

namespace secraxis {

// Whole-file read with a hard size cap (default 512 MiB). Non-secret buffer:
// .seis content is ciphertext. (Callers loading anything secret-equivalent
// must NOT use this.)
Result<Bytes> read_file(const std::string& utf8_path,
                        uint64_t max_size = 512ull << 20);

// The first `n` bytes of a file (fewer if it is shorter) and its size.
Result<Bytes> read_file_head(const std::string& utf8_path, size_t n,
                             uint64_t* file_size);

Status write_file_atomic(const std::string& utf8_path, ByteView data);
// The same, but never replaces anything: Err::Exists if a file (or link)
// is at `utf8_path` when the new one would be put in place. `cancel` (not
// owned), when set by another thread before then, also during a long write
// of the temporary file, stops it: Err::Canceled, nothing left behind.
Status write_file_new(const std::string& utf8_path, ByteView data,
                      const std::atomic<bool>* cancel = nullptr);

// For plaintext exports: writes a NEW file that only the current user can
// read or write (POSIX mode 0600; Windows a protected DACL granting the user
// alone, so nothing is inherited from the folder). Never through anything
// already there, file or link (Err::Exists). A failed write deletes what
// was written (Err::IoWrite).
Status write_file_private(const std::string& utf8_path, ByteView data);

// The file a symbolic link at `utf8_path` points to, followed to its end;
// `utf8_path` itself when it is no link, or one that leads nowhere. A save
// replaces that file: renaming over the link would replace the link itself.
std::string resolve_symlink(const std::string& utf8_path);

bool file_exists(const std::string& utf8_path);
Status remove_file(const std::string& utf8_path);

// Serializes the processes that replace the same file: seis_save holds it
// from its unchanged-check through the rename, so of two windows saving the
// same state at once exactly one writes and the other sees the change.
// POSIX: flock() on the file itself (a regular file only), re-taken if the
// file was replaced while waiting; nothing to hold when there is no file
// yet. Windows: "<name>.lock" beside it, opened sharing nothing. One this
// creates is deleted when closed, also when the process ends however it
// ends; one found there already is held as it is and deleted afterwards
// only if it carries REPLACE_LOCK_MARK (a power loss can leave one of
// ours): a file of that name that is not ours is never deleted. It binds
// only processes that take it: a sync tool just replaces the file, which
// the unchanged-check catches.
constexpr char REPLACE_LOCK_MARK[] = "Secraxis save lock\r\n";

class ReplaceLock final {
  public:
    ReplaceLock() = default;
    ~ReplaceLock() { release(); }
    ReplaceLock(const ReplaceLock&) = delete;
    ReplaceLock& operator=(const ReplaceLock&) = delete;

    // Waits up to `wait_ms` for another holder: Err::IoWrite if it still
    // holds it then. Success also when no lock can be taken here at all (a
    // file system without locks): the unchanged-check still applies.
    Status acquire(const std::string& utf8_path, unsigned wait_ms);
    void release() noexcept;
    bool held() const noexcept { return h_ != -1; }

  private:
    intptr_t h_ = -1;  // POSIX descriptor or Windows HANDLE
};

}  // namespace secraxis

#endif  // SECRAXIS_FS_ATOMIC_H
