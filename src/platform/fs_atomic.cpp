#include "secraxis/fs_atomic.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "secraxis/crypto.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <ctime>
#endif
#include <vector>

namespace secraxis {

namespace {

// Empty when no random numbers can be made (the write is then refused).
std::string temp_sibling(const std::string& path) {
    uint8_t r[8];
    if (!random_bytes(r, sizeof(r))) return std::string();
    char suf[24];
    std::snprintf(suf, sizeof(suf), ".tmp-%02x%02x%02x%02x%02x%02x%02x%02x",
                  r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    return path + suf;
}

// A leftover of temp_sibling(dir/base): base + ".tmp-" + 16 hex digits.
bool is_temp_of(const std::string& name, const std::string& base) {
    if (name.size() != base.size() + 21 || name.compare(0, base.size(), base) != 0 ||
        name.compare(base.size(), 5, ".tmp-") != 0)
        return false;
    for (size_t i = base.size() + 5; i < name.size(); ++i) {
        const char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

#if defined(_WIN32)
std::wstring widen(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                        static_cast<int>(utf8.size()), &w[0], n);
    return w;
}

std::string narrow(const wchar_t* w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}
#endif

// Writes `data` to the new file `tmp` and flushes it to stable storage. On
// failure nothing is left behind.
Status write_temp(const std::string& tmp, ByteView data) {
#if defined(_WIN32)
    const std::wstring wtmp = widen(tmp);
    HANDLE f = CreateFileW(wtmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return status_fail(Err::IoWrite);
    size_t off = 0;
    while (off < data.len) {
        DWORD chunk = static_cast<DWORD>(
            (data.len - off > (1u << 30)) ? (1u << 30) : (data.len - off));
        DWORD put = 0;
        if (!WriteFile(f, data.ptr + off, chunk, &put, nullptr) || put == 0) {
            CloseHandle(f);
            DeleteFileW(wtmp.c_str());
            return status_fail(Err::IoWrite);
        }
        off += put;
    }
    if (!FlushFileBuffers(f)) {
        CloseHandle(f);
        DeleteFileW(wtmp.c_str());
        return status_fail(Err::IoWrite);
    }
    CloseHandle(f);
    return status_ok();
#else
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return status_fail(Err::IoWrite);
    size_t off = 0;
    while (off < data.len) {
        ssize_t put = write(fd, data.ptr + off, data.len - off);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) {
            close(fd);
            unlink(tmp.c_str());
            return status_fail(Err::IoWrite);
        }
        off += static_cast<size_t>(put);
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp.c_str());
        return status_fail(Err::IoWrite);
    }
    close(fd);
    return status_ok();
#endif
}

#if !defined(_WIN32)
// fsync the directory so a rename or link in it is durable.
void sync_dir_of(const std::string& utf8_path) {
    std::string dir = utf8_path;
    size_t slash = dir.find_last_of('/');
    dir = (slash == std::string::npos) ? "." : (slash == 0 ? "/" : dir.substr(0, slash));
    int dfd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
}
#endif

// Removes what interrupted earlier writes of `utf8_path` left behind (see
// fs_atomic.h): for a vault each is a whole older copy, still openable with
// the master password it had then, holding entries deleted since.
void remove_stale_temps(const std::string& utf8_path) {
#if defined(_WIN32)
    const size_t cut = utf8_path.find_last_of("\\/");
    const std::string dir = cut == std::string::npos ? std::string() : utf8_path.substr(0, cut + 1);
    const std::string base = cut == std::string::npos ? utf8_path : utf8_path.substr(cut + 1);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(widen(utf8_path + ".tmp-*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    std::vector<std::string> stale;
    do {
        const std::string name = narrow(fd.cFileName);
        if (is_temp_of(name, base) && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            stale.push_back(name);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    for (const std::string& name : stale) DeleteFileW(widen(dir + name).c_str());
#else
    const size_t cut = utf8_path.find_last_of('/');
    const std::string dir =
        cut == std::string::npos ? std::string(".") : (cut == 0 ? std::string("/") : utf8_path.substr(0, cut));
    const std::string base = cut == std::string::npos ? utf8_path : utf8_path.substr(cut + 1);
    DIR* d = opendir(dir.c_str());
    if (d == nullptr) return;
    std::vector<std::string> stale;
    while (dirent* e = readdir(d))
        if (is_temp_of(e->d_name, base)) stale.push_back(e->d_name);
    closedir(d);
    for (const std::string& name : stale) unlink((dir + "/" + name).c_str());
#endif
}

}  // namespace

Result<Bytes> read_file(const std::string& utf8_path, uint64_t max_size) {
    using R = Result<Bytes>;
#if defined(_WIN32)
    HANDLE f = CreateFileW(widen(utf8_path).c_str(), GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return R::failure(Err::IoRead);
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 0 ||
        static_cast<uint64_t>(sz.QuadPart) > max_size) {
        CloseHandle(f);
        return R::failure(Err::IoRead);
    }
    Bytes data(static_cast<size_t>(sz.QuadPart));
    size_t off = 0;
    while (off < data.size()) {
        DWORD chunk = static_cast<DWORD>(
            (data.size() - off > (1u << 30)) ? (1u << 30) : (data.size() - off));
        DWORD got = 0;
        if (!ReadFile(f, data.data() + off, chunk, &got, nullptr) || got == 0) {
            CloseHandle(f);
            return R::failure(Err::IoRead);
        }
        off += got;
    }
    CloseHandle(f);
    return R::success(static_cast<Bytes&&>(data));
#else
    int fd = open(utf8_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return R::failure(Err::IoRead);
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        static_cast<uint64_t>(st.st_size) > max_size || !S_ISREG(st.st_mode)) {
        close(fd);
        return R::failure(Err::IoRead);
    }
    Bytes data(static_cast<size_t>(st.st_size));
    size_t off = 0;
    while (off < data.size()) {
        ssize_t got = read(fd, data.data() + off, data.size() - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            close(fd);
            return R::failure(Err::IoRead);
        }
        off += static_cast<size_t>(got);
    }
    close(fd);
    return R::success(static_cast<Bytes&&>(data));
#endif
}

Result<Bytes> read_file_head(const std::string& utf8_path, size_t n,
                             uint64_t* file_size) {
    using R = Result<Bytes>;
#if defined(_WIN32)
    HANDLE f = CreateFileW(widen(utf8_path).c_str(), GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return R::failure(Err::IoRead);
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 0) {
        CloseHandle(f);
        return R::failure(Err::IoRead);
    }
    *file_size = static_cast<uint64_t>(sz.QuadPart);
    Bytes data(static_cast<size_t>(*file_size < n ? *file_size : n));
    size_t off = 0;
    while (off < data.size()) {
        DWORD got = 0;
        if (!ReadFile(f, data.data() + off, static_cast<DWORD>(data.size() - off), &got,
                      nullptr) ||
            got == 0) {
            CloseHandle(f);
            return R::failure(Err::IoRead);
        }
        off += got;
    }
    CloseHandle(f);
    return R::success(static_cast<Bytes&&>(data));
#else
    int fd = open(utf8_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return R::failure(Err::IoRead);
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return R::failure(Err::IoRead);
    }
    *file_size = static_cast<uint64_t>(st.st_size);
    Bytes data(static_cast<size_t>(*file_size < n ? *file_size : n));
    size_t off = 0;
    while (off < data.size()) {
        ssize_t got = read(fd, data.data() + off, data.size() - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            close(fd);
            return R::failure(Err::IoRead);
        }
        off += static_cast<size_t>(got);
    }
    close(fd);
    return R::success(static_cast<Bytes&&>(data));
#endif
}

Status write_file_atomic(const std::string& utf8_path, ByteView data) {
    // Leftovers of interrupted earlier writes go first, while a vault save
    // still holds its replace lock: after the rename the next writer may
    // already be writing its own temporary file, which this would delete.
    remove_stale_temps(utf8_path);
    const std::string tmp = temp_sibling(utf8_path);
    if (tmp.empty()) return status_fail(Err::RngFailed);
    Status ws = write_temp(tmp, data);
    if (!ws.ok()) return ws;
#if defined(_WIN32)
    const std::wstring wtmp = widen(tmp);
    if (!MoveFileExW(wtmp.c_str(), widen(utf8_path).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(wtmp.c_str());
        return status_fail(Err::IoWrite);
    }
#else
    if (rename(tmp.c_str(), utf8_path.c_str()) != 0) {
        unlink(tmp.c_str());
        return status_fail(Err::IoWrite);
    }
    sync_dir_of(utf8_path);
#endif
    return status_ok();
}

Status write_file_new(const std::string& utf8_path, ByteView data,
                      const std::atomic<bool>* cancel) {
    remove_stale_temps(utf8_path);
    const std::string tmp = temp_sibling(utf8_path);
    if (tmp.empty()) return status_fail(Err::RngFailed);
    Status ws = write_temp(tmp, data);
    if (!ws.ok()) return ws;
    // Given up while the temporary file was written (a slow or stalled
    // drive): nothing is put in place.
    if (cancel != nullptr && cancel->load()) {
#if defined(_WIN32)
        DeleteFileW(widen(tmp).c_str());
#else
        unlink(tmp.c_str());
#endif
        return status_fail(Err::Canceled);
    }
#if defined(_WIN32)
    // Without MOVEFILE_REPLACE_EXISTING the move fails if anything is there.
    const std::wstring wtmp = widen(tmp);
    if (!MoveFileExW(wtmp.c_str(), widen(utf8_path).c_str(), MOVEFILE_WRITE_THROUGH)) {
        const DWORD e = GetLastError();
        DeleteFileW(wtmp.c_str());
        return status_fail(e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS ? Err::Exists
                                                                               : Err::IoWrite);
    }
#else
    // link() never replaces. On a file system without hard links (FAT) it
    // fails otherwise: then check and rename, a narrow race at worst.
    if (link(tmp.c_str(), utf8_path.c_str()) == 0) {
        unlink(tmp.c_str());
    } else {
        struct stat st;
        if (errno == EEXIST || lstat(utf8_path.c_str(), &st) == 0) {
            unlink(tmp.c_str());
            return status_fail(Err::Exists);
        }
        if (rename(tmp.c_str(), utf8_path.c_str()) != 0) {
            unlink(tmp.c_str());
            return status_fail(Err::IoWrite);
        }
    }
    sync_dir_of(utf8_path);
#endif
    return status_ok();
}

Status write_file_private(const std::string& utf8_path, ByteView data) {
#if defined(_WIN32)
    // The user alone: one entry in a protected DACL, so nothing is inherited
    // from the folder (on a drive other than the system's, a new file there
    // is usually readable by every user).
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return status_fail(Err::IoWrite);
    DWORD need = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &need);
    std::vector<uint8_t> user_info(need > 0 ? need : 1);
    const bool got_user =
        need > 0 && GetTokenInformation(token, TokenUser, user_info.data(), need, &need);
    CloseHandle(token);
    if (!got_user) return status_fail(Err::IoWrite);
    PSID user = reinterpret_cast<TOKEN_USER*>(user_info.data())->User.Sid;
    const DWORD acl_size = static_cast<DWORD>(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) -
                                              sizeof(DWORD) + GetLengthSid(user));
    std::vector<uint8_t> acl_mem(acl_size);
    PACL acl = reinterpret_cast<PACL>(acl_mem.data());
    SECURITY_DESCRIPTOR sd;
    if (!InitializeAcl(acl, acl_size, ACL_REVISION) ||
        !AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, user) ||
        !InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        return status_fail(Err::IoWrite);
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    HANDLE f = CreateFileW(widen(utf8_path).c_str(), GENERIC_WRITE | DELETE, 0, &sa, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        return status_fail(e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS ? Err::Exists
                                                                               : Err::IoWrite);
    }
    bool ok = true;
    size_t off = 0;
    while (ok && off < data.len) {
        const DWORD chunk = static_cast<DWORD>(
            (data.len - off > (1u << 30)) ? (1u << 30) : (data.len - off));
        DWORD put = 0;
        ok = WriteFile(f, data.ptr + off, chunk, &put, nullptr) && put != 0;
        off += put;
    }
    if (ok) ok = FlushFileBuffers(f) != 0;
    if (!ok) {
        // Deleted through this handle (nobody else can open it meanwhile):
        // no part of the plaintext stays behind under that name.
        FILE_DISPOSITION_INFO gone;
        gone.DeleteFile = TRUE;
        SetFileInformationByHandle(f, FileDispositionInfo, &gone, sizeof(gone));
    }
    CloseHandle(f);
    return ok ? status_ok() : status_fail(Err::IoWrite);
#else
    // O_EXCL: never through an existing file, nor through a link (even one
    // that leads nowhere).
    const int fd =
        open(utf8_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return status_fail(errno == EEXIST ? Err::Exists : Err::IoWrite);
    bool ok = true;
    size_t off = 0;
    while (ok && off < data.len) {
        const ssize_t put = write(fd, data.ptr + off, data.len - off);
        if (put < 0 && errno == EINTR) continue;
        ok = put > 0;
        if (ok) off += static_cast<size_t>(put);
    }
    if (ok) ok = fsync(fd) == 0;
    if (!ok) {
        // No part of the plaintext stays behind under that name.
        if (ftruncate(fd, 0) != 0) {
            // unlinked below all the same
        }
        unlink(utf8_path.c_str());
    }
    if (close(fd) != 0 && ok) {
        unlink(utf8_path.c_str());
        ok = false;
    }
    return ok ? status_ok() : status_fail(Err::IoWrite);
#endif
}

std::string resolve_symlink(const std::string& utf8_path) {
#if defined(_WIN32)
    const std::wstring w = widen(utf8_path);
    if (w.empty()) return utf8_path;
    WIN32_FIND_DATAW fd;
    HANDLE find = FindFirstFileW(w.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return utf8_path;
    FindClose(find);
    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 ||
        fd.dwReserved0 != IO_REPARSE_TAG_SYMLINK)
        return utf8_path;
    // Opened through the link (to its end): that file's own name.
    HANDLE f = CreateFileW(w.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return utf8_path;
    std::wstring out;
    const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD n = GetFinalPathNameByHandleW(f, nullptr, 0, flags);
    if (n > 0 && n <= 32768) {
        out.assign(n, L'\0');
        const DWORD got = GetFinalPathNameByHandleW(f, &out[0], n, flags);
        if (got == 0 || got >= n)
            out.clear();
        else
            out.resize(got);
    }
    CloseHandle(f);
    if (out.empty()) return utf8_path;
    return narrow(out.c_str());  // "\\?\C:\..." (or "\\?\UNC\..."): fine for every call here
#else
    struct stat st;
    if (lstat(utf8_path.c_str(), &st) != 0 || !S_ISLNK(st.st_mode)) return utf8_path;
    char* real = realpath(utf8_path.c_str(), nullptr);
    if (real == nullptr) return utf8_path;
    std::string out(real);
    std::free(real);
    return out;
#endif
}

bool file_exists(const std::string& utf8_path) {
#if defined(_WIN32)
    DWORD attr = GetFileAttributesW(widen(utf8_path).c_str());
    return attr != INVALID_FILE_ATTRIBUTES &&
           (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
    struct stat st;
    return stat(utf8_path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
#endif
}

Status remove_file(const std::string& utf8_path) {
#if defined(_WIN32)
    return DeleteFileW(widen(utf8_path).c_str()) ? status_ok()
                                                 : status_fail(Err::IoWrite);
#else
    return (unlink(utf8_path.c_str()) == 0) ? status_ok()
                                            : status_fail(Err::IoWrite);
#endif
}

namespace {

constexpr unsigned kLockPollMs = 10;

void nap_ms(unsigned ms) {
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = static_cast<time_t>(ms / 1000);
    ts.tv_nsec = static_cast<long>(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
#endif
}

}  // namespace

Status ReplaceLock::acquire(const std::string& utf8_path, unsigned wait_ms) {
    release();
#if defined(_WIN32)
    const std::wstring name = widen(utf8_path + ".lock");
    int refused = 0;  // creations denied in a row while no such file exists
    for (unsigned waited = 0;; waited += kLockPollMs) {
        // Ours, made here. Sharing nothing, so another holder's open fails
        // until this one closes; closing (or the process ending, however it
        // ends) deletes it.
        HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr,
                               CREATE_NEW,
                               FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY |
                                   FILE_FLAG_DELETE_ON_CLOSE,
                               nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD put = 0;
            WriteFile(h, REPLACE_LOCK_MARK, sizeof(REPLACE_LOCK_MARK) - 1, &put, nullptr);
            h_ = reinterpret_cast<intptr_t>(h);
            return status_ok();
        }
        DWORD e = GetLastError();
        if (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) {
            // Already there: another save holds it (this open fails), or it
            // was left behind. Held as it is (sharing nothing). If it carries
            // our mark, it is marked for deletion through this very handle,
            // so it goes when the handle closes and nothing else can take
            // its place in between; any other file is left as it is.
            bool can_delete = true;
            h = CreateFileW(name.c_str(), GENERIC_READ | DELETE, 0, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
                can_delete = false;  // not ours to delete, or read-only: hold it only
                h = CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            if (h != INVALID_HANDLE_VALUE) {
                char buf[sizeof(REPLACE_LOCK_MARK)] = {};
                DWORD got = 0;
                if (can_delete && ReadFile(h, buf, sizeof(buf), &got, nullptr) &&
                    got == sizeof(REPLACE_LOCK_MARK) - 1 &&
                    std::memcmp(buf, REPLACE_LOCK_MARK, got) == 0) {
                    FILE_DISPOSITION_INFO gone;
                    gone.DeleteFile = TRUE;
                    SetFileInformationByHandle(h, FileDispositionInfo, &gone, sizeof(gone));
                }
                h_ = reinterpret_cast<intptr_t>(h);
                return status_ok();
            }
            e = GetLastError();  // ERROR_FILE_NOT_FOUND: it just went; retry
        }
        const DWORD attr = GetFileAttributesW(name.c_str());
        const DWORD attr_err = attr == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
            return status_ok();  // a folder of that name: no lock here
        if (e == ERROR_ACCESS_DENIED &&
            (attr_err == ERROR_FILE_NOT_FOUND || attr_err == ERROR_PATH_NOT_FOUND)) {
            // Creating it is denied with nothing there: the folder takes no
            // new files (the save fails on its own), unless a pending delete
            // was just finishing, which another try or two tells.
            if (++refused >= 3) return status_ok();
        } else {
            refused = 0;
        }
        // Held (sharing violation), closed and not yet gone (access denied
        // while its delete is pending), or gone meanwhile: try again.
        // Anything else means no lock can be had here.
        if (e != ERROR_SHARING_VIOLATION && e != ERROR_ACCESS_DENIED && e != ERROR_FILE_NOT_FOUND)
            return status_ok();
        if (waited >= wait_ms) return status_fail(Err::IoWrite);
        nap_ms(kLockPollMs);
    }
#else
    for (unsigned waited = 0;; waited += kLockPollMs) {
        // Only a regular file is locked (and opened at all); O_NONBLOCK in
        // case it is swapped for something else, whose open must not wait.
        struct stat held, now;
        if (stat(utf8_path.c_str(), &now) != 0 || !S_ISREG(now.st_mode)) return status_ok();
        const int fd = open(utf8_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) return status_ok();  // gone: nothing to replace
        if (fstat(fd, &held) != 0 || !S_ISREG(held.st_mode)) {
            close(fd);
            return status_ok();
        }
        int r;
        do {
            r = flock(fd, LOCK_EX | LOCK_NB);
        } while (r != 0 && errno == EINTR);
        if (r == 0) {
            // Locked; but if the file was replaced while we waited, the lock
            // is on the old one: take the new one instead.
            if (stat(utf8_path.c_str(), &now) == 0 && held.st_dev == now.st_dev &&
                held.st_ino == now.st_ino) {
                h_ = fd;
                return status_ok();
            }
            close(fd);
            if (waited >= wait_ms) return status_fail(Err::IoWrite);
            continue;
        }
        const int e = errno;
        close(fd);
        if (e != EWOULDBLOCK && e != EAGAIN) return status_ok();  // no locks here
        if (waited >= wait_ms) return status_fail(Err::IoWrite);
        nap_ms(kLockPollMs);
    }
#endif
}

void ReplaceLock::release() noexcept {
    if (h_ == -1) return;
#if defined(_WIN32)
    CloseHandle(reinterpret_cast<HANDLE>(h_));  // deletes the lock file if it is ours
#else
    close(static_cast<int>(h_));  // closing drops the flock
#endif
    h_ = -1;
}

}  // namespace secraxis
