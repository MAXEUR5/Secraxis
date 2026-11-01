#include <sodium.h>

#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

#include "secraxis/crypto.h"
#include "secraxis/secure_buffer.h"
#include "secraxis/tui_core.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <vector>

extern char** environ;
#endif

namespace secraxis {

// Platform clipboard with clear-if-ours semantics (agenda §14.8). We keep a
// hash of what we last set so we only clear the clipboard if it still holds
// our value (avoid clobbering something the user copied afterwards). The hash
// is non-reversible; we never keep the plaintext after set.
//
// Where this process cannot reach the user's clipboard (POSIX over SSH, or no
// clipboard tool), copies go through the terminal instead (OSC 52): the
// terminal sets its own clipboard. That copy cannot be read back, so its
// timeout clears it unconditionally.
class PlatformClipboard final : public Clipboard {
  public:
    PlatformClipboard(int clipboard_escapes, unsigned clear_after_s);
    bool set_secret(ByteView data) override;
    bool clear_if_ours() override;
    PasteStatus read_text(SecureBuffer* out) override;
    const char* paste_hint() const override;
    const char* copy_hint() const override;
    const char* sent_note() const override;
    bool via_terminal() const override { return via_terminal_; }

  private:
    bool have_ours_ = false;
    bool via_terminal_ = false;
#if defined(_WIN32)
    bool ours_unicode_ = false;  // set as CF_UNICODETEXT (else CF_TEXT)
#else
    const char* set_cmd_ = nullptr;  // clipboard tool, or null: none usable
    std::vector<std::string> get_argv_;  // reads it (no shell); empty: none
    bool remote_ = false;            // an SSH session without X11 forwarding
    int escapes_ = -1;               // TermCaps::clipboard_escapes
    // The tool kept in the foreground under timeout(1), serving our copy (see
    // the constructor); empty where that is not available.
    std::vector<std::string> serve_argv_;
    pid_t owner_ = -1;               // that process while it may still serve
    void stop_owner();
#endif
    uint8_t ours_hash_[32] = {};
    ClipboardFingerprint fp_;
    void hash(ByteView d, uint8_t out[32]) const { fp_.of(d, out); }
    bool matches_current();
#if !defined(_WIN32)
    void forget_in_tmux();
#endif
};

ClipboardFingerprint::ClipboardFingerprint() {
    // No key without random numbers (RDSEED with the system's generator):
    // then nothing is copied, since the copy could never be recognized.
    Result<SecureBuffer> k = random_secret(32);
    if (k.ok()) key_ = static_cast<SecureBuffer&&>(k.value);
}

bool ClipboardFingerprint::of(ByteView data, uint8_t out[32]) const {
    if (!key_.valid()) {
        std::memset(out, 0, 32);
        return false;
    }
    // Keyed BLAKE2b (libsodium generichash): a non-reversible fingerprint used
    // only to decide clear-if-ours — never stored plaintext. The key is secret
    // (a fixed one made this a fast hash anyone could test guesses against).
    const ByteView k = key_.view();
    crypto_generichash(out, 32, data.ptr, data.len, k.ptr, k.len);
    return true;
}

#if defined(_WIN32)

namespace {
// Another program may have the clipboard open for a moment (a clipboard
// manager reading a change, the remote-desktop bridge): tried for up to
// about 100 ms.
bool open_clipboard() {
    for (int tries = 0;; ++tries) {
        if (OpenClipboard(nullptr)) return true;
        if (tries == 10) return false;
        Sleep(10);
    }
}

// Vault text is UTF-8. Well-formed text goes on the clipboard as UTF-16
// (CF_UNICODETEXT) so non-ASCII passwords and usernames paste correctly in
// every application; anything else falls back to the raw bytes as CF_TEXT so
// the exact stored bytes are what gets pasted. The conversion writes straight
// into the clipboard's memory block (no intermediate copy).
bool set_clipboard_text(const char* p, size_t n, bool* unicode) {
    if (n > 0x7FFFFFFF) return false;
    const int wlen =
        n == 0 ? 0
               : MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p,
                                     static_cast<int>(n), nullptr, 0);
    *unicode = (n == 0 || wlen > 0);
    if (!open_clipboard()) return false;
    if (!EmptyClipboard()) {
        CloseClipboard();
        return false;
    }
    const size_t bytes = *unicode ? (static_cast<size_t>(wlen) + 1) * sizeof(wchar_t)
                                  : n + 1;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h == nullptr) {
        CloseClipboard();
        return false;
    }
    void* mem = GlobalLock(h);
    if (mem == nullptr) {
        GlobalFree(h);
        CloseClipboard();
        return false;
    }
    if (*unicode) {
        wchar_t* w = static_cast<wchar_t*>(mem);
        if (wlen > 0)
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, static_cast<int>(n),
                                w, wlen);
        w[wlen] = L'\0';
    } else {
        std::memcpy(mem, p, n);
        static_cast<char*>(mem)[n] = '\0';
    }
    GlobalUnlock(h);
    // Not taken: the block stays ours (wiped, then freed), and "copied" would
    // be false.
    if (SetClipboardData(*unicode ? CF_UNICODETEXT : CF_TEXT, h) == nullptr) {
        void* again = GlobalLock(h);
        if (again != nullptr) {
            SecureZeroMemory(again, GlobalSize(h));
            GlobalUnlock(h);
        }
        GlobalFree(h);
        CloseClipboard();
        return false;
    }
    // Mark as sensitive so clipboard history / cloud sync skip it where the
    // OS honors it (Windows 10+ ExcludeClipboardContentFromMonitorProcessing).
    UINT fmtNoHistory =
        RegisterClipboardFormatA("ExcludeClipboardContentFromMonitorProcessing");
    if (fmtNoHistory != 0) {
        HGLOBAL h2 = GlobalAlloc(GMEM_MOVEABLE, 1);
        if (h2 != nullptr) SetClipboardData(fmtNoHistory, h2);
    }
    // DWORD 0 in these: not in the clipboard history (Win+V), not uploaded to
    // the cloud clipboard.
    for (const char* name : {"CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"}) {
        const UINT fmt = RegisterClipboardFormatA(name);
        if (fmt == 0) continue;
        HGLOBAL h3 = GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
        if (h3 == nullptr) continue;
        void* q = GlobalLock(h3);
        if (q == nullptr) {
            GlobalFree(h3);
            continue;
        }
        *static_cast<DWORD*>(q) = 0;
        GlobalUnlock(h3);
        if (SetClipboardData(fmt, h3) == nullptr) GlobalFree(h3);
    }
    CloseClipboard();
    return true;
}

// The text in an open clipboard as UTF-8, read straight into secure memory:
// UTF-16 re-encoded (unicode), or the raw CF_TEXT bytes. Reads stop at the
// memory block's end even if a program left the text unterminated. *block
// gets the data's handle (still owned by the clipboard).
PasteStatus read_open_clipboard(bool unicode, size_t cap, SecureBuffer* out, HANDLE* block_out) {
    PasteStatus st = PasteStatus::Empty;
    HANDLE h = GetClipboardData(unicode ? CF_UNICODETEXT : CF_TEXT);
    *block_out = h;
    const void* mem = h != nullptr ? GlobalLock(h) : nullptr;
    if (mem != nullptr) {
        const size_t block = GlobalSize(h);
        if (unicode) {
            const wchar_t* w = static_cast<const wchar_t*>(mem);
            const size_t wn = wcsnlen(w, block / sizeof(wchar_t));
            const int n = wn == 0 || wn > 0x7FFFFFFF
                              ? 0
                              : WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(wn),
                                                    nullptr, 0, nullptr, nullptr);
            if (n > 0 && static_cast<size_t>(n) > cap) {
                st = PasteStatus::TooLong;
            } else if (n > 0) {
                *out = SecureBuffer::alloc(static_cast<size_t>(n));
                if (out->valid()) {
                    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(wn),
                                        reinterpret_cast<char*>(out->data()), n, nullptr,
                                        nullptr);
                    st = PasteStatus::Ok;
                }
            }
        } else {
            const char* p = static_cast<const char*>(mem);
            const size_t n = strnlen(p, block);
            if (n > cap) {
                st = PasteStatus::TooLong;
            } else if (n > 0) {
                *out = SecureBuffer::alloc(n);
                if (out->valid()) {
                    std::memcpy(out->data(), p, n);
                    st = PasteStatus::Ok;
                }
            }
        }
        GlobalUnlock(h);
    }
    return st;
}

// Zeroes a clipboard data block held in this process. Windows frees such
// blocks without wiping them: a copied or pasted password would stay readable
// in freed memory (found by the memory scan in tests/interop).
void wipe_block(HANDLE h) {
    if (h == nullptr) return;
    void* mem = GlobalLock(h);
    if (mem == nullptr) return;
    SecureZeroMemory(mem, GlobalSize(h));
    GlobalUnlock(h);
}
}  // namespace

PlatformClipboard::PlatformClipboard(int clipboard_escapes, unsigned clear_after_s) {
    (void)clipboard_escapes;
    (void)clear_after_s;
}

bool PlatformClipboard::set_secret(ByteView data) {
    // A copy that could not be recognized later could never be cleared.
    if (!fp_.valid()) return false;
    if (!set_clipboard_text(reinterpret_cast<const char*>(data.ptr), data.len,
                            &ours_unicode_))
        return false;
    hash(data, ours_hash_);
    have_ours_ = true;
    return true;
}

// With the clipboard open: does it still hold what we put there?
bool PlatformClipboard::matches_current() {
    SecureBuffer cur;
    HANDLE block = nullptr;
    const PasteStatus st = read_open_clipboard(ours_unicode_, 1u << 24, &cur, &block);
    if (st != PasteStatus::Ok && st != PasteStatus::Empty) return false;
    uint8_t curh[32];
    hash(cur.view(), curh);
    return ct_equal(curh, ours_hash_, 32);
}

bool PlatformClipboard::clear_if_ours() {
    if (!have_ours_) return true;
    // Busy: the fingerprint is kept for the next try.
    if (!open_clipboard()) return false;
    // One clipboard session for the check and the clear: nobody can copy in
    // between. Our data block is zeroed before Windows frees it.
    if (matches_current()) {
        wipe_block(GetClipboardData(ours_unicode_ ? CF_UNICODETEXT : CF_TEXT));
        EmptyClipboard();
    }
    CloseClipboard();
    secure_wipe(ours_hash_, sizeof(ours_hash_));
    have_ours_ = false;
    return true;
}

PasteStatus PlatformClipboard::read_text(SecureBuffer* out) {
    if (!open_clipboard()) return PasteStatus::Unavailable;
    HANDLE block = nullptr;
    const PasteStatus st = read_open_clipboard(true, PASTE_MAX, out, &block);
    // This process's copy of someone else's clipboard text (often a
    // password) is zeroed once read; our own copy stays until its timeout.
    if (st == PasteStatus::Ok && !(have_ours_ && matches_current())) wipe_block(block);
    CloseClipboard();
    return st;
}

const char* PlatformClipboard::paste_hint() const {
    return "The clipboard is busy; try Ctrl+V again.";
}

const char* PlatformClipboard::copy_hint() const {
    return "The clipboard is busy; try again.";
}

const char* PlatformClipboard::sent_note() const { return "copied."; }

#else  // POSIX: a clipboard tool where one reaches the user's display, else OSC 52.

namespace {
bool env_set(const char* name) {
    const char* v = std::getenv(name);
    return v != nullptr && v[0] != '\0';
}

bool in_path(const char* exe) {
    const char* path = std::getenv("PATH");
    if (path == nullptr) return false;
    std::string dir;
    for (const char* p = path;; ++p) {
        if (*p == ':' || *p == '\0') {
            const std::string full = (dir.empty() ? std::string(".") : dir) + "/" + exe;
            if (access(full.c_str(), X_OK) == 0) return true;
            dir.clear();
            if (*p == '\0') return false;
        } else {
            dir += *p;
        }
    }
}

// The pipes to a clipboard tool carry secrets, so they are read and written
// through the descriptor straight from and into secure memory: stdio's own
// stream buffer would keep a copy in memory that is freed without wiping
// (found by the memory scan in tests/interop/scenarios/linux_memory.txt).
bool pipe_to(const char* cmd, const uint8_t* p, size_t n) {
    FILE* f = popen(cmd, "w");
    if (f == nullptr) return false;
    const int fd = fileno(f);
    size_t done = 0;
    while (done < n) {
        const ssize_t w = ::write(fd, p + done, n - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;  // EPIPE: the tool went away (SIGPIPE is ignored)
        }
        done += static_cast<size_t>(w);
    }
    const int rc = pclose(f);
    return rc == 0 && done == n;
}

// Starts argv (searched on PATH, no shell) with `n` bytes on its standard
// input, written straight from secure memory; its output goes nowhere. It
// stays in our process group, so a terminal hangup ends it with us. Returns
// its pid, or -1.
pid_t spawn_with_input(const std::vector<std::string>& args, const uint8_t* p, size_t n) {
    std::vector<char*> argv;
    for (const std::string& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    int fds[2];
    if (pipe(fds) != 0) return -1;
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t pid = -1;
    const int rc = posix_spawnp(&pid, argv[0], &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[0]);
    if (rc != 0) {
        close(fds[1]);
        return -1;
    }
    size_t done = 0;
    while (done < n) {
        const ssize_t w = ::write(fds[1], p + done, n - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;  // EPIPE: it went away (SIGPIPE is ignored)
        }
        done += static_cast<size_t>(w);
    }
    close(fds[1]);
    if (done != n) {
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
        return -1;
    }
    return pid;
}

// Still running `ms` milliseconds on (a tool that cannot reach the display
// gives up at once)?
bool still_running(pid_t pid, int ms) {
    for (int t = 0; t < ms; t += 5) {
        if (waitpid(pid, nullptr, WNOHANG) == pid) return false;
        usleep(5000);
    }
    return true;
}

// How long a tool reading the clipboard may take. One whose clipboard owner
// never answers (a hung program, a stuck VM or remote-desktop bridge) would
// otherwise keep xclip, xsel or wl-paste, and the screen with it, waiting
// forever: on Ctrl+V, and in every clear (the timeout, the lock, the exit).
constexpr int kReadToolMs = 2000;

// At most `cap` bytes of a tool's output (argv, searched on PATH, no shell),
// read straight into secure memory (no growing string leaving copies
// behind). A tool that has not finished kReadToolMs on is killed and gives
// Unavailable.
PasteStatus read_from(const std::vector<std::string>& args, size_t cap, SecureBuffer* out) {
    SecureBuffer buf = SecureBuffer::alloc(cap + 1);
    if (!buf.valid()) return PasteStatus::Unavailable;
    std::vector<char*> argv;
    for (const std::string& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    int fds[2];
    if (pipe(fds) != 0) return PasteStatus::Unavailable;
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[1]);
    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t pid = -1;
    const int rc = posix_spawnp(&pid, argv[0], &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        return PasteStatus::Unavailable;
    }
    using Clock = std::chrono::steady_clock;
    const Clock::time_point deadline = Clock::now() + std::chrono::milliseconds(kReadToolMs);
    auto ms_left = [&]() {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        return left > 0 ? static_cast<int>(left) : 0;
    };
    uint8_t sink[256] = {};
    size_t n = 0;
    bool late = false;
    for (;;) {
        const int wait = ms_left();
        if (wait == 0) {
            late = true;
            break;
        }
        struct pollfd pfd;
        pfd.fd = fds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int pr = poll(&pfd, 1, wait);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (pr == 0) {
            late = true;
            break;
        }
        // Past the cap the rest is read and dropped, so the tool can finish.
        const bool room = n <= cap;
        const ssize_t r = ::read(fds[0], room ? buf.data() + n : sink,
                                 room ? cap + 1 - n : sizeof(sink));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;  // the end of its output
        if (room) n += static_cast<size_t>(r);
    }
    secure_wipe(sink, sizeof(sink));
    close(fds[0]);
    int status = 0;
    bool ended = false;
    while (!late) {
        const pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            ended = true;
            break;
        }
        if ((w < 0 && errno != EINTR) || ms_left() == 0) break;
        usleep(2000);
    }
    if (!ended) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        return PasteStatus::Unavailable;  // too late: what it said is dropped
    }
    const bool failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (failed && n == 0) return PasteStatus::Unavailable;
    if (n > cap) return PasteStatus::TooLong;
    if (n == 0) return PasteStatus::Empty;
    *out = SecureBuffer::alloc(n);
    if (!out->valid()) return PasteStatus::Unavailable;
    std::memcpy(out->data(), buf.data(), n);
    return PasteStatus::Ok;
}

void write_all(const uint8_t* p, size_t n) {
    while (n > 0) {
        const ssize_t w = ::write(STDOUT_FILENO, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
}

// OSC 52: the terminal sets its own clipboard to `data`; empty data clears
// it. Inside tmux the same sequence also goes through tmux's passthrough
// (tmux forwards plain OSC 52 only with set-clipboard on).
void osc52(ByteView data) {
    const size_t b64 = sodium_base64_encoded_len(data.len, sodium_base64_VARIANT_ORIGINAL);
    SecureBuffer seq = SecureBuffer::alloc(2 * b64 + 64);
    if (!seq.valid()) return;
    char* s = reinterpret_cast<char*>(seq.data());
    size_t n = 0;
    auto put = [&](const char* t) {
        const size_t l = std::strlen(t);
        std::memcpy(s + n, t, l);
        n += l;
    };
    put("\x1b]52;c;");
    const size_t at = n;
    if (data.len > 0) sodium_bin2base64(s + n, b64, data.ptr, data.len, sodium_base64_VARIANT_ORIGINAL);
    n += data.len > 0 ? std::strlen(s + at) : 0;
    put("\x07");
    write_all(seq.data(), n);
    if (env_set("TMUX")) {
        // The payload again, as "ESC P tmux; ESC <osc> ESC \".
        const size_t plain = n;
        put("\x1bPtmux;\x1b");
        std::memmove(s + n, s, plain);
        n += plain;
        put("\x1b\\");
        write_all(seq.data() + plain, n - plain);
    }
}
}  // namespace

PlatformClipboard::PlatformClipboard(int clipboard_escapes, unsigned clear_after_s)
    : escapes_(clipboard_escapes) {
    // Over SSH a clipboard tool would reach the server's clipboard (or none),
    // not the user's; with X11 forwarding DISPLAY is the user's own screen.
    remote_ = (env_set("SSH_CONNECTION") || env_set("SSH_TTY") || env_set("SSH_CLIENT")) &&
              !env_set("DISPLAY");
    if (remote_) return;
#if defined(__APPLE__)
    set_cmd_ = "pbcopy 2>/dev/null";
    get_argv_ = {"pbpaste"};
#else
    if (env_set("WAYLAND_DISPLAY") && in_path("wl-copy") && in_path("wl-paste")) {
        set_cmd_ = "wl-copy 2>/dev/null";
        get_argv_ = {"wl-paste", "--no-newline"};
    } else if (env_set("DISPLAY") && in_path("xclip")) {
        set_cmd_ = "xclip -selection clipboard 2>/dev/null";
        get_argv_ = {"xclip", "-selection", "clipboard", "-o"};
    } else if (env_set("DISPLAY") && in_path("xsel")) {
        set_cmd_ = "xsel --clipboard --input 2>/dev/null";
        get_argv_ = {"xsel", "--clipboard", "--output"};
    }
    // These tools serve a copy from a process of their own. Left to fork into
    // the background they would serve it until someone copies something else,
    // even after this program is killed or crashes. Kept in the foreground
    // under timeout(1) instead, the server still ends when someone else
    // copies, ends with the terminal (it stays in our process group), and in
    // any case ends clear_after_s seconds on: the copy cannot outlive the
    // clipboard timeout by more than that margin, whatever happens to us.
    if (set_cmd_ != nullptr && clear_after_s > 0 && in_path("timeout")) {
        serve_argv_ = {"timeout", "--foreground", std::to_string(clear_after_s)};
        if (std::strncmp(set_cmd_, "wl-copy", 7) == 0)
            serve_argv_.insert(serve_argv_.end(), {"wl-copy", "--foreground"});
        else if (std::strncmp(set_cmd_, "xclip", 5) == 0)
            serve_argv_.insert(serve_argv_.end(), {"xclip", "-quiet", "-selection", "clipboard"});
        else
            serve_argv_.insert(serve_argv_.end(), {"xsel", "--nodetach", "--clipboard", "--input"});
    }
#endif
}

void PlatformClipboard::stop_owner() {
    if (owner_ <= 0) return;
    // Still serving (it ends by itself once someone else copies)? Ending it
    // takes our copy off the clipboard.
    if (waitpid(owner_, nullptr, WNOHANG) == 0) {
        kill(owner_, SIGTERM);
        waitpid(owner_, nullptr, 0);
    }
    owner_ = -1;
}

bool PlatformClipboard::set_secret(ByteView data) {
    // A copy that could not be recognized later could never be cleared.
    if (!fp_.valid()) return false;
    via_terminal_ = false;
    stop_owner();  // an earlier copy's server
    if (!serve_argv_.empty()) {
        const pid_t pid = spawn_with_input(serve_argv_, data.ptr, data.len);
        if (pid > 0 && still_running(pid, 60)) {
            owner_ = pid;
            hash(data, ours_hash_);
            have_ours_ = true;
            return true;
        }
        // It could not serve (no display access?): the plain way below.
    }
    if (set_cmd_ != nullptr && pipe_to(set_cmd_, data.ptr, data.len)) {
        hash(data, ours_hash_);
        have_ours_ = true;
        return true;
    }
    // No clipboard here: the terminal's own (OSC 52), unless the terminal is
    // known to ignore it; then saying "copied" would be false.
    if (escapes_ == 0) return false;
    osc52(data);
    hash(data, ours_hash_);
    via_terminal_ = true;
    have_ours_ = true;
    return true;
}

// tmux (set-clipboard on) keeps every OSC 52 copy as one of its automatic
// paste buffers ("buffer0", "buffer1", ...) and ignores an empty one: the
// password would outlive the timeout, and the program, there (found by
// tests: tmux 3.4 kept it). Deletes the automatic buffers that hold our
// copy or the blank the clear sent instead; nothing else is touched, and
// only names of that exact form reach a command line.
void PlatformClipboard::forget_in_tmux() {
    if (!in_path("tmux")) return;
    SecureBuffer names;
    if (read_from({"tmux", "list-buffers", "-F", "#{buffer_name}"}, 1u << 16, &names) !=
        PasteStatus::Ok)
        return;
    uint8_t blank[32];
    hash(ByteView(" ", 1), blank);
    const char* p = reinterpret_cast<const char*>(names.data());
    for (size_t i = 0; i < names.size();) {
        size_t j = i;
        while (j < names.size() && p[j] != '\n') ++j;
        const std::string name(p + i, j - i);
        i = j + 1;
        if (name.size() < 7 || name.size() > 16 || name.compare(0, 6, "buffer") != 0 ||
            name.find_first_not_of("0123456789", 6) != std::string::npos)
            continue;
        SecureBuffer content;
        if (read_from({"tmux", "show-buffer", "-b", name}, 1u << 20, &content) != PasteStatus::Ok)
            continue;
        uint8_t h[32];
        hash(content.view(), h);
        content.reset();
        if (ct_equal(h, ours_hash_, 32) || ct_equal(h, blank, 32)) {
            const std::string del = "tmux delete-buffer -b " + name + " 2>/dev/null";
            pipe_to(del.c_str(), nullptr, 0);
        }
        secure_wipe(h, sizeof(h));
    }
}

bool PlatformClipboard::matches_current() {
    SecureBuffer cur;
    const PasteStatus st = read_from(get_argv_, 1u << 24, &cur);
    if (st != PasteStatus::Ok && st != PasteStatus::Empty) return false;
    uint8_t curh[32];
    hash(cur.view(), curh);
    return ct_equal(curh, ours_hash_, 32);
}

// Always done (true): what can be cleared is. A copy a clipboard manager took
// over whose owner does not answer cannot even be checked (read_from gives
// up); trying again every second would only stall the screen each time.
bool PlatformClipboard::clear_if_ours() {
    if (!have_ours_) return true;
    if (via_terminal_) {
        // Cannot be read back: cleared unconditionally. tmux ignores an empty
        // payload, so inside it a blank replaces the copy (and reaches the
        // outer terminal), and the paste buffers tmux kept of it are deleted.
        if (env_set("TMUX")) {
            osc52(ByteView(" ", 1));
            forget_in_tmux();
        } else {
            osc52(ByteView());
        }
    } else {
        stop_owner();
    }
    // A clipboard manager may have taken our copy over: clear it there too.
    if (!via_terminal_ && !get_argv_.empty() && matches_current()) {
        pipe_to(set_cmd_, nullptr, 0);
    }
    secure_wipe(ours_hash_, sizeof(ours_hash_));
    have_ours_ = false;
    via_terminal_ = false;
    return true;
}

PasteStatus PlatformClipboard::read_text(SecureBuffer* out) {
    if (get_argv_.empty()) return PasteStatus::Unavailable;
    return read_from(get_argv_, PASTE_MAX, out);
}

const char* PlatformClipboard::paste_hint() const {
#if defined(__APPLE__)
    if (!remote_) return "Paste with Cmd+V.";
#endif
    if (remote_) return "Over SSH, paste with your terminal: Ctrl+Shift+V or right-click.";
    return "Ctrl+V needs wl-clipboard or xclip; or paste with Ctrl+Shift+V.";
}

// tmux passes a program's clipboard request on only with set-clipboard on
// (the default, "external", drops it): say so rather than claim a copy.
const char* PlatformClipboard::sent_note() const {
    if (env_set("TMUX")) return "sent through tmux (it needs set-clipboard on).";
    return "sent to your terminal's clipboard.";
}

const char* PlatformClipboard::copy_hint() const {
    if (remote_)
        return "This terminal ignores clipboard requests over SSH (OSC 52); try ssh -X with xclip.";
    return "Copying needs wl-clipboard or xclip; this terminal ignores clipboard requests.";
}

#endif

// Factory (avoids exposing the concrete type in the header).
Clipboard* make_platform_clipboard(int clipboard_escapes, unsigned clear_after_s) {
    return new PlatformClipboard(clipboard_escapes, clear_after_s);
}

}  // namespace secraxis
