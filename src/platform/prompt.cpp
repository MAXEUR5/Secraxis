#include "secraxis/prompt.h"

#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <csignal>
#include <termios.h>
#include <unistd.h>
#endif

namespace secraxis {

namespace {
#if defined(_WIN32)
// The console mode to put back if the prompt is cut short (Ctrl+C, the
// console closing): echo must not stay off for whatever runs next.
HANDLE g_in = nullptr;
DWORD g_mode = 0;
volatile LONG g_hidden = 0;
BOOL WINAPI restore_on_event(DWORD) {
    if (InterlockedExchange(&g_hidden, 0) != 0) SetConsoleMode(g_in, g_mode);
    return FALSE;  // and on to the default handling (the process ends)
}
#else
// Likewise on POSIX, for the signals that end a waiting prompt.
struct termios g_saved;
volatile sig_atomic_t g_hidden = 0;
void restore_on_signal(int sig) {
    if (g_hidden) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);  // async-signal-safe
    g_hidden = 0;
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}
constexpr int kEndingSignals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
#endif
}  // namespace

bool stdin_is_tty() {
#if defined(_WIN32)
    // A console, not just any character device (NUL and COM ports pass
    // _isatty).
    DWORD mode = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

SecureBuffer read_hidden_line(const char* prompt) {
    if (prompt != nullptr) {
        std::fputs(prompt, stderr);
        std::fflush(stderr);
    }
    // Grow a secure buffer as we read; cap to a sane max.
    constexpr size_t MAX = 4096;
    SecureBuffer buf = SecureBuffer::alloc(MAX);
    if (!buf.valid()) return buf;
    size_t len = 0;

#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool restore = false;
    if (GetConsoleMode(h, &mode)) {
        g_in = h;
        g_mode = mode;
        InterlockedExchange(&g_hidden, 1);
        SetConsoleCtrlHandler(restore_on_event, TRUE);
        SetConsoleMode(h, mode & ~(DWORD)(ENABLE_ECHO_INPUT));
        restore = true;
    }
    for (;;) {
        char c;
        DWORD got = 0;
        if (!ReadFile(h, &c, 1, &got, nullptr) || got == 0) break;  // EOF
        if (c == '\r') continue;
        if (c == '\n') break;
        if (c == '\b') { if (len > 0) --len; continue; }
        if (len < MAX && static_cast<unsigned char>(c) >= 0x20) buf.data()[len++] = (uint8_t)c;
    }
    if (restore) {
        if (InterlockedExchange(&g_hidden, 0) != 0) SetConsoleMode(h, mode);
        SetConsoleCtrlHandler(restore_on_event, FALSE);
    }
#else
    struct termios oldt, newt;
    struct sigaction old_actions[4];
    bool restore = false;
    if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
        g_saved = oldt;
        g_hidden = 1;
        struct sigaction sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sa_handler = restore_on_signal;
        sigemptyset(&sa.sa_mask);
        for (size_t k = 0; k < 4; ++k) sigaction(kEndingSignals[k], &sa, &old_actions[k]);
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
        restore = true;
    }
    for (;;) {
        unsigned char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0) break;  // EOF
        if (c == '\n') break;
        if (c == 0x7F || c == 0x08) { if (len > 0) --len; continue; }
        if (len < MAX && c >= 0x20) buf.data()[len++] = c;
    }
    if (restore) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        g_hidden = 0;
        for (size_t k = 0; k < 4; ++k) sigaction(kEndingSignals[k], &old_actions[k], nullptr);
    }
#endif
    std::fputc('\n', stderr);

    // Shrink to the exact length (fresh buffer; wipe the oversized one).
    SecureBuffer out = SecureBuffer::alloc(len);
    if (out.valid() && len > 0) std::memcpy(out.data(), buf.data(), len);
    return out;
}

}  // namespace secraxis
