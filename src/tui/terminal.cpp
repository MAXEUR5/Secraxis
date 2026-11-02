#include "secraxis/terminal.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "secraxis/secure_buffer.h"
#include "secraxis/tui_input.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cwchar>
#else
#include <cerrno>
#include <clocale>
#include <csignal>
#include <fcntl.h>
#include <langinfo.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace secraxis {

namespace {

// Global restore state so a panic/signal path can put the terminal back.
std::atomic<bool> g_needs_restore{false};
// The stop request (Terminal::hangup): the signal number on POSIX, 1 on
// Windows; 0 while none.
std::atomic<int> g_hangup{0};

#if defined(_WIN32)
HANDLE g_hin = INVALID_HANDLE_VALUE;
HANDLE g_hout = INVALID_HANDLE_VALUE;
DWORD g_in_mode = 0;
DWORD g_out_mode = 0;
UINT g_in_cp = 0;
UINT g_out_cp = 0;
bool g_font_changed = false;      // the classic console's font, while switched
CONSOLE_FONT_INFOEX g_font_orig = {};
HANDLE g_stop_event = nullptr;     // set on a stop request: wakes read_key
HANDLE g_done_event = nullptr;     // set by finish_hangup: the handler may return
#else
struct termios g_orig;
bool g_have_orig = false;
int g_wake[2] = {-1, -1};          // SIGWINCH self-pipe
std::atomic<bool> g_winch{false};
#endif

void write_str(const char* s, size_t n) {
#if defined(_WIN32)
    while (n > 0) {
        DWORD wrote = 0;
        const DWORD chunk = n > 0x10000 ? 0x10000 : static_cast<DWORD>(n);
        if (!WriteFile(g_hout, s, chunk, &wrote, nullptr) || wrote == 0) return;
        s += wrote;
        n -= wrote;
    }
#else
    while (n > 0) {
        const ssize_t r = ::write(STDOUT_FILENO, s, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return;
        }
        s += r;
        n -= static_cast<size_t>(r);
    }
#endif
}

void write_cstr(const char* s) { write_str(s, std::strlen(s)); }

// Alternate screen, hidden cursor, no auto-wrap (nothing can scroll), and
// bracketed paste (pasted text is marked, see InputDecoder). Mouse reporting
// (clicks and wheel, SGR coordinates) is switched on separately when wanted
// and always switched off on the way out.
const char* ENTER_SEQ = "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[?2004h\x1b[0m\x1b[2J\x1b[H";
const char* LEAVE_SEQ =
    "\x1b[?1006l\x1b[?1000l\x1b[?2004l\x1b[0m\x1b[2J\x1b[?7h\x1b[?25h\x1b[?1049l";
const char* MOUSE_ON = "\x1b[?1000h\x1b[?1006h";

#if !defined(_WIN32)
void on_signal(int sig) {
    Terminal::restore_all();
    // Re-raise with default handler so exit status is correct.
    signal(sig, SIG_DFL);
    raise(sig);
}

// SIGHUP, SIGTERM, SIGINT: ask the app to save the user's work and leave
// (Terminal::hangup). Repeats change nothing (one hangup can signal twice:
// the session leader, then its process group); the alarm 5 s later ends
// the program at once (on_signal) if the cleanup has not. Only
// async-signal-safe calls here.
void on_stop(int sig) {
    if (g_hangup.load() != 0) return;
    g_hangup.store(sig);
    signal(SIGALRM, on_signal);
    alarm(5);
    if (g_wake[1] >= 0) {
        const char b = 2;
        const ssize_t r = ::write(g_wake[1], &b, 1);
        (void)r;
    }
}

void on_winch(int) {
    g_winch.store(true);
    if (g_wake[1] >= 0) {
        const char b = 1;
        const ssize_t r = ::write(g_wake[1], &b, 1);
        (void)r;
    }
}
#endif

void restore_at_exit() { Terminal::restore_all(); }

#if defined(_WIN32)
// The console is closing (window closed, log-off, shut-down) or Ctrl+Break:
// ask the app to save the user's work and leave, and wait for it. When this
// returns the system ends the process (close, log-off, shut-down: within
// about 5 s in any case).
BOOL WINAPI on_console_event(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            break;
        default:
            return FALSE;
    }
    if (g_hangup.exchange(1) == 0 && g_stop_event != nullptr) SetEvent(g_stop_event);
    if (g_done_event != nullptr) WaitForSingleObject(g_done_event, 4500);
    return TRUE;
}

// Log-off and shut-down. The console sends CTRL_LOGOFF_EVENT and
// CTRL_SHUTDOWN_EVENT only to programs that have not loaded user32 (this one
// has, for the clipboard); such a program learns of them from its windows,
// as documented under SetConsoleCtrlHandler. A hidden top-level window (a
// message-only one gets no session messages) on a thread of its own takes
// WM_ENDSESSION down the same path as the console's events: the work is
// kept (or dropped, as set) before it returns, after which Windows may end
// the process at any moment.
LRESULT CALLBACK end_session_proc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_QUERYENDSESSION) return TRUE;  // never stands in the way
    if (msg == WM_ENDSESSION) {
        if (wp != 0) on_console_event(CTRL_LOGOFF_EVENT);
        return 0;
    }
    return DefWindowProcW(w, msg, wp, lp);
}

DWORD WINAPI end_session_thread(LPVOID) {
    WNDCLASSW wc;
    std::memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = end_session_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"SecraxisEndSession";
    if (RegisterClassW(&wc) == 0) return 0;
    if (CreateWindowExW(0, wc.lpszClassName, L"Secraxis", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr,
                        wc.hInstance, nullptr) == nullptr)
        return 0;
    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) DispatchMessageW(&m);
    return 0;
}
#endif

ColorDepth detect_color(const TerminalOptions& opt) {
    if (opt.no_color) return ColorDepth::None;
    const char* nc = std::getenv("NO_COLOR");  // https://no-color.org
    if (nc != nullptr && nc[0] != '\0') return ColorDepth::None;
#if defined(_WIN32)
    return ColorDepth::TrueColor;  // VT processing implies 24-bit support
#else
    const char* ct = std::getenv("COLORTERM");
    if (ct != nullptr && (std::strcmp(ct, "truecolor") == 0 || std::strcmp(ct, "24bit") == 0))
        return ColorDepth::TrueColor;
    const char* term = std::getenv("TERM");
    if (term != nullptr && std::strstr(term, "256color") != nullptr)
        return ColorDepth::Ansi256;
    return ColorDepth::Ansi16;
#endif
}

// Terminals known to ship complete fonts or font fallback, so the Rich glyph
// tier (rounded corners, check marks, braille) never renders as tofu. The
// legacy Windows console and the Linux VT get the WGL4-only Basic tier.
bool modern_terminal() {
    static const char* kVars[] = {"WT_SESSION", "TERM_PROGRAM", "KITTY_WINDOW_ID",
                                  "WEZTERM_EXECUTABLE", "ALACRITTY_SOCKET",
                                  "ALACRITTY_LOG", "VTE_VERSION", "KONSOLE_VERSION",
                                  "GHOSTTY_RESOURCES_DIR"};
    for (const char* v : kVars) {
        const char* e = std::getenv(v);
        if (e != nullptr && e[0] != '\0') return true;
    }
#if defined(_WIN32)
    // Windows Terminal reached through the Windows 11 default-terminal handoff
    // (double-clicking the .exe) sets no WT_SESSION. Every ConPTY host gives
    // the console a hidden "PseudoConsoleWindow", where the legacy console
    // host has a "ConsoleWindowClass" window.
    if (HWND w = GetConsoleWindow()) {
        wchar_t cls[32] = {};
        if (GetClassNameW(w, cls, 32) > 0 && std::wcscmp(cls, L"PseudoConsoleWindow") == 0)
            return true;
    }
#else
    const char* ct = std::getenv("COLORTERM");
    if (ct != nullptr && (std::strcmp(ct, "truecolor") == 0 || std::strcmp(ct, "24bit") == 0))
        return true;
    const char* term = std::getenv("TERM");
    if (term != nullptr) {
        for (const char* t : {"kitty", "alacritty", "foot", "ghostty", "wezterm"})
            if (std::strstr(term, t) != nullptr) return true;
    }
#endif
    return false;
}

// COLORFGBG="fg;bg" (rxvt, Konsole): a light background is 7 or 9..15.
int theme_from_env() {
    const char* v = std::getenv("COLORFGBG");
    if (v == nullptr) return 0;
    const char* semi = std::strrchr(v, ';');
    if (semi == nullptr) return 0;
    const int bg = std::atoi(semi + 1);
    return (bg == 7 || bg >= 9) ? 2 : 1;
}

#if !defined(_WIN32)
// Parse "ESC ] 11 ; rgb:RRRR/GGGG/BBBB" anywhere in buf. Returns 2 (light),
// 1 (dark) or 0 (not found).
int theme_from_osc11(const char* buf, size_t n) {
    static const char kTag[] = "\x1b]11;rgb:";
    const size_t tl = sizeof(kTag) - 1;
    for (size_t i = 0; i + tl < n; ++i) {
        if (std::memcmp(buf + i, kTag, tl) != 0) continue;
        unsigned comp[3] = {0, 0, 0};
        size_t p = i + tl;
        for (int c = 0; c < 3; ++c) {
            unsigned v = 0;
            int digits = 0;
            while (p < n && digits < 4) {
                const char ch = buf[p];
                int d = -1;
                if (ch >= '0' && ch <= '9') d = ch - '0';
                else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                if (d < 0) break;
                v = v * 16 + static_cast<unsigned>(d);
                ++digits;
                ++p;
            }
            if (digits == 0) return 0;
            // Scale to 8 bits whatever the digit count.
            comp[c] = digits == 1 ? v * 17 : (digits == 2 ? v : v >> (4 * (digits - 2)));
            if (c < 2) {
                if (p >= n || buf[p] != '/') return 0;
                ++p;
            }
        }
        const unsigned luma = (299 * comp[0] + 587 * comp[1] + 114 * comp[2]) / 1000;
        return luma >= 128 ? 2 : 1;
    }
    return 0;
}
#endif

}  // namespace

Terminal::Terminal(const TerminalOptions& opt) {
#if defined(_WIN32)
    g_hin = GetStdHandle(STD_INPUT_HANDLE);
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hin == INVALID_HANDLE_VALUE || g_hout == INVALID_HANDLE_VALUE) return;
    if (!GetConsoleMode(g_hin, &g_in_mode) ||
        !GetConsoleMode(g_hout, &g_out_mode))
        return;
    g_in_cp = GetConsoleCP();
    g_out_cp = GetConsoleOutputCP();
    if (!SetConsoleMode(g_hout, g_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        error_ = "This console cannot process terminal sequences. Use Windows Terminal, "
                 "or turn off \"Use legacy console\" in the console's properties.";
        return;
    }
    SetConsoleMode(g_hout, g_out_mode);
#else
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return;
    const char* term = std::getenv("TERM");
    if (term != nullptr && std::strcmp(term, "dumb") == 0) {
        error_ = "This terminal (TERM=dumb) cannot address the screen.";
        return;
    }
    if (tcgetattr(STDIN_FILENO, &g_orig) != 0) return;
    g_have_orig = true;
#endif
    ok_ = true;
    mouse_ = opt.mouse;
    static bool hook = false;
    if (!hook) {
        std::atexit(restore_at_exit);
        hook = true;
    }
    enter_raw();
    probe(opt);
}

Terminal::~Terminal() {
    decoder_.clear();
    leave_raw();
}

void Terminal::enter_raw() {
    if (!ok_ || entered_) return;
#if defined(_WIN32)
    // Raw records (no line mode, echo or Ctrl+C processing), resize events,
    // and QuickEdit off: a mouse selection would otherwise block every write
    // until a key is pressed, freezing the screen with a secret revealed.
    DWORD in = g_in_mode;
    in &= ~static_cast<DWORD>(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT |
                              ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE |
                              ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_MOUSE_INPUT);
    in |= ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS;
    if (mouse_) in |= ENABLE_MOUSE_INPUT;
    DWORD out = g_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                DISABLE_NEWLINE_AUTO_RETURN;
    // VT input: keys arrive as the byte stream a POSIX terminal sends.
    // Windows Terminal (Windows 11) and the classic console from Windows 11
    // 24H2 mark pastes (bracketed paste), so pasted text can never act as a
    // command; in older classic consoles a paste is indistinguishable from typing.
    if (g_stop_event == nullptr) {
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        SetConsoleCtrlHandler(on_console_event, TRUE);
        if (HANDLE th = CreateThread(nullptr, 0, end_session_thread, nullptr, 0, nullptr))
            CloseHandle(th);
    }
    vt_input_ = SetConsoleMode(g_hin, in | ENABLE_VIRTUAL_TERMINAL_INPUT) != 0;
    if (!vt_input_) SetConsoleMode(g_hin, in);
    if (!SetConsoleMode(g_hout, out))
        SetConsoleMode(g_hout, g_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#else
    struct termios raw = g_orig;
    raw.c_lflag &= ~static_cast<tcflag_t>(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_iflag &= ~static_cast<tcflag_t>(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
    raw.c_oflag &= ~static_cast<tcflag_t>(OPOST);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    signal(SIGINT, on_stop);
    signal(SIGTERM, on_stop);
    // A clipboard tool that exits early must not kill us with SIGPIPE (the
    // terminal would stay raw): writes report EPIPE instead.
    signal(SIGPIPE, SIG_IGN);
#if defined(SIGHUP)
    signal(SIGHUP, on_stop);
#endif
    if (g_wake[0] < 0 && pipe(g_wake) == 0) {
        for (int fd : g_wake) {
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
    }
    signal(SIGWINCH, on_winch);
#endif
    write_cstr(ENTER_SEQ);
#if defined(_WIN32)
    if (mouse_ && vt_input_) write_cstr(MOUSE_ON);
#else
    if (mouse_) write_cstr(MOUSE_ON);
#endif
    entered_ = true;
    g_needs_restore.store(true);
}

void Terminal::leave_raw() noexcept {
    if (!entered_) return;
    write_cstr(LEAVE_SEQ);
#if defined(_WIN32)
    SetConsoleMode(g_hin, g_in_mode);
    SetConsoleMode(g_hout, g_out_mode);
    SetConsoleCP(g_in_cp);
    SetConsoleOutputCP(g_out_cp);
    if (g_font_changed) {
        SetCurrentConsoleFontEx(g_hout, FALSE, &g_font_orig);
        g_font_changed = false;
    }
#else
    signal(SIGWINCH, SIG_DFL);
    if (g_have_orig) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig);
#endif
    entered_ = false;
    g_needs_restore.store(false);
}

bool Terminal::hangup() noexcept { return g_hangup.load() != 0; }

void Terminal::finish_hangup() noexcept {
    const int sig = g_hangup.load();
    if (sig == 0) return;
    restore_all();
#if defined(_WIN32)
    if (g_done_event != nullptr) SetEvent(g_done_event);
#else
    alarm(0);
    signal(sig, SIG_DFL);
    raise(sig);
#endif
}

void Terminal::restore_all() noexcept {
    if (!g_needs_restore.load()) return;
    write_cstr(LEAVE_SEQ);
#if defined(_WIN32)
    if (g_hin != INVALID_HANDLE_VALUE) SetConsoleMode(g_hin, g_in_mode);
    if (g_hout != INVALID_HANDLE_VALUE) SetConsoleMode(g_hout, g_out_mode);
    SetConsoleCP(g_in_cp);
    SetConsoleOutputCP(g_out_cp);
    if (g_font_changed && g_hout != INVALID_HANDLE_VALUE) {
        SetCurrentConsoleFontEx(g_hout, FALSE, &g_font_orig);
        g_font_changed = false;
    }
#else
    if (g_have_orig) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig);
#endif
    g_needs_restore.store(false);
}

// ---------------------------------------------------------------------------
// Startup probe
// ---------------------------------------------------------------------------
#if defined(_WIN32)
namespace {
// Columns the console advances for one glyph (its own width decision: the
// same logic Windows Terminal uses through ConPTY). -1 if unknown.
int win_advance(const char* utf8) {
    CONSOLE_SCREEN_BUFFER_INFO a, b;
    write_cstr("\x1b[H");
    if (!GetConsoleScreenBufferInfo(g_hout, &a)) return -1;
    write_cstr(utf8);
    if (!GetConsoleScreenBufferInfo(g_hout, &b)) return -1;
    if (b.dwCursorPosition.Y != a.dwCursorPosition.Y) return -1;
    return b.dwCursorPosition.X - a.dwCursorPosition.X;
}

// The classic console window (conhost), as opposed to a ConPTY host such as
// Windows Terminal, which draws with its own fonts.
bool classic_console() {
    HWND w = GetConsoleWindow();
    if (w == nullptr) return false;
    wchar_t cls[32] = {};
    return GetClassNameW(w, cls, 32) > 0 && std::wcscmp(cls, L"ConsoleWindowClass") == 0;
}

// True when the classic console's font draws an accented letter and a
// symbol one cell wide. The default font of Chinese, Japanese and Korean
// systems (NSimSun, MS Gothic, ...) and the raster fonts draw them two cells
// wide, which forces ASCII stand-ins and spreads out accented text: then the
// console switches to Consolas for this session (restored on exit; Windows
// links CJK glyphs in from the system fonts) unless keep_font.
bool console_font_ok(bool keep_font) {
    static const char kAccent[] = "\xC3\xA9";  // e acute
    static const char kDot[] = "\xE2\x97\x8F";    // black circle
    if (win_advance(kAccent) == 1 && win_advance(kDot) == 1) return true;
    if (keep_font) return false;
    CONSOLE_FONT_INFOEX cur = {};
    cur.cbSize = sizeof(cur);
    if (!GetCurrentConsoleFontEx(g_hout, FALSE, &cur)) return false;
    CONSOLE_FONT_INFOEX next = {};
    next.cbSize = sizeof(next);
    next.dwFontSize.Y = cur.dwFontSize.Y >= 12 ? cur.dwFontSize.Y : 16;
    next.FontFamily = FF_MODERN | TMPF_TRUETYPE;
    next.FontWeight = FW_NORMAL;
    std::wcscpy(next.FaceName, L"Consolas");
    if (!SetCurrentConsoleFontEx(g_hout, FALSE, &next)) return false;
    g_font_orig = cur;
    g_font_changed = true;
    return win_advance(kAccent) == 1 && win_advance(kDot) == 1;
}
}  // namespace
#else
namespace {
// Collects terminal replies. Cursor-position reports are taken out in order;
// everything else (keys typed during startup, the color reply) goes to the
// decoder, which discards string sequences. Wiped when done.
class ReplyReader {
  public:
    explicit ReplyReader(InputDecoder* dec) : dec_(dec) {}
    ~ReplyReader() { flush(); }

    // 1-based column of the next CPR, or -1 after timeout_ms. With `theme`,
    // an OSC 11 color reply seen before the CPR sets *theme; with `id`, the
    // identification replies seen before it fill *id. With `row`, a CPR from
    // another row is a late answer to an earlier question: set aside.
    int next_cpr(int timeout_ms, int* theme = nullptr, TermIdent* id = nullptr, int row = 0) {
        int waited = 0;
        for (;;) {
            int col = 0, at_row = 0;
            while ((col = take_cpr(theme, id, &at_row)) != 0 && row != 0 && at_row != row) {
            }
            if (col != 0) return col;
            if (waited >= timeout_ms || n_ == sizeof(buf_)) return -1;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(STDIN_FILENO, &rf);
            struct timeval tv {0, 20000};
            waited += 20;
            if (select(STDIN_FILENO + 1, &rf, nullptr, nullptr, &tv) <= 0) continue;
            const ssize_t r = ::read(STDIN_FILENO, buf_ + n_, sizeof(buf_) - n_);
            if (r > 0) n_ += static_cast<size_t>(r);
        }
    }

    // Reads on for up to timeout_ms until the DA2 answer is in: the
    // Microsoft consoles over SSH can deliver it after the CPR that should
    // have followed it. Every terminal of note answers DA2.
    void wait_ident(int timeout_ms, int* theme, TermIdent* id) {
        int waited = 0;
        for (;;) {
            scan_term_ident(buf_, n_, id);
            const int t = theme_from_osc11(buf_, n_);
            if (t != 0) *theme = t;
            if (id->da2[0] >= 0 || waited >= timeout_ms || n_ == sizeof(buf_)) return;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(STDIN_FILENO, &rf);
            struct timeval tv {0, 20000};
            waited += 20;
            if (select(STDIN_FILENO + 1, &rf, nullptr, nullptr, &tv) <= 0) continue;
            const ssize_t r = ::read(STDIN_FILENO, buf_ + n_, sizeof(buf_) - n_);
            if (r > 0) n_ += static_cast<size_t>(r);
        }
    }

    void flush() {
        if (n_ > 0) dec_->feed(buf_, n_);
        secure_wipe(buf_, sizeof(buf_));
        n_ = 0;
    }

  private:
    // Extract the first ESC [ row ; col R in the buffer: returns its column
    // (its row in *row_out), or 0 if there is none yet.
    int take_cpr(int* theme, TermIdent* id, int* row_out) {
        for (size_t i = 0; i + 1 < n_; ++i) {
            if (buf_[i] != '\x1b' || buf_[i + 1] != '[') continue;
            size_t p = i + 2;
            int row = 0, col = 0;
            bool semi = false, digits = false;
            while (p < n_) {
                const char c = buf_[p];
                if (c >= '0' && c <= '9') {
                    int& v = semi ? col : row;
                    if (v < 10000) v = v * 10 + (c - '0');
                    digits = true;
                } else if (c == ';' && !semi) {
                    semi = true;
                } else {
                    break;
                }
                ++p;
            }
            if (p < n_ && buf_[p] == 'R' && semi && digits && col > 0) {
                if (theme != nullptr) {
                    const int t = theme_from_osc11(buf_, i);
                    if (t != 0) *theme = t;
                }
                if (id != nullptr) scan_term_ident(buf_, i, id);
                if (i > 0) dec_->feed(buf_, i);
                const size_t used = p + 1;
                std::memmove(buf_, buf_ + used, n_ - used);
                secure_wipe(buf_ + n_ - used, used);
                n_ -= used;
                *row_out = row;
                return col;
            }
        }
        return 0;
    }

    InputDecoder* dec_;
    char buf_[2048];
    size_t n_ = 0;
};

// An SSH login often has no locale at all (C/POSIX): then the terminal itself
// decides, by measurement, whether UTF-8 is drawn as text.
bool locale_is_c() {
    const char* cs = nl_langinfo(CODESET);
    return cs != nullptr && (std::strcmp(cs, "ANSI_X3.4-1968") == 0 ||
                             std::strcmp(cs, "US-ASCII") == 0 || std::strcmp(cs, "ASCII") == 0);
}

bool locale_is_utf8() {
    std::setlocale(LC_CTYPE, "");
    const char* cs = nl_langinfo(CODESET);
    if (cs == nullptr) return false;
    return std::strcmp(cs, "UTF-8") == 0 || std::strcmp(cs, "utf8") == 0 ||
           std::strcmp(cs, "UTF8") == 0;
}
}  // namespace
#endif

namespace {
// For a Windows console whose font draws symbols two cells wide (the Chinese,
// Japanese and Korean default fonts) when that font cannot be switched (over
// SSH, or --keep-font).
const char* const kConsoleFontNote =
    "Font draws symbols wide: use Consolas or Windows Terminal.";
}  // namespace

void Terminal::probe(const TerminalOptions& opt) {
    caps_.color = detect_color(opt);
#if defined(_WIN32)
    caps_.width.utf8 = !opt.force_ascii;
#else
    caps_.width.utf8 = !opt.force_ascii && locale_is_utf8();
    const bool try_utf8 = !opt.force_ascii && !caps_.width.utf8 && locale_is_c();
#endif
    int theme = opt.theme;
    if (theme == 0) theme = theme_from_env();
    caps_.glyphs = GlyphTier::Ascii;
    // Gate: a terminal that cannot report its cursor cannot be measured, so it
    // gets the ASCII set. U+4E2D then tells whether wide (CJK) characters
    // really take two cells.
    static const char kBox[] = "\xE2\x94\x80";
    static const char kCjk[] = "\xE4\xB8\xAD";
#if defined(_WIN32)
    if (!caps_.width.utf8) {
        caps_.light = (theme == 2);
        return;
    }
    // The classic console gets the full set too once its font is right.
    const bool font_ok = classic_console() && console_font_ok(opt.keep_font);
    const bool rich = opt.glyphs == 2 || (opt.glyphs == 0 && (modern_terminal() || font_ok));
    glyphs_ = glyphs_for(rich ? GlyphTier::Rich : GlyphTier::Basic);
    const std::vector<std::string> probes = glyph_probe_strings(glyphs_);
    std::vector<int> adv(probes.size(), -1);
    const int gate = win_advance(kBox);
    int wide = -1;
    if (gate >= 0) {
        wide = win_advance(kCjk);
        for (size_t k = 0; k < probes.size(); ++k) adv[k] = win_advance(probes[k].c_str());
    }
#else
    if (!caps_.width.utf8 && !try_utf8) {
        caps_.light = (theme == 2);
        return;
    }
    ReplyReader rr(&decoder_);
    // Each step measures on a row of its own: the gate on row 1, the CJK
    // character on 2, the identification's closing report on 3, the glyph
    // burst on 4. A late answer to an earlier step then shows by its row and
    // is set aside, instead of being taken for the next step's (that shifted
    // every later measurement by one: CJK text drawn as '?', separators
    // lost). A terminal of fewer rows gets them all on row 1, as before.
    struct winsize ws;
    const bool own_rows = ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row >= 4;
    auto row_of = [&](int step) { return own_rows ? step : 0; };  // 0: any row
    auto at_row = [&](int step) {
        char at[16];
        std::snprintf(at, sizeof(at), "\x1b[%d;1H", own_rows ? step : 1);
        return std::string(at);
    };
    auto measure = [&](int step, const std::string& s) {
        std::string q = at_row(step);
        q += s;
        q += "\x1b[6n";
        write_str(q.data(), q.size());
    };
    measure(1, kBox);
    // Over SSH every answer is a round trip, which a busy link or host can
    // stretch past what a local terminal ever takes: there the first answer
    // may take 2 s (none at all still means the ASCII set), and each later
    // one gets three times what it took. (At 400 ms, a slow round trip from
    // the Windows console made the program start in ASCII, showing non-ASCII
    // names as '?'.) Local terminals answer in milliseconds: unchanged.
    const bool over_ssh = std::getenv("SSH_CONNECTION") != nullptr ||
                          std::getenv("SSH_TTY") != nullptr ||
                          std::getenv("SSH_CLIENT") != nullptr;
    const auto asked = std::chrono::steady_clock::now();
    const int gcol = rr.next_cpr(over_ssh ? 2000 : 400, nullptr, nullptr, row_of(1));
    const int round_trip = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::steady_clock::now() - asked)
                                                .count());
    auto reply_wait = [&](int usual) {
        const int scaled = 3 * round_trip;
        return scaled > usual ? (scaled < 2000 ? scaled : 2000) : usual;
    };
    const int gate = gcol < 0 ? -1 : gcol - 1;
    // Without a locale, the terminal shows whether it decodes UTF-8: one
    // cell for the three bytes of a box line.
    if (try_utf8 && gate == 1) caps_.width.utf8 = true;
    std::vector<std::string> probes;
    std::vector<int> adv;
    int wide = -1;
    bool microsoft_seen = false, vte_seen = false;
    if (gate >= 0 && caps_.width.utf8) {
        measure(2, kCjk);
        const int wcol = rr.next_cpr(reply_wait(400), nullptr, nullptr, row_of(2));
        wide = wcol < 0 ? -1 : wcol - 1;
        // Who is drawing (XTVERSION, DA2) and, unless set, its background
        // (OSC 11); the CPR after them bounds the wait where nothing answers.
        std::string q;
        if (opt.theme == 0) q += "\x1b]11;?\x1b\\";
        q += "\x1b[>0q\x1b[>c";
        q += at_row(3);
        q += "\x1b[6n";
        write_str(q.data(), q.size());
        TermIdent id;
        int t = 0;
        rr.next_cpr(reply_wait(400), &t, &id, row_of(3));
        if (id.da2[0] < 0) rr.wait_ident(reply_wait(250), &t, &id);
        if (t != 0 && opt.theme == 0) theme = t;
        const TermTraits tr = term_traits(id);
        // The full set on every UTF-8 terminal (each glyph is still measured
        // below), but for the Linux text console and PuTTY; the emoji flag only
        // where the terminal is known to draw them.
        const char* term = std::getenv("TERM");
        const bool vt_console = term != nullptr && std::strcmp(term, "linux") == 0;
        const bool rich = opt.glyphs == 2 || (opt.glyphs == 0 && !vt_console && !tr.plain);
        glyphs_ = glyphs_for(rich ? GlyphTier::Rich : GlyphTier::Basic);
        if (!modern_terminal() && !tr.emoji) glyphs_.emoji = false;
        caps_.clipboard_escapes = tr.clipboard_escapes;
        microsoft_seen = tr.microsoft;
        vte_seen = tr.vte;
        // Colours too, where TERM and COLORTERM undersell the terminal
        // (xterm says "xterm" yet has 256 colours). Never past --no-color.
        if (caps_.color == ColorDepth::Ansi16 || caps_.color == ColorDepth::Ansi256) {
            if (tr.truecolor)
                caps_.color = ColorDepth::TrueColor;
            else if (caps_.color == ColorDepth::Ansi16 && tr.color256)
                caps_.color = ColorDepth::Ansi256;
        }
        probes = glyph_probe_strings(glyphs_);
        adv.assign(probes.size(), -1);
        // All glyphs in one burst on row 4, then their replies in order, 5 s
        // in all at most. After an answer that does not come in time the
        // rest stay unknown (drawn plainly): a late answer would otherwise be
        // taken for the next glyph's, and a terminal that stops answering
        // costs no more waiting.
        for (const std::string& s : probes) measure(4, s);
        const auto burst_end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (size_t k = 0; k < probes.size(); ++k) {
            const int left = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  burst_end - std::chrono::steady_clock::now())
                                                  .count());
            const int wait = reply_wait(300) < left ? reply_wait(300) : left;
            const int col = wait > 0 ? rr.next_cpr(wait, nullptr, nullptr, row_of(4)) : -1;
            if (col < 0) break;
            adv[k] = col - 1;
        }
    }
    rr.flush();
#endif
    if (gate >= 0 && caps_.width.utf8 && !probes.empty()) {
        caps_.width.wide_ok = (wide != 1);
        if (gate == 1) caps_.width.add_narrow(U'\x2500');
        apply_glyph_probe(probes, adv, &glyphs_, &caps_.width);
        caps_.glyphs = glyphs_.tier;
        caps_.glyph_set = &glyphs_;
        if (caps_.width.ambiguous_wide) {
#if defined(_WIN32)
            caps_.look_note = kConsoleFontNote;
#else
            // Short enough for the start page's line (LAUNCHER_TIP_MAX).
            caps_.look_note = microsoft_seen ? kConsoleFontNote
                              : vte_seen     ? "Symbols are wide here: set ambiguous-width to narrow."
                                             : "This terminal draws symbols wide; plain ones stand in.";
#endif
        }
    }
    caps_.light = (theme == 2);
    write_cstr("\x1b[0m\x1b[2J\x1b[H");
}

// ---------------------------------------------------------------------------
// Size, input, output
// ---------------------------------------------------------------------------
TermSize Terminal::size() {
    TermSize s;
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(g_hout, &info)) {
        s.cols = info.srWindow.Right - info.srWindow.Left + 1;
        s.rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        s.cols = ws.ws_col;
        s.rows = ws.ws_row;
    }
#endif
    if (s.cols < 1) s.cols = 1;
    if (s.rows < 1) s.rows = 1;
    return s;
}

bool Terminal::take_resize() noexcept {
#if !defined(_WIN32)
    if (g_winch.exchange(false)) resized_ = true;
#endif
    const bool r = resized_;
    resized_ = false;
    return r;
}

#if defined(_WIN32)
namespace {
bool translate_key(const KEY_EVENT_RECORD& ke, Utf16Assembler* u16, KeyEvent* out) {
    using C = KeyEvent::Code;
    uint8_t mods = (ke.dwControlKeyState & CAPSLOCK_ON) ? KEYMOD_CAPS_LOCK : 0;
    if (!ke.bKeyDown) {
        // Alt+numpad entry delivers its character on the Alt key release.
        if (ke.wVirtualKeyCode != VK_MENU || ke.uChar.UnicodeChar == 0) return false;
    } else {
        switch (ke.wVirtualKeyCode) {
            case VK_RETURN: *out = KeyEvent::key(C::Enter, mods); return true;
            case VK_ESCAPE: *out = KeyEvent::key(C::Esc, mods); return true;
            case VK_UP: *out = KeyEvent::key(C::Up, mods); return true;
            case VK_DOWN: *out = KeyEvent::key(C::Down, mods); return true;
            case VK_LEFT: *out = KeyEvent::key(C::Left, mods); return true;
            case VK_RIGHT: *out = KeyEvent::key(C::Right, mods); return true;
            case VK_PRIOR: *out = KeyEvent::key(C::PageUp, mods); return true;
            case VK_NEXT: *out = KeyEvent::key(C::PageDown, mods); return true;
            case VK_HOME: *out = KeyEvent::key(C::Home, mods); return true;
            case VK_END: *out = KeyEvent::key(C::End, mods); return true;
            case VK_BACK: *out = KeyEvent::key(C::Backspace, mods); return true;
            case VK_DELETE: *out = KeyEvent::key(C::Del, mods); return true;
            case VK_TAB:
                *out = KeyEvent::key((ke.dwControlKeyState & SHIFT_PRESSED) ? C::BackTab
                                                                            : C::Tab,
                                     mods);
                return true;
            default:
                break;
        }
    }
    const wchar_t u = ke.uChar.UnicodeChar;
    if (u == 0) return false;
    if (u < 0x20) {
        if (u >= 1 && u <= 26) {
            *out = KeyEvent::chr(static_cast<char32_t>(U'a' + (u - 1)),
                                 static_cast<uint8_t>(mods | KEYMOD_CTRL));
            return true;
        }
        return false;
    }
    char32_t cp = 0;
    if (!u16->push(static_cast<uint16_t>(u), &cp)) return false;
    *out = KeyEvent::chr(cp, mods);
    return true;
}
}  // namespace
#endif

#if defined(_WIN32)
// Takes up to a batch of the console's queued records. Characters (VT input)
// go to the decoder; a record that is an event by itself (a mouse record, a
// key with no character, any key without VT input) is returned at once.
bool Terminal::read_records(KeyEvent* out) {
    DWORD pending = 0;
    for (int batch = 0; batch < 256 && GetNumberOfConsoleInputEvents(g_hin, &pending) &&
                        pending > 0;
         ++batch) {
        INPUT_RECORD rec;
        DWORD got = 0;
        if (!ReadConsoleInputW(g_hin, &rec, 1, &got) || got == 0) break;
        if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT) {
            resized_ = true;
            continue;
        }
        if (rec.EventType == MOUSE_EVENT) {
            const MOUSE_EVENT_RECORD& me = rec.Event.MouseEvent;
            CONSOLE_SCREEN_BUFFER_INFO info;
            int ox = 0, oy = 0;
            if (GetConsoleScreenBufferInfo(g_hout, &info)) {
                ox = info.srWindow.Left;
                oy = info.srWindow.Top;
            }
            const int16_t mx = static_cast<int16_t>(me.dwMousePosition.X - ox);
            const int16_t my = static_cast<int16_t>(me.dwMousePosition.Y - oy);
            if (me.dwEventFlags & MOUSE_WHEELED) {
                const short delta = static_cast<short>(HIWORD(me.dwButtonState));
                *out = KeyEvent::mouse(delta > 0 ? KeyEvent::Pointer::WheelUp
                                                 : KeyEvent::Pointer::WheelDown,
                                       0, mx, my);
                return true;
            }
            if (me.dwEventFlags & MOUSE_MOVED) continue;
            const unsigned long now_buttons = me.dwButtonState & 0x7u;
            const unsigned long pressed = now_buttons & ~buttons_;
            const unsigned long released = buttons_ & ~now_buttons;
            buttons_ = now_buttons;
            if (pressed & FROM_LEFT_1ST_BUTTON_PRESSED) {
                *out = KeyEvent::mouse(KeyEvent::Pointer::Press, 0, mx, my);
                return true;
            }
            if (released & FROM_LEFT_1ST_BUTTON_PRESSED) {
                *out = KeyEvent::mouse(KeyEvent::Pointer::Release, 0, mx, my);
                return true;
            }
            continue;
        }
        if (rec.EventType != KEY_EVENT) continue;
        const KEY_EVENT_RECORD& ke = rec.Event.KeyEvent;
        // Records with a key code carry the keyboard state (with VT input,
        // the key-up records do).
        if (ke.wVirtualKeyCode != 0) caps_lock_ = (ke.dwControlKeyState & CAPSLOCK_ON) != 0;
        bool hit = false;
        if (vt_input_ && ke.bKeyDown && ke.uChar.UnicodeChar != 0) {
            char32_t cp = 0;
            if (utf16_.push(static_cast<uint16_t>(ke.uChar.UnicodeChar), &cp)) {
                char b[4];
                decoder_.feed(b, utf8_encode(cp, b));
                secure_wipe(b, sizeof(b));
            }
        } else if (!vt_input_ || ke.uChar.UnicodeChar == 0) {
            hit = translate_key(ke, &utf16_, out);
        }
        secure_wipe(&rec, sizeof(rec));
        if (hit) return true;
    }
    return false;
}
#endif

bool Terminal::read_key(KeyEvent* out, int timeout_ms) {
    if (!ok_) return false;
#if defined(_WIN32)
    // With VT input, characters (keys, pastes, mouse reports) go through the
    // decoder, as on POSIX; records that carry no character (keys a console
    // left untranslated, mouse records) are translated directly.
    auto with_caps = [&]() {
        if (caps_lock_) out->mods = static_cast<uint8_t>(out->mods | KEYMOD_CAPS_LOCK);
        return true;
    };
    if (g_hangup.load() != 0) return false;
    if (decoder_.next(out, false)) return with_caps();
    for (;;) {
        // The rest of an escape sequence gets a moment (a lone ESC is the
        // Esc key); see InputDecoder::next for what a flush may resolve.
        const bool partial = decoder_.has_partial();
        const HANDLE waits[2] = {g_hin, g_stop_event};
        const DWORD wait = WaitForMultipleObjects(
            g_stop_event != nullptr ? 2 : 1, waits, FALSE,
            partial                ? static_cast<DWORD>(decoder_.partial_wait_ms())
            : timeout_ms < 0 ? INFINITE
                             : static_cast<DWORD>(timeout_ms));
        if (g_hangup.load() != 0) return false;
        if (wait != WAIT_OBJECT_0) {
            if (partial && decoder_.next(out, !decoder_.in_paste())) return with_caps();
            return false;
        }
        if (read_records(out)) return true;
        if (decoder_.next(out, false)) return with_caps();
        if (!decoder_.has_partial()) return false;
    }
#else
    if (g_hangup.load() != 0) return false;
    if (decoder_.next(out, false)) return true;
    char buf[1024];
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(STDIN_FILENO, &rf);
    int maxfd = STDIN_FILENO;
    if (g_wake[0] >= 0) {
        FD_SET(g_wake[0], &rf);
        if (g_wake[0] > maxfd) maxfd = g_wake[0];
    }
    const int wait_ms = decoder_.has_partial() ? decoder_.partial_wait_ms() : timeout_ms;
    struct timeval tv;
    tv.tv_sec = wait_ms / 1000;
    tv.tv_usec = (wait_ms % 1000) * 1000;
    const int rv = select(maxfd + 1, &rf, nullptr, nullptr, wait_ms < 0 ? nullptr : &tv);
    if (rv < 0) return false;  // EINTR (e.g. SIGWINCH): caller re-polls
    if (rv == 0) return decoder_.has_partial() && decoder_.next(out, !decoder_.in_paste());
    if (g_wake[0] >= 0 && FD_ISSET(g_wake[0], &rf)) {
        char drain[16];
        while (::read(g_wake[0], drain, sizeof(drain)) > 0) {
        }
        if (g_hangup.load() != 0) return false;
        resized_ = true;
    }
    if (FD_ISSET(STDIN_FILENO, &rf)) {
        const ssize_t r = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (r > 0) decoder_.feed(buf, static_cast<size_t>(r));
        secure_wipe(buf, sizeof(buf));
    }
    if (decoder_.next(out, false)) return true;
    if (decoder_.has_partial()) {
        // Give the rest of an escape sequence a moment to arrive, then
        // resolve it (a lone ESC is the Esc key).
        FD_ZERO(&rf);
        FD_SET(STDIN_FILENO, &rf);
        const int more_ms = decoder_.partial_wait_ms();
        struct timeval tv2 {more_ms / 1000, (more_ms % 1000) * 1000};
        if (select(STDIN_FILENO + 1, &rf, nullptr, nullptr, &tv2) > 0) {
            const ssize_t r = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (r > 0) decoder_.feed(buf, static_cast<size_t>(r));
            secure_wipe(buf, sizeof(buf));
        }
        return decoder_.next(out, !decoder_.in_paste());
    }
    return false;
#endif
}

void Terminal::write(const WipeBuffer& bytes) {
    if (!ok_ || bytes.empty()) return;
    write_str(bytes.data(), bytes.size());
}

}  // namespace secraxis
