// terminal.h — portable raw-mode terminal (agenda §14.9). Win32 Console API
// and POSIX termios/VT behind one interface. Responsibilities:
//   * enter/leave raw mode + alternate screen; ALWAYS restore on scope exit,
//     including on panic/signal (RAII + a global restore hook)
//   * disable echo (master password never echoes) and line buffering; on
//     Windows also QuickEdit, whose mouse selection would freeze output (and
//     with it the reveal timeout) until the user pressed a key
//   * disable auto-wrap, so no write can ever scroll the screen
//   * translate input into TuiMachine KeyEvents (UTF-16 console records on
//     Windows, the InputDecoder byte parser on POSIX; bracketed paste on)
//   * report window resizes (WINDOW_BUFFER_SIZE_EVENT / SIGWINCH)
//   * probe the terminal once at startup: does it draw box-drawing characters
//     (East Asian Ambiguous) in one cell, CJK in two, and is its background
//     light? The answers select the glyph set, width policy and theme.
//
// The terminal never sees secret bytes except the reveal the renderer draws;
// nothing here logs, and nothing reaches scrollback (alternate screen).
#ifndef SECRAXIS_TERMINAL_H
#define SECRAXIS_TERMINAL_H

#include <string>

#include "secraxis/tui_core.h"
#include "secraxis/tui_input.h"
#include "secraxis/tui_screen.h"

namespace secraxis {

struct TermSize {
    int cols = 80;
    int rows = 24;
};

struct TerminalOptions {
    bool force_ascii = false;   // ASCII chrome and ASCII-only text
    bool no_color = false;      // attributes only
    int theme = 0;              // 0 auto, 1 dark, 2 light
    int glyphs = 0;             // 0 auto, 1 basic, 2 rich (never past the probe)
    bool mouse = true;          // report clicks and the wheel
    bool keep_font = false;     // Windows console: never switch its font
};

class Terminal final {
  public:
    explicit Terminal(const TerminalOptions& opt);
    ~Terminal();  // restores original mode + leaves alt screen
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;

    bool ok() const noexcept { return ok_; }
    const char* error() const noexcept { return error_; }
    const TermCaps& caps() const noexcept { return caps_; }
    TermSize size();

    // Wait up to timeout_ms for input. Returns true with *out set when a key
    // arrives; returns false on timeout or when the window was resized.
    bool read_key(KeyEvent* out, int timeout_ms);
    // True once after each observed resize.
    bool take_resize() noexcept;

    // Write a frame produced by ScreenWriter (the caller wipes the buffer).
    void write(const WipeBuffer& bytes);

    // Emergency restore (idempotent); also installed as an atexit/signal
    // hook so a crash leaves the terminal usable.
    static void restore_all() noexcept;

    // True once the terminal is going away or the program was asked to stop:
    // SIGHUP (window closed, SSH connection dropped), SIGTERM, SIGINT from
    // outside (in raw mode Ctrl+C is a key); on Windows the console's close,
    // log-off and shut-down events and Ctrl+Break. read_key then returns
    // false at once. The app saves the user's work, cleans up (clipboard,
    // secrets, terminal) and calls finish_hangup(). If that takes 5 s, the
    // program ends at once with the terminal restored.
    static bool hangup() noexcept;
    // After the cleanup: end the way the signal ends a program (POSIX), or
    // let the console's handler return (Windows). No-op without a hangup.
    static void finish_hangup() noexcept;

  private:
    void enter_raw();
    void leave_raw() noexcept;
    void probe(const TerminalOptions& opt);
#if defined(_WIN32)
    bool read_records(KeyEvent* out);
#endif

    bool ok_ = false;
    bool entered_ = false;
    const char* error_ = "Secraxis requires an interactive terminal (TTY).";
    TermCaps caps_;
    Glyphs glyphs_;             // the verified set caps_.glyph_set points to
    bool resized_ = false;
    InputDecoder decoder_;      // POSIX byte stream (and probe leftovers)
    bool mouse_ = false;
#if defined(_WIN32)
    Utf16Assembler utf16_;      // Win32 console records
    unsigned long buttons_ = 0; // last mouse button state (press/release edges)
    bool vt_input_ = false;     // keys arrive as a VT byte stream (decoder_)
    bool caps_lock_ = false;    // from the records that carry key state
#endif
};

}  // namespace secraxis

#endif  // SECRAXIS_TERMINAL_H
