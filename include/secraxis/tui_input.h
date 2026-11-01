// tui_input.h — terminal input decoding, platform-independent so it can be
// unit-tested and fuzzed everywhere.
//
// InputDecoder turns the byte stream of a POSIX terminal (UTF-8 text, C0
// controls, CSI/SS3 key sequences, string sequences, bracketed paste) into
// KeyEvents. Bytes inside a bracketed paste become KEYMOD_PASTE characters with
// every control (including CR/LF) dropped, so a paste can neither submit a
// form nor trigger a command. Consumed bytes are wiped (a paste may carry a
// password).
//
// Utf16Assembler does the same job for the Win32 console, whose key events
// carry UTF-16 code units (astral characters arrive as surrogate pairs).
#ifndef SECRAXIS_TUI_INPUT_H
#define SECRAXIS_TUI_INPUT_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "secraxis/tui_core.h"

namespace secraxis {

class InputDecoder final {
  public:
    static constexpr size_t CAPACITY = 4096;
    InputDecoder() = default;
    ~InputDecoder() { clear(); }
    InputDecoder(const InputDecoder&) = delete;
    InputDecoder& operator=(const InputDecoder&) = delete;

    // Queue raw bytes. Returns how many were accepted (input beyond the
    // buffer's capacity is dropped).
    size_t feed(const char* p, size_t n);
    // Next complete event. With `flush` (the reader waited partial_wait_ms()
    // and nothing came), a lone ESC becomes the Esc key and a stalled string
    // reply (OSC, DCS...) is dropped. Anything else that is incomplete -- a
    // split CSI or SS3 sequence, mouse report or paste marker, a split UTF-8
    // character, anything inside a paste -- keeps waiting for its rest: its
    // tail must never be read as typed keys.
    bool next(KeyEvent* out, bool flush);
    // Bytes waiting for the rest of a sequence.
    bool has_partial() const noexcept { return len_ > 0; }
    // How long a reader waits for the rest before flushing: 25 ms for a lone
    // ESC (the Esc key must feel immediate), 1 s for a string reply.
    int partial_wait_ms() const noexcept;
    bool in_paste() const noexcept { return paste_; }
    void clear() noexcept;

  private:
    void consume(size_t n) noexcept;
    // Parse at buf_[0]. Returns >0 bytes consumed (event in *out if *have),
    // 0 if more bytes are needed.
    size_t parse(KeyEvent* out, bool* have, bool flush);
    char buf_[CAPACITY];
    size_t len_ = 0;
    bool paste_ = false;
};

// What a terminal says it is, from its answers to XTVERSION (CSI > 0 q:
// "ESC P > | name ESC \\") and DA2 (CSI > c: "ESC [ > a ; b ; c c").
struct TermIdent {
    std::string version;            // the XTVERSION text, if any
    int da2[3] = {-1, -1, -1};      // -1: no answer
};
// Collects both answers wherever they are in buf[0, n).
void scan_term_ident(const char* buf, size_t n, TermIdent* id);

// What follows from it, for a terminal that does not say so otherwise (over
// SSH no environment variable tells; some never set COLORTERM).
struct TermTraits {
    bool vte = false;          // GNOME Terminal and the other VTE terminals
    bool microsoft = false;    // Windows Terminal, the classic Windows console
    bool truecolor = false;    // 24-bit colour
    bool color256 = false;     // at least 256 colours (xterm says TERM=xterm)
    bool emoji = false;        // draws emoji two cells wide, in colour
    bool plain = false;        // one font, no fallback (PuTTY): the plain set
    int8_t clipboard_escapes = -1;  // OSC 52: 1 taken, 0 ignored, -1 unknown
};
TermTraits term_traits(const TermIdent& id);

class Utf16Assembler final {
  public:
    // Feed one UTF-16 unit. Returns true and sets *cp when a scalar is
    // complete; lone surrogates are dropped.
    bool push(uint16_t unit, char32_t* cp) noexcept;

  private:
    uint16_t high_ = 0;
};

}  // namespace secraxis

#endif  // SECRAXIS_TUI_INPUT_H
