// tui_screen.h — terminal capabilities and the frame writer.
//
// ScreenWriter keeps a mirror of what the terminal currently shows and turns
// the next Canvas into the minimal byte stream that updates it: only changed
// cells are written, each run positioned with an absolute CUP. Text whose
// width the terminal might disagree with (any non-ASCII cluster that is not a
// probe-verified chrome glyph) is followed by a fresh CUP, and a wide
// character's right half is blanked before the character is drawn, so a
// width disagreement can at worst clip one glyph; it can never shift the rest
// of the row or a border. Auto-wrap is disabled while the TUI runs, so nothing
// can scroll the screen.
//
// Frames may contain a revealed secret, so the output buffer (WipeBuffer)
// and the mirror are wiped when reused or released.
#ifndef SECRAXIS_TUI_SCREEN_H
#define SECRAXIS_TUI_SCREEN_H

#include <cstddef>
#include <string_view>
#include <vector>

#include "secraxis/tui_canvas.h"

namespace secraxis {

enum class ColorDepth : uint8_t { None, Ansi16, Ansi256, TrueColor };

struct TermCaps {
    ColorDepth color = ColorDepth::TrueColor;
    GlyphTier glyphs = GlyphTier::Rich;  // Rich/Basic need the probe's OK
    // The tier's glyphs after the probe measured each one on the live
    // terminal (any that is not one cell wide replaced by its ASCII form).
    // nullptr: use glyphs_for(glyphs) as is (tests, tools).
    const Glyphs* glyph_set = nullptr;
    WidthPolicy width;
    bool light = false;          // light terminal background → light theme
    bool sync_output = true;     // wrap frames in DEC mode 2026
    // Whether the terminal takes clipboard escapes (OSC 52), by what it said
    // it is: 1 yes, 0 no (VTE, xterm's defaults), -1 not known.
    int8_t clipboard_escapes = -1;
    // Set when the terminal draws symbols two cells wide (a CJK console font,
    // an "ambiguous: wide" setting), so plain ones stand in: how to get the
    // full set, for the first screen. Null otherwise.
    const char* look_note = nullptr;
};

// Growable byte buffer that wipes every block it lets go of.
class WipeBuffer final {
  public:
    WipeBuffer() = default;
    ~WipeBuffer() { release(); }
    WipeBuffer(const WipeBuffer&) = delete;
    WipeBuffer& operator=(const WipeBuffer&) = delete;

    void append(const char* p, size_t n);
    void append(std::string_view s) { append(s.data(), s.size()); }
    void push(char c) { append(&c, 1); }
    const char* data() const noexcept { return buf_.data(); }
    size_t size() const noexcept { return len_; }
    bool empty() const noexcept { return len_ == 0; }
    void truncate(size_t n) noexcept;  // wipe and drop bytes past n
    void clear() noexcept;    // wipe contents, keep capacity
    void release() noexcept;  // wipe and free

  private:
    std::vector<char> buf_;
    size_t len_ = 0;
};

// Nearest xterm-256 palette index for a 24-bit color (16..255).
uint8_t rgb_to_xterm256(uint32_t rgb) noexcept;

// Append the SGR sequence selecting `st` (always starting from a reset).
void append_sgr(const Style& st, ColorDepth depth, WipeBuffer* out);

class ScreenWriter final {
  public:
    // Forget what the terminal shows; the next frame clears and repaints.
    void invalidate() noexcept { valid_ = false; }
    // Append the bytes that turn the terminal's screen into `next`.
    void diff(const Canvas& next, ColorDepth depth, bool sync, WipeBuffer* out);
    // Wipe the mirror (on exit).
    void clear() noexcept;

  private:
    Canvas prev_;
    bool valid_ = false;
    std::vector<uint8_t> dirty_;
};

}  // namespace secraxis

#endif  // SECRAXIS_TUI_SCREEN_H
