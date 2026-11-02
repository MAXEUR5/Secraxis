// tui_canvas.h — the cell grid the renderer draws into, and the styles and
// glyph sets it draws with.
//
// A Canvas is a cols×rows grid of Cells. Text enters only through
// Canvas::text(), which clusters/sanitizes via next_cluster() (tui_text.h),
// clips to a column budget, never splits a wide character, and truncates with
// the glyph set's ellipsis. Chrome (borders, bars, markers) enters through
// Canvas::glyph() and is flagged "trusted": its width was verified by the
// terminal probe, so the screen writer may stream it without re-positioning.
//
// During RevealSecret the canvas holds the revealed secret's code points, so
// its storage is wiped whenever it is resized, reset, or destroyed.
#ifndef SECRAXIS_TUI_CANVAS_H
#define SECRAXIS_TUI_CANVAS_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "secraxis/tui_text.h"

namespace secraxis {

// 0 = the terminal's default color. Otherwise bit 31 is set, bits 24-27 hold
// the ANSI-16 fallback index and bits 0-23 the 24-bit RGB value.
using Color = uint32_t;
constexpr Color rgb(uint32_t hex, uint32_t ansi16) {
    return 0x80000000u | ((ansi16 & 15u) << 24) | (hex & 0xFFFFFFu);
}

enum : uint8_t {
    ATTR_BOLD = 1,
    ATTR_DIM = 2,
    ATTR_UNDERLINE = 4,
    ATTR_REVERSE = 8,
};

struct Style {
    Color fg = 0;
    Color bg = 0;
    uint8_t attrs = 0;
};
inline bool operator==(const Style& a, const Style& b) {
    return a.fg == b.fg && a.bg == b.bg && a.attrs == b.attrs;
}
inline bool operator!=(const Style& a, const Style& b) { return !(a == b); }

// Chrome glyph tiers. Every non-ASCII glyph is drawn only after the terminal
// probe proved East Asian Ambiguous characters take one cell.
//   Basic: only characters in WGL4, the repertoire every Windows console font
//          (Consolas, Lucida Console, Courier New) and the common CJK console
//          fonts carry, so the legacy console never shows tofu boxes.
//   Rich:  rounded corners, check marks, braille spinner; used where the
//          terminal is known to have full fonts or font fallback (Windows
//          Terminal, iTerm2, kitty, WezTerm, VTE, Konsole, ...).
//   Ascii: the agenda's "+-|" set and "..." truncation.
enum class GlyphTier : uint8_t { Ascii, Basic, Rich };

struct Glyphs {
    GlyphTier tier;
    char32_t h, v, tl, tr, bl, br;   // frames
    char32_t sel_bar;                // selected-row marker
    char32_t bullet;                 // password mask
    char32_t dot;                    // separator
    char32_t thumb;                  // scrollbar thumb
    char32_t bar_full, bar_empty;    // progress and countdowns
    char32_t up, down, left, right;
    char32_t ok, fail, warn, note;   // message markers
    char32_t brand;                  // product mark
    char32_t prompt;                 // input prompt
    char32_t dot_on, dot_off;        // step indicator
    const char* ellipsis;
    const char32_t* spinner;         // animation frames, nullptr: use a bar
    int spinner_len;
    bool emoji;    // color emoji take two cells (measured; nothing draws emoji since 0.9.3)
    bool blocks;   // block and double-line glyphs for the start-page logo
    bool unicode() const noexcept { return tier != GlyphTier::Ascii; }
};
const Glyphs& glyphs_for(GlyphTier tier) noexcept;

// Terminal probe support (Terminal::probe measures; these decide). The probe
// strings are every glyph of `g`, its ellipsis, its first spinner frame, two
// East Asian Ambiguous letters, an emoji, and the logo's block glyphs. Given
// each one's measured advance (-1 if unknown), apply_glyph_probe replaces
// every glyph that is not exactly one cell with its ASCII form (the frame as
// a group), records the ambiguous symbols that are, sets ambiguous_wide from
// the letters, keeps emoji only if the emoji took exactly two cells, and keeps
// the block logo only if all its glyphs took one.
std::vector<std::string> glyph_probe_strings(const Glyphs& g);
void apply_glyph_probe(const std::vector<std::string>& probes, const std::vector<int>& adv,
                       Glyphs* g, WidthPolicy* wp);

enum : uint8_t {
    CELL_TRUSTED = 1,      // chrome glyph or ASCII: width known to the terminal
    CELL_PLACEHOLDER = 2,  // sanitized-away content
};

struct Cell {
    char32_t cp[1 + Cluster::MAX_COMBINING] = {U' ', 0, 0};
    uint8_t ncp = 1;
    uint8_t width = 1;  // 1, 2 (lead of a wide pair), 0 (its continuation)
    uint8_t flags = CELL_TRUSTED;
    Style style;
};
bool same_cell(const Cell& a, const Cell& b) noexcept;

struct Rect {
    int x = 0, y = 0, w = 0, h = 0;
    int right() const { return x + w; }
    int bottom() const { return y + h; }
};

class Canvas final {
  public:
    Canvas() = default;
    ~Canvas();
    Canvas(const Canvas&) = delete;
    Canvas& operator=(const Canvas&) = delete;

    // Resize/clear to blank cells in `base`. Wipes the previous contents.
    void reset(int cols, int rows, const Glyphs& g, const WidthPolicy& wp,
               Style base);
    // Wipe and release storage.
    void clear() noexcept;
    // Exact copy (used by the screen writer for its previous-frame mirror).
    void copy_from(const Canvas& o);

    int cols() const noexcept { return cols_; }
    int rows() const noexcept { return rows_; }
    const Glyphs& glyphs() const noexcept { return *g_; }
    const WidthPolicy& width_policy() const noexcept { return wp_; }
    const Cell& at(int x, int y) const { return cells_[idx(x, y)]; }

    void fill(Rect r, Style st);
    // Restyle cells without changing their text.
    void paint(Rect r, Style st);
    // Fade everything drawn so far into one quiet style (the scrim behind a
    // modal dialog): backgrounds are dropped, text keeps its shape.
    void fade(Style faded);
    // Draw `s` at (x, y) using at most `max_w` columns. Returns the columns
    // used. If the text does not fit and `ellipsis` is set, it ends with the
    // glyph set's ellipsis. Wide characters never straddle the limit.
    int text(int x, int y, std::string_view s, Style st, int max_w,
             bool ellipsis = true);
    // Same, drawing the byte ranges [hl[2k], hl[2k+1]) in `hl_style`
    // (search matches).
    int text_hl(int x, int y, std::string_view s, Style st, int max_w,
                const std::vector<size_t>& hl, Style hl_style);
    // Same, right-aligned so the text ends at column x + max_w.
    int text_right(int x, int y, std::string_view s, Style st, int max_w);
    void glyph(int x, int y, char32_t cp, Style st);
    void hline(int x, int y, int w, char32_t cp, Style st);
    void vline(int x, int y, int h, char32_t cp, Style st);
    void box(Rect r, Style st);

    // Hardware cursor request (for IME placement in text fields).
    void set_cursor(int x, int y) noexcept;
    bool cursor_visible() const noexcept { return cursor_on_; }
    int cursor_x() const noexcept { return cur_x_; }
    int cursor_y() const noexcept { return cur_y_; }

    // UTF-8 of one row (continuation cells skipped). Tests/diagnostics only.
    std::string row_text(int y) const;

  private:
    size_t idx(int x, int y) const {
        return static_cast<size_t>(y) * static_cast<size_t>(cols_) +
               static_cast<size_t>(x);
    }
    void put(int x, int y, const Cluster& c, Style st, uint8_t flags);
    // Keep wide pairs consistent when (x, y) is overwritten.
    void break_pair(int x, int y);

    int cols_ = 0, rows_ = 0;
    std::vector<Cell> cells_;
    const Glyphs* g_ = nullptr;
    WidthPolicy wp_;
    bool cursor_on_ = false;
    int cur_x_ = 0, cur_y_ = 0;
};

}  // namespace secraxis

#endif  // SECRAXIS_TUI_CANVAS_H
