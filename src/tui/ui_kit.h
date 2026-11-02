// ui_kit.h — the TUI's shared drawing vocabulary (internal to src/tui): the
// theme, text helpers, frames and dialogs, pills and buttons, the clickable
// footer, toasts, input strips and entry badges. renderer.cpp (vault screens)
// and launcher_view.cpp (the start page) both draw with it, so the two look
// like one product.
#ifndef SECRAXIS_TUI_UI_KIT_H
#define SECRAXIS_TUI_UI_KIT_H

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "secraxis/renderer.h"

namespace secraxis {
namespace ui {

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
struct Theme {
    Style text, strong, muted, subtle, border, accent, accent_bold, sel, sel_strong,
        sel_muted, sel_bar, ok, warn, err, secret, input, input_focus, input_hint,
        pill, pill_key, danger_pill, danger_key, primary_pill, primary_key, key,
        key_label, label, label_focus, bar_full, bar_empty, thumb, match, match_sel,
        scrim, logo_shadow;
    Style chip[8];
    Color logo_from = 0, logo_to = 0;  // wordmark gradient
    bool mono = false;
    bool truecolor = false;
};
Theme make_theme(const TermCaps& caps);
// Same style drawn over another surface's background.
Style on(Style s, const Style& surface);
// Linear blend of two 24-bit colors (t in 0..1000), keeping a's fallback.
Color blend(Color a, Color b, int t);

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------
int clampi(int v, int lo, int hi);
int width_of(const Canvas& c, std::string_view s);
std::string utf8(char32_t cp);
std::string repeat(char32_t cp, int n);
std::string seconds_text(uint64_t ms);
bool real_time(uint64_t unix_s);
std::string format_date(uint64_t unix_s, int64_t offset_s, bool with_time);
std::string relative_time(uint64_t then, uint64_t now);
// A path shortened in the middle to `width` columns ("C:\Users\…\Vaults").
std::string ellipsize_middle(const Canvas& c, const std::string& s, int width);

struct Span {
    size_t begin, end;
};
// Greedy word wrap: at spaces when possible, else between clusters (CJK).
std::vector<Span> wrap(std::string_view s, int width, const WidthPolicy& wp);
std::string_view slice(std::string_view s, const Span& sp);

// ---------------------------------------------------------------------------
// Drawing context
// ---------------------------------------------------------------------------
struct Ctx {
    const RenderEnv& env;
    Canvas& c;
    const Theme& t;
    const Glyphs& g;
    RenderResult* res;
};

// A clickable area standing for `ev`. Later zones lie on top. `opens`: a
// list row, which a double-click opens (adds Enter); never a form field.
void zone(Ctx& x, Rect r, const KeyEvent& ev, bool opens = false);
// A modal takes over the pointer: zones drawn so far stop responding.
void modal(Ctx& x);

int centered_x(const Ctx& x, int w);
void center_text(Ctx& x, int y, std::string_view s, Style st);
void frame(Ctx& x, Rect r, Style bs, std::string_view title, Style ts);
// Clears a centered area, frames it, returns the padded interior.
Rect dialog(Ctx& x, int w, int h, std::string_view title, Style border);

// "key label" in hint style; returns columns used.
int hint(Ctx& x, int px, int y, std::string_view key, std::string_view label, int max_w);
// A key in a small pill: " a ".
int keycap(Ctx& x, int px, int y, std::string_view key);
// A button: " key  label " on a pill; clickable. kind: 0 plain, 1 primary,
// 2 danger.
int button(Ctx& x, int px, int y, std::string_view key, std::string_view label, int kind,
           const KeyEvent& ev);
int button_width(const Ctx& x, std::string_view key, std::string_view label);
// Right-aligned "k label  k label" group ending at `right`, each clickable.
void inline_hints(Ctx& x, int right, int y,
                  std::initializer_list<std::pair<const char*, const char*>> hs,
                  std::initializer_list<KeyEvent> evs);

struct Hint {
    std::string key;
    std::string label;
    int priority;   // lower = kept longer when space runs out
    KeyEvent ev;    // what a click sends
    bool click = true;
};
// The footer: hints that fit (by priority), clickable, plus right status.
void footer(Ctx& x, int y, const std::vector<Hint>& hints, std::string_view right,
            Style right_style);
void toast(Ctx& x, int y, int px, const std::string& message, MessageKind kind);

// Progress line with "<what> in Ns".
void countdown(Ctx& x, int px, int y, int w, uint64_t remaining, uint64_t total,
               std::string_view what, Style label);

// A one-line input: tinted strip, caret-following scroll, hint when empty,
// hardware cursor at the caret when focused.
void input_strip(Ctx& x, Rect r, std::string_view value, size_t caret, bool focus,
                 const char* empty_hint);

// The entry's badge: its initials ("GW", or one CJK character) centered on a
// tile of BADGE_W cells in the entry's color (EntryRecord::color: 0 picks one
// from the name). Monochrome terminals draw the initials in bold, unfilled.
void badge(Ctx& x, int px, int y, const std::string& name, uint8_t color);
constexpr int BADGE_W = 4;
// The tile's style for an entry color (0 automatic, from the name).
Style entry_style(const Ctx& x, const std::string& name, uint8_t color);
// "Auto", "Red", ... "Grey" for 0..ENTRY_COLORS.
const char* entry_color_name(uint8_t color);

}  // namespace ui
}  // namespace secraxis

#endif  // SECRAXIS_TUI_UI_KIT_H
