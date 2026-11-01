// tui_text.h — Unicode text handling for the TUI: strict UTF-8 decoding,
// display-width classes, and cell clustering.
//
// Everything the renderer draws passes through next_cluster(), which is the
// single sanitizing choke point between vault metadata (which may come from an
// imported CSV/JSON file, i.e. attacker-controlled) and the terminal:
//   * ill-formed UTF-8 → one placeholder per maximal ill-formed subpart
//   * C0/C1 controls, DEL, bidi overrides/isolates, BOM, ZWSP, line/paragraph
//     separators, noncharacters → placeholder (never reach the terminal)
//   * combining marks attach to the preceding cluster, capped at
//     MAX_COMBINING so "zalgo" stacks cannot bleed into neighboring rows
//   * VS15/VS16 are dropped so a cluster's width never depends on the
//     terminal's emoji-presentation choice
// Widths follow the generated tables (src/tui/unicode_tables.inc). Whether
// East Asian Ambiguous characters take one or two cells, and whether wide
// characters are supported at all, is measured on the live terminal
// (Terminal::probe) and carried in WidthPolicy.
#ifndef SECRAXIS_TUI_TEXT_H
#define SECRAXIS_TUI_TEXT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace secraxis {

struct WidthPolicy {
    bool utf8 = true;             // false: every non-ASCII cluster → placeholder
    bool wide_ok = true;          // terminal draws East Asian Wide as 2 cells
    bool ambiguous_wide = false;  // terminal draws East Asian Ambiguous as 2
    // Ambiguous code points the probe measured at one cell on this terminal.
    // They stay narrow even when ambiguous_wide is set: legacy consoles with
    // CJK fonts draw letters such as U+00E9 wide but box drawing narrow.
    static constexpr size_t MAX_NARROW = 40;
    char32_t narrow[MAX_NARROW] = {};
    uint8_t n_narrow = 0;
    bool is_narrow(char32_t cp) const noexcept {
        for (uint8_t k = 0; k < n_narrow; ++k)
            if (narrow[k] == cp) return true;
        return false;
    }
    void add_narrow(char32_t cp) noexcept {
        if (!is_narrow(cp) && n_narrow < MAX_NARROW) narrow[n_narrow++] = cp;
    }
};

enum class CpClass : uint8_t { Narrow, Wide, Ambiguous, Zero, Unsafe };

// Classification from the generated tables (policy-independent).
CpClass classify_cp(char32_t cp) noexcept;

// Decode one scalar from s[*i..n). On success stores it, advances *i, and
// returns true. On ill-formed input advances *i past the maximal ill-formed
// subpart (at least one byte) and returns false (Unicode §3.9, U+FFFD
// substitution of maximal subparts).
bool utf8_decode(const char* s, size_t n, size_t* i, char32_t* cp) noexcept;

// Encode a scalar (callers pass valid scalars). Returns bytes written (1-4).
size_t utf8_encode(char32_t cp, char out[4]) noexcept;

// True for scalars the TUI accepts as typed text: anything that classifies
// as Narrow/Wide/Ambiguous/Zero (never controls, bidi overrides, etc.).
bool is_text_cp(char32_t cp) noexcept;

// One terminal cell's worth of text.
struct Cluster {
    static constexpr size_t MAX_COMBINING = 2;
    char32_t cp[1 + MAX_COMBINING] = {};
    uint8_t ncp = 0;
    uint8_t width = 1;           // 1 or 2 columns
    bool placeholder = false;    // sanitized: draw the placeholder glyph
};

// Read the next cluster starting at s[*i]. Returns false at end of input.
bool next_cluster(const char* s, size_t n, size_t* i, const WidthPolicy& p,
                  Cluster* out) noexcept;

// Display width of UTF-8 text after sanitization.
size_t display_width(std::string_view s, const WidthPolicy& p) noexcept;

// Unicode version of the width tables (for diagnostics/docs).
const char* unicode_tables_version() noexcept;

}  // namespace secraxis

#endif  // SECRAXIS_TUI_TEXT_H
