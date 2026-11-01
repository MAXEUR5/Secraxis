#include "secraxis/tui_canvas.h"

#include <string>
#include <vector>

#include "secraxis/secure_buffer.h"

namespace secraxis {

namespace {

// Braille spinner (Rich tier only).
const char32_t kBraille[] = {U'\x280B', U'\x2819', U'\x2839', U'\x2838', U'\x283C',
                             U'\x2834', U'\x2826', U'\x2827', U'\x2807', U'\x280F'};
const char32_t kAsciiSpin[] = {U'|', U'/', U'-', U'\\'};

const Glyphs kRich = {
    GlyphTier::Rich,
    U'\x2500', U'\x2502', U'\x250C', U'\x2510', U'\x2514', U'\x2518',  // ─│┌┐└┘
    U'\x2503',  // ┃ selected-row bar
    U'\x2022',  // •
    U'\x00B7',  // ·
    U'\x2503',  // ┃ scrollbar thumb
    U'\x2501', U'\x2500',  // ━ ─ progress
    U'\x2191', U'\x2193', U'\x2190', U'\x2192',
    U'\x2713', U'\x2717', U'!', U'\x2022',  // ✓ ✗ ! •
    U'\x25C6',  // ◆
    U'\x203A',  // ›
    U'\x25A0', U'\x25A1',  // ■ □
    "\xE2\x80\xA6",  // …
    kBraille, 10,
    true, true,
};

const Glyphs kBasic = {
    GlyphTier::Basic,
    U'\x2500', U'\x2502', U'\x250C', U'\x2510', U'\x2514', U'\x2518',  // ─│┌┐└┘
    U'\x258C',  // ▌
    U'\x2022',  // •
    U'\x00B7',  // ·
    U'\x2588',  // █
    U'\x2588', U'\x2591',  // █ ░
    U'\x2191', U'\x2193', U'\x2190', U'\x2192',
    U'\x2022', U'\x00D7', U'!', U'\x2022',  // • × ! •
    U'\x25CA',  // ◊
    U'\x203A',  // ›
    U'\x25A0', U'\x25A1',  // ■ □
    "\xE2\x80\xA6",  // …
    nullptr, 0,
    false, true,
};

const Glyphs kAscii = {
    GlyphTier::Ascii,
    U'-', U'|', U'+', U'+', U'+', U'+',
    U'>', U'*', U'-', U'#', U'#', U'-',
    U'^', U'v', U'<', U'>',
    U'+', U'x', U'!', U'*',
    U'*', U'>', U'*', U'o',
    "...",
    kAsciiSpin, 4,
    false, false,
};

}  // namespace

const Glyphs& glyphs_for(GlyphTier tier) noexcept {
    switch (tier) {
        case GlyphTier::Rich: return kRich;
        case GlyphTier::Basic: return kBasic;
        case GlyphTier::Ascii: break;
    }
    return kAscii;
}

// ---------------------------------------------------------------------------
// Terminal-probe support
// ---------------------------------------------------------------------------
namespace {

// Every chrome glyph a tier may draw, in a fixed order. The first six are the
// frame, which is replaced as a group so corners and lines always match.
char32_t Glyphs::*const kGlyphFields[] = {
    &Glyphs::h,         &Glyphs::v,        &Glyphs::tl,       &Glyphs::tr,
    &Glyphs::bl,        &Glyphs::br,       &Glyphs::sel_bar,  &Glyphs::bullet,
    &Glyphs::dot,       &Glyphs::thumb,    &Glyphs::bar_full, &Glyphs::bar_empty,
    &Glyphs::up,        &Glyphs::down,     &Glyphs::left,     &Glyphs::right,
    &Glyphs::ok,        &Glyphs::fail,     &Glyphs::warn,     &Glyphs::note,
    &Glyphs::brand,     &Glyphs::prompt,   &Glyphs::dot_on,   &Glyphs::dot_off,
};
constexpr size_t kNumFields = sizeof(kGlyphFields) / sizeof(kGlyphFields[0]);

std::string utf8_of(char32_t cp) {
    char b[4];
    return std::string(b, utf8_encode(cp, b));
}

// The start-page logo's glyphs: full block and the double-line set.
const char* const kLogoGlyphs[] = {
    "\xE2\x96\x88", "\xE2\x95\x90", "\xE2\x95\x91", "\xE2\x95\x94",
    "\xE2\x95\x97", "\xE2\x95\x9A", "\xE2\x95\x9D",
};
constexpr size_t kNumLogoGlyphs = sizeof(kLogoGlyphs) / sizeof(kLogoGlyphs[0]);

// Where the plainer (Basic, WGL4) form of every field starts in the probe.
constexpr size_t kAltBase = kNumFields + 5 + kNumLogoGlyphs;

}  // namespace

std::vector<std::string> glyph_probe_strings(const Glyphs& g) {
    std::vector<std::string> v;
    for (char32_t Glyphs::*f : kGlyphFields) v.push_back(utf8_of(g.*f));
    v.push_back(g.ellipsis);
    v.push_back(g.spinner != nullptr ? utf8_of(g.spinner[0]) : std::string(" "));
    v.push_back("\xC3\xA9");  // e-acute
    v.push_back("\xD0\x96");  // Cyrillic Zhe
    v.push_back("\xF0\x9F\x94\x91");  // key emoji (two cells expected)
    for (const char* b : kLogoGlyphs) v.push_back(b);
    // The plainer form of every field, used where the first one is not one
    // cell wide (a diamond the font lacks still has its lozenge).
    const Glyphs& basic = glyphs_for(GlyphTier::Basic);
    for (char32_t Glyphs::*f : kGlyphFields) v.push_back(utf8_of(basic.*f));
    return v;
}

void apply_glyph_probe(const std::vector<std::string>& probes, const std::vector<int>& adv,
                       Glyphs* g, WidthPolicy* wp) {
    if (probes.size() != kAltBase + kNumFields || adv.size() != probes.size()) return;
    // Every ambiguous symbol measured at one cell stays narrow in text too.
    for (size_t k = 0; k < probes.size(); ++k) {
        size_t i = 0;
        char32_t cp = 0;
        const std::string& s = probes[k];
        if (adv[k] != 1 || s.empty() || !utf8_decode(s.data(), s.size(), &i, &cp) ||
            i != s.size())
            continue;
        if (classify_cp(cp) == CpClass::Ambiguous) wp->add_narrow(cp);
    }
    // Keep what the terminal draws in exactly one cell; the rest falls back
    // to its plainer form if that is one cell, else to ASCII. The frame
    // changes as a group so corners and lines always match.
    const Glyphs& a = glyphs_for(GlyphTier::Ascii);
    const Glyphs& b = glyphs_for(GlyphTier::Basic);
    bool frame_ok = true, alt_frame_ok = true;
    for (size_t k = 0; k < 6; ++k) {
        frame_ok = frame_ok && adv[k] == 1;
        alt_frame_ok = alt_frame_ok && adv[kAltBase + k] == 1;
    }
    for (size_t k = 0; k < kNumFields; ++k) {
        if (k < 6 ? frame_ok : adv[k] == 1) continue;
        const bool alt_ok = k < 6 ? alt_frame_ok : adv[kAltBase + k] == 1;
        g->*kGlyphFields[k] = alt_ok ? b.*kGlyphFields[k] : a.*kGlyphFields[k];
    }
    if (adv[kNumFields] != 1) g->ellipsis = a.ellipsis;
    if (g->spinner != nullptr && adv[kNumFields + 1] != 1) {
        g->spinner = a.spinner;
        g->spinner_len = a.spinner_len;
    }
    wp->ambiguous_wide = adv[kNumFields + 2] == 2 || adv[kNumFields + 3] == 2;
    g->emoji = g->emoji && adv[kNumFields + 4] == 2;
    for (size_t k = 0; k < kNumLogoGlyphs; ++k)
        if (adv[kNumFields + 5 + k] != 1) g->blocks = false;
}

bool same_cell(const Cell& a, const Cell& b) noexcept {
    if (a.ncp != b.ncp || a.width != b.width || a.flags != b.flags ||
        a.style != b.style)
        return false;
    for (uint8_t k = 0; k < a.ncp; ++k)
        if (a.cp[k] != b.cp[k]) return false;
    return true;
}

Canvas::~Canvas() { clear(); }

void Canvas::clear() noexcept {
    if (!cells_.empty()) secure_wipe(cells_.data(), cells_.size() * sizeof(Cell));
    std::vector<Cell>().swap(cells_);
    cols_ = rows_ = 0;
    cursor_on_ = false;
}

void Canvas::reset(int cols, int rows, const Glyphs& g, const WidthPolicy& wp,
                   Style base) {
    if (cols < 1) cols = 1;
    if (rows < 1) rows = 1;
    const size_t n = static_cast<size_t>(cols) * static_cast<size_t>(rows);
    if (n != cells_.size()) {
        clear();
        cells_.resize(n);
    } else if (!cells_.empty()) {
        secure_wipe(cells_.data(), cells_.size() * sizeof(Cell));
    }
    cols_ = cols;
    rows_ = rows;
    g_ = &g;
    wp_ = wp;
    cursor_on_ = false;
    Cell blank;
    blank.style = base;
    for (Cell& c : cells_) c = blank;
}

void Canvas::copy_from(const Canvas& o) {
    if (o.cells_.size() != cells_.size()) {
        clear();
        cells_.resize(o.cells_.size());
    }
    for (size_t i = 0; i < cells_.size(); ++i) cells_[i] = o.cells_[i];
    cols_ = o.cols_;
    rows_ = o.rows_;
    g_ = o.g_;
    wp_ = o.wp_;
    cursor_on_ = o.cursor_on_;
    cur_x_ = o.cur_x_;
    cur_y_ = o.cur_y_;
}

void Canvas::break_pair(int x, int y) {
    Cell& c = cells_[idx(x, y)];
    if (c.width == 0 && x > 0) {
        // Overwriting the right half of a wide pair: blank the left half.
        Cell& lead = cells_[idx(x - 1, y)];
        lead.cp[0] = U' ';
        lead.ncp = 1;
        lead.width = 1;
        lead.flags = CELL_TRUSTED;
    } else if (c.width == 2 && x + 1 < cols_) {
        // Overwriting the left half: blank the orphaned right half.
        Cell& tail = cells_[idx(x + 1, y)];
        tail.cp[0] = U' ';
        tail.ncp = 1;
        tail.width = 1;
        tail.flags = CELL_TRUSTED;
    }
}

void Canvas::put(int x, int y, const Cluster& cl, Style st, uint8_t flags) {
    if (x < 0 || y < 0 || x >= cols_ || y >= rows_) return;
    const int w = cl.width;
    if (w == 2 && x + 1 >= cols_) return;  // caller budgets; never half-draw
    break_pair(x, y);
    if (w == 2) break_pair(x + 1, y);
    Cell& c = cells_[idx(x, y)];
    c.style = st;
    c.width = static_cast<uint8_t>(w);
    if (cl.placeholder) {
        c.cp[0] = U'?';
        c.ncp = 1;
        c.flags = CELL_PLACEHOLDER | CELL_TRUSTED;
        c.style.attrs = static_cast<uint8_t>(c.style.attrs | ATTR_REVERSE);
    } else {
        for (uint8_t k = 0; k < cl.ncp; ++k) c.cp[k] = cl.cp[k];
        for (uint8_t k = cl.ncp; k < 1 + Cluster::MAX_COMBINING; ++k) c.cp[k] = 0;
        c.ncp = cl.ncp;
        c.flags = flags;
    }
    if (w == 2) {
        Cell& t = cells_[idx(x + 1, y)];
        t.cp[0] = 0;
        t.ncp = 0;
        t.width = 0;
        t.flags = c.flags;
        t.style = st;
    }
}

void Canvas::fill(Rect r, Style st) {
    Cluster sp;
    sp.cp[0] = U' ';
    sp.ncp = 1;
    for (int y = r.y; y < r.bottom(); ++y)
        for (int x = r.x; x < r.right(); ++x) put(x, y, sp, st, CELL_TRUSTED);
}

void Canvas::paint(Rect r, Style st) {
    for (int y = r.y; y < r.bottom(); ++y) {
        if (y < 0 || y >= rows_) continue;
        for (int x = r.x; x < r.right(); ++x) {
            if (x < 0 || x >= cols_) continue;
            Cell& c = cells_[idx(x, y)];
            c.style = st;
            if (c.flags & CELL_PLACEHOLDER)
                c.style.attrs = static_cast<uint8_t>(c.style.attrs | ATTR_REVERSE);
        }
    }
}

void Canvas::fade(Style faded) {
    for (Cell& c : cells_) {
        const bool ph = (c.flags & CELL_PLACEHOLDER) != 0;
        c.style = faded;
        if (ph) c.style.attrs = static_cast<uint8_t>(c.style.attrs | ATTR_REVERSE);
    }
    cursor_on_ = false;
}

int Canvas::text(int x, int y, std::string_view s, Style st, int max_w,
                 bool ellipsis) {
    if (y < 0 || y >= rows_ || max_w <= 0) return 0;
    if (x < 0) return 0;
    if (x + max_w > cols_) max_w = cols_ - x;
    if (max_w <= 0) return 0;
    const size_t total = display_width(s, wp_);
    const bool fits = total <= static_cast<size_t>(max_w);
    std::string_view ell = ellipsis ? std::string_view(g_->ellipsis)
                                    : std::string_view();
    int ell_w = static_cast<int>(display_width(ell, wp_));
    if (fits || ell_w >= max_w) ell_w = 0;
    const int budget = fits ? max_w : max_w - ell_w;

    int col = 0;
    size_t i = 0;
    Cluster cl;
    while (next_cluster(s.data(), s.size(), &i, wp_, &cl)) {
        if (col + cl.width > budget) break;
        const bool ascii = !cl.placeholder && cl.ncp == 1 && cl.cp[0] < 0x80;
        put(x + col, y, cl, st, ascii ? CELL_TRUSTED : 0);
        col += cl.width;
    }
    if (!fits && ell_w > 0) {
        while (col < budget) {  // a wide char did not fit: pad
            glyph(x + col, y, U' ', st);
            ++col;
        }
        size_t j = 0;
        while (next_cluster(ell.data(), ell.size(), &j, wp_, &cl)) {
            put(x + col, y, cl, st, CELL_TRUSTED);
            col += cl.width;
        }
    }
    return col;
}

int Canvas::text_hl(int x, int y, std::string_view s, Style st, int max_w,
                    const std::vector<size_t>& hl, Style hl_style) {
    if (hl.empty()) return text(x, y, s, st, max_w);
    if (y < 0 || y >= rows_ || x < 0 || max_w <= 0) return 0;
    if (x + max_w > cols_) max_w = cols_ - x;
    if (max_w <= 0) return 0;
    const bool fits = display_width(s, wp_) <= static_cast<size_t>(max_w);
    const std::string_view ell(g_->ellipsis);
    int ell_w = static_cast<int>(display_width(ell, wp_));
    if (fits || ell_w >= max_w) ell_w = 0;
    const int budget = fits ? max_w : max_w - ell_w;
    int col = 0;
    size_t i = 0;
    Cluster cl;
    while (true) {
        const size_t at = i;
        if (!next_cluster(s.data(), s.size(), &i, wp_, &cl)) break;
        if (col + cl.width > budget) break;
        bool lit = false;
        for (size_t k = 0; k + 1 < hl.size(); k += 2)
            if (at >= hl[k] && at < hl[k + 1]) lit = true;
        const bool ascii = !cl.placeholder && cl.ncp == 1 && cl.cp[0] < 0x80;
        put(x + col, y, cl, lit ? hl_style : st, ascii ? CELL_TRUSTED : 0);
        col += cl.width;
    }
    if (!fits && ell_w > 0) {
        while (col < budget) {
            glyph(x + col, y, U' ', st);
            ++col;
        }
        size_t j = 0;
        while (next_cluster(ell.data(), ell.size(), &j, wp_, &cl)) {
            put(x + col, y, cl, st, CELL_TRUSTED);
            col += cl.width;
        }
    }
    return col;
}

int Canvas::text_right(int x, int y, std::string_view s, Style st, int max_w) {
    const int w = static_cast<int>(display_width(s, wp_));
    if (w >= max_w) return text(x, y, s, st, max_w);
    return text(x + max_w - w, y, s, st, w);
}

void Canvas::glyph(int x, int y, char32_t cp, Style st) {
    Cluster cl;
    cl.cp[0] = cp;
    cl.ncp = 1;
    cl.width = 1;
    // Chrome glyphs come from a set whose every member the terminal probe
    // measured at one cell (Terminal::probe), so the width is known.
    put(x, y, cl, st, CELL_TRUSTED);
}

void Canvas::hline(int x, int y, int w, char32_t cp, Style st) {
    for (int k = 0; k < w; ++k) glyph(x + k, y, cp, st);
}

void Canvas::vline(int x, int y, int h, char32_t cp, Style st) {
    for (int k = 0; k < h; ++k) glyph(x, y + k, cp, st);
}

void Canvas::box(Rect r, Style st) {
    if (r.w < 2 || r.h < 2) return;
    const Glyphs& g = *g_;
    glyph(r.x, r.y, g.tl, st);
    glyph(r.right() - 1, r.y, g.tr, st);
    glyph(r.x, r.bottom() - 1, g.bl, st);
    glyph(r.right() - 1, r.bottom() - 1, g.br, st);
    hline(r.x + 1, r.y, r.w - 2, g.h, st);
    hline(r.x + 1, r.bottom() - 1, r.w - 2, g.h, st);
    vline(r.x, r.y + 1, r.h - 2, g.v, st);
    vline(r.right() - 1, r.y + 1, r.h - 2, g.v, st);
}

void Canvas::set_cursor(int x, int y) noexcept {
    if (x < 0 || y < 0 || x >= cols_ || y >= rows_) {
        cursor_on_ = false;
        return;
    }
    cursor_on_ = true;
    cur_x_ = x;
    cur_y_ = y;
}

std::string Canvas::row_text(int y) const {
    std::string out;
    if (y < 0 || y >= rows_) return out;
    for (int x = 0; x < cols_; ++x) {
        const Cell& c = cells_[idx(x, y)];
        if (c.width == 0) continue;
        for (uint8_t k = 0; k < c.ncp; ++k) {
            char b[4];
            out.append(b, utf8_encode(c.cp[k], b));
        }
    }
    return out;
}

}  // namespace secraxis
