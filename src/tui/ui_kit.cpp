#include "ui_kit.h"

#include <cstdio>

namespace secraxis {
namespace ui {

// ---------------------------------------------------------------------------
// Theme
//
// Visual language: the terminal's own background everywhere, hairline frames
// only where a frame carries meaning (dialogs, inputs), one accent color, and
// a three-step text hierarchy (text, muted, subtle). Every color has an
// explicit ANSI-16 fallback, and monochrome terminals get the same
// distinctions through attributes alone.
// ---------------------------------------------------------------------------
namespace {

struct Palette {
    Color muted, subtle, border, accent, sel_bg, sel_fg, sel_muted, ok, warn, err,
        secret_fg, secret_bg, input_bg, input_focus_bg, input_fg, pill_bg, pill_fg,
        danger_bg, danger_fg, primary_bg, primary_fg, match_fg, chip_fg, logo_from,
        logo_to, logo_shadow;
    Color chip_bg[8];
};

const Palette kDark = {
    rgb(0x9298A8, 8),  rgb(0x5F6577, 8),  rgb(0x363A48, 8),  rgb(0x8B93FF, 12),
    rgb(0x252940, 8),  rgb(0xF3F4FA, 15), rgb(0xB9BED0, 7),  rgb(0x7EE2A8, 10),
    rgb(0xF2C46D, 11), rgb(0xFF8F8F, 9),  rgb(0xF2C46D, 11), rgb(0x2C2717, 0),
    rgb(0x1C1E2B, 0),  rgb(0x24273C, 8),  rgb(0xE8EAF2, 15), rgb(0x2A2D3B, 8),
    rgb(0xD9DCE6, 7),  rgb(0x4A1F27, 1),  rgb(0xFFD9D9, 15), rgb(0x8B93FF, 12),
    rgb(0x10121C, 0),  rgb(0xB3B8FF, 14), rgb(0xECEDF5, 15), rgb(0x8B93FF, 12),
    rgb(0xC08BFF, 13), rgb(0x3A3E58, 8),
    // Entry colors: Red, Amber, Green, Teal, Blue, Violet, Pink, Grey.
    {rgb(0x7A2E36, 1), rgb(0x7A5418, 3), rgb(0x2E5E37, 2), rgb(0x1C5853, 6),
     rgb(0x26497A, 4), rgb(0x4B3C82, 5), rgb(0x7A2E63, 5), rgb(0x454A5A, 8)},
};

const Palette kLight = {
    rgb(0x5E6472, 8),  rgb(0x9AA0AD, 7),  rgb(0xD8DBE3, 7),  rgb(0x4F46E5, 4),
    rgb(0xECEDFC, 7),  rgb(0x16172A, 0),  rgb(0x4A4F5E, 8),  rgb(0x15803D, 2),
    rgb(0xB45309, 3),  rgb(0xDC2626, 1),  rgb(0x92400E, 3),  rgb(0xFEF3C7, 15),
    rgb(0xF2F3F7, 7),  rgb(0xE7E8FB, 15), rgb(0x1D1F2B, 0),  rgb(0xE8EAF0, 7),
    rgb(0x2B2E3B, 0),  rgb(0xFDE2E2, 1),  rgb(0x991B1B, 15), rgb(0x4F46E5, 4),
    rgb(0xFFFFFF, 15), rgb(0x4338CA, 4),  rgb(0x1E2030, 0),  rgb(0x4F46E5, 4),
    rgb(0x9333EA, 5),  rgb(0xC9CCD8, 7),
    // Entry colors: Red, Amber, Green, Teal, Blue, Violet, Pink, Grey.
    {rgb(0xFAD4D6, 1), rgb(0xFBE5BF, 3), rgb(0xD3EED2, 2), rgb(0xC9EDE8, 6),
     rgb(0xD2E1F9, 4), rgb(0xE2DBFC, 5), rgb(0xF8D5EA, 5), rgb(0xE0E3EA, 7)},
};

Style fg(Color c, uint8_t attrs = 0) { return Style{c, 0, attrs}; }
Style fgbg(Color f, Color b, uint8_t attrs = 0) { return Style{f, b, attrs}; }

}  // namespace

Theme make_theme(const TermCaps& caps) {
    const Palette& p = caps.light ? kLight : kDark;
    Theme t;
    t.text = Style();
    t.strong = Style{0, 0, ATTR_BOLD};
    t.muted = fg(p.muted);
    t.subtle = fg(p.subtle);
    t.border = fg(p.border);
    t.accent = fg(p.accent);
    t.accent_bold = fg(p.accent, ATTR_BOLD);
    t.sel = fgbg(p.sel_fg, p.sel_bg);
    t.sel_strong = fgbg(p.sel_fg, p.sel_bg, ATTR_BOLD);
    t.sel_muted = fgbg(p.sel_muted, p.sel_bg);
    t.sel_bar = fgbg(p.accent, p.sel_bg, ATTR_BOLD);
    t.ok = fg(p.ok);
    t.warn = fg(p.warn);
    t.err = fg(p.err);
    t.secret = fgbg(p.secret_fg, p.secret_bg, ATTR_BOLD);
    t.input = fgbg(p.input_fg, p.input_bg);
    t.input_focus = fgbg(p.input_fg, p.input_focus_bg);
    t.input_hint = fgbg(p.subtle, p.input_bg);
    t.pill = fgbg(p.pill_fg, p.pill_bg);
    t.pill_key = fgbg(p.pill_fg, p.pill_bg, ATTR_BOLD);
    t.danger_pill = fgbg(p.danger_fg, p.danger_bg);
    t.danger_key = fgbg(p.danger_fg, p.danger_bg, ATTR_BOLD);
    t.primary_pill = fgbg(p.primary_fg, p.primary_bg);
    t.primary_key = fgbg(p.primary_fg, p.primary_bg, ATTR_BOLD);
    t.key = Style{0, 0, ATTR_BOLD};
    t.key_label = fg(p.muted);
    t.label = fg(p.subtle);
    t.label_focus = fg(p.accent, ATTR_BOLD);
    t.bar_full = fg(p.accent);
    t.bar_empty = fg(p.border);
    t.thumb = fg(p.subtle);
    t.match = fg(p.match_fg, ATTR_BOLD | ATTR_UNDERLINE);
    t.match_sel = fgbg(p.match_fg, p.sel_bg, ATTR_BOLD | ATTR_UNDERLINE);
    t.scrim = fg(p.border);
    t.logo_shadow = fg(p.logo_shadow);
    t.logo_from = p.logo_from;
    t.logo_to = p.logo_to;
    for (int k = 0; k < 8; ++k) t.chip[k] = fgbg(p.chip_fg, p.chip_bg[k], ATTR_BOLD);
    t.truecolor = caps.color == ColorDepth::TrueColor || caps.color == ColorDepth::Ansi256;

    if (caps.color == ColorDepth::Ansi16) {
        // Many terminals draw bold in the bright variant of colors 0-7: the
        // primary button's bold black key would turn grey on its blue.
        t.primary_key.attrs = 0;
    }
    if (caps.color == ColorDepth::None) {
        // Monochrome: carry every distinction with attributes alone.
        t.mono = true;
        t.sel.attrs = ATTR_REVERSE;
        t.sel_strong.attrs = ATTR_REVERSE | ATTR_BOLD;
        t.sel_muted.attrs = ATTR_REVERSE;
        t.sel_bar.attrs = ATTR_REVERSE | ATTR_BOLD;
        t.accent.attrs = ATTR_BOLD;
        t.secret.attrs = ATTR_BOLD | ATTR_UNDERLINE;
        t.input.attrs = ATTR_UNDERLINE;
        t.input_focus.attrs = ATTR_UNDERLINE | ATTR_BOLD;
        t.input_hint.attrs = ATTR_UNDERLINE;
        t.pill.attrs = ATTR_REVERSE;
        t.pill_key.attrs = ATTR_REVERSE | ATTR_BOLD;
        t.danger_pill.attrs = ATTR_REVERSE;
        t.danger_key.attrs = ATTR_REVERSE | ATTR_BOLD;
        t.primary_pill.attrs = ATTR_REVERSE;
        t.primary_key.attrs = ATTR_REVERSE | ATTR_BOLD;
        t.label_focus.attrs = ATTR_BOLD | ATTR_UNDERLINE;
        t.warn.attrs = ATTR_BOLD;
        t.err.attrs = ATTR_BOLD;
        t.match_sel.attrs = ATTR_REVERSE | ATTR_UNDERLINE | ATTR_BOLD;
        t.scrim.attrs = ATTR_DIM;
        t.logo_shadow.attrs = ATTR_DIM;
    }
    return t;
}

Style on(Style s, const Style& surface) {
    s.bg = surface.bg;
    if (s.fg == 0) s.fg = surface.fg;
    s.attrs = static_cast<uint8_t>(s.attrs | (surface.attrs & ATTR_REVERSE));
    return s;
}

Color blend(Color a, Color b, int t) {
    if (a == 0 || b == 0) return a;
    t = clampi(t, 0, 1000);
    auto ch = [&](int shift) {
        const int x = static_cast<int>((a >> shift) & 0xFF);
        const int y = static_cast<int>((b >> shift) & 0xFF);
        return static_cast<uint32_t>(x + (y - x) * t / 1000) & 0xFFu;
    };
    return (a & 0xFF000000u) | (ch(16) << 16) | (ch(8) << 8) | ch(0);
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------
int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

int width_of(const Canvas& c, std::string_view s) {
    return static_cast<int>(display_width(s, c.width_policy()));
}

std::string utf8(char32_t cp) {
    char b[4];
    return std::string(b, utf8_encode(cp, b));
}

std::string repeat(char32_t cp, int n) {
    std::string out;
    const std::string one = utf8(cp);
    for (int k = 0; k < n; ++k) out += one;
    return out;
}

std::string seconds_text(uint64_t ms) { return std::to_string((ms + 999) / 1000) + "s"; }

// 2001-01-01 .. 9999-12-31: earlier values are uptimes or unset, later ones
// corrupt (and would overflow the date arithmetic below).
bool real_time(uint64_t unix_s) { return unix_s >= 978307200ULL && unix_s <= 253402300799ULL; }

std::string format_date(uint64_t unix_s, int64_t offset_s, bool with_time) {
    if (!real_time(unix_s)) return "-";
    const int64_t t = static_cast<int64_t>(unix_s) + offset_s;
    int64_t days = t / 86400;
    int64_t rem = t % 86400;
    if (rem < 0) {
        rem += 86400;
        --days;
    }
    // Civil date from a day count (Howard Hinnant's days_from_civil inverse).
    const int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const int64_t m = mp < 10 ? mp + 3 : mp - 9;
    const int64_t y = yoe + era * 400 + (m <= 2 ? 1 : 0);
    // Zero-padded fields without snprintf, whose int64 ranges GCC cannot bound
    // (-Wformat-truncation).
    auto pad = [](int64_t v, size_t w) {
        std::string s = std::to_string(v);
        if (s.size() < w) s.insert(0, w - s.size(), '0');
        return s;
    };
    std::string out = pad(y, 4) + "-" + pad(m, 2) + "-" + pad(d, 2);
    if (with_time) out += " " + pad(rem / 3600, 2) + ":" + pad((rem % 3600) / 60, 2);
    return out;
}

std::string relative_time(uint64_t then, uint64_t now) {
    if (!real_time(then) || !real_time(now)) return "";
    if (then >= now || now - then < 60) return "just now";
    const uint64_t d = now - then;
    auto ago = [](uint64_t n, const char* unit) {
        return std::to_string(n) + unit + " ago";
    };
    if (d < 3600) return ago(d / 60, "m");
    if (d < 86400) return ago(d / 3600, "h");
    if (d < 2 * 86400) return "yesterday";
    if (d < 7 * 86400) return ago(d / 86400, "d");
    if (d < 30 * 86400) return ago(d / (7 * 86400), "w");
    if (d < 365 * 86400) return ago(d / (30 * 86400), "mo");
    return ago(d / (365 * 86400), "y");
}

std::string ellipsize_middle(const Canvas& c, const std::string& s, int width) {
    if (width <= 0) return "";
    if (width_of(c, s) <= width) return s;
    const std::string ell = c.glyphs().ellipsis;
    const int ew = width_of(c, ell);
    if (width <= ew + 2) return ell;
    // Keep about a third at the start (the drive or root), the rest at the end
    // (the folder and file the reader cares about).
    const int head_w = (width - ew) / 3;
    const int tail_w = width - ew - head_w;
    std::string head, tail;
    size_t i = 0;
    Cluster cl;
    int w = 0;
    while (i < s.size()) {
        const size_t at = i;
        if (!next_cluster(s.data(), s.size(), &i, c.width_policy(), &cl)) break;
        if (w + cl.width > head_w) {
            i = at;
            break;
        }
        w += cl.width;
    }
    head = s.substr(0, i);
    // Tail: walk the clusters once, keep the suffix that fits.
    std::vector<size_t> starts;
    std::vector<int> widths;
    size_t j = 0;
    while (j < s.size()) {
        const size_t at = j;
        if (!next_cluster(s.data(), s.size(), &j, c.width_policy(), &cl)) break;
        starts.push_back(at);
        widths.push_back(cl.width);
    }
    int tw = 0;
    size_t from = s.size();
    for (size_t k = starts.size(); k-- > 0;) {
        if (starts[k] < head.size() || tw + widths[k] > tail_w) break;
        tw += widths[k];
        from = starts[k];
    }
    tail = s.substr(from);
    return head + ell + tail;
}

std::vector<Span> wrap(std::string_view s, int width, const WidthPolicy& wp) {
    std::vector<Span> lines;
    if (width < 1) return lines;
    size_t line_start = 0, i = 0, last_space = std::string::npos;
    int col = 0;
    Cluster cl;
    while (i < s.size()) {
        const size_t at = i;
        if (!next_cluster(s.data(), s.size(), &i, wp, &cl)) break;
        const bool space = !cl.placeholder && cl.ncp == 1 && cl.cp[0] == U' ';
        if (col + cl.width > width) {
            if (space) {
                lines.push_back({line_start, at});
                line_start = i;
            } else if (last_space != std::string::npos && last_space > line_start) {
                lines.push_back({line_start, last_space});
                line_start = last_space + 1;
                i = line_start;
            } else {
                lines.push_back({line_start, at});
                line_start = at;
                i = at;
            }
            col = 0;
            last_space = std::string::npos;
            continue;
        }
        if (space) last_space = at;
        col += cl.width;
    }
    if (line_start < s.size() || lines.empty()) lines.push_back({line_start, s.size()});
    return lines;
}

std::string_view slice(std::string_view s, const Span& sp) {
    return s.substr(sp.begin, sp.end - sp.begin);
}

// ---------------------------------------------------------------------------
// Pointer zones, frames, dialogs
// ---------------------------------------------------------------------------
void zone(Ctx& x, Rect r, const KeyEvent& ev, bool opens) {
    if (x.res == nullptr || r.w <= 0 || r.h <= 0) return;
    HitZone z;
    z.r = r;
    z.ev = ev;
    z.opens = opens;
    x.res->zones.push_back(z);
}

void modal(Ctx& x) {
    if (x.res != nullptr) x.res->zones.clear();
}

int centered_x(const Ctx& x, int w) {
    const int v = (x.c.cols() - w) / 2;
    return v > 0 ? v : 0;
}

void center_text(Ctx& x, int y, std::string_view s, Style st) {
    const int w = width_of(x.c, s);
    x.c.text(centered_x(x, w), y, s, st, x.c.cols());
}

void frame(Ctx& x, Rect r, Style bs, std::string_view title, Style ts) {
    x.c.box(r, bs);
    if (!title.empty() && r.w > 8) {
        x.c.glyph(r.x + 2, r.y, U' ', bs);
        const int used = x.c.text(r.x + 3, r.y, title, ts, r.w - 8);
        x.c.glyph(r.x + 3 + used, r.y, U' ', bs);
    }
}

namespace {

// Clear a margin around a dialog card (two columns at the sides, a row above
// and below, never the title or footer row) and the rest of every word the
// card cuts, so the faded screen behind it never ends in a stray letter
// against the border. Rules and box lines stop the word wipe.
void clear_margin(Ctx& x, Rect r) {
    const int top = r.y - 1 >= 1 ? r.y - 1 : r.y;
    const int bottom = r.bottom() < x.c.rows() - 1 ? r.bottom() + 1 : r.bottom();
    const Rect m{r.x - 2, top, r.w + 4, bottom - top};
    x.c.fill(m, x.t.scrim);
    auto wordy = [&](int px, int y) {
        const Cell& c = x.c.at(px, y);
        if (c.width == 0) return true;  // the right half of a wide character
        return c.cp[0] != U' ' && !(c.cp[0] >= U'\x2500' && c.cp[0] <= U'\x259F');
    };
    constexpr int kMaxWipe = 24;
    for (int y = m.y; y < m.bottom(); ++y) {
        if (y < 0 || y >= x.c.rows()) continue;
        for (int px = m.x - 1, n = 0; px >= 0 && n < kMaxWipe && wordy(px, y); ++n) {
            const int w = (x.c.at(px, y).width == 0 && px > 0) ? 2 : 1;
            x.c.fill(Rect{px - w + 1, y, w, 1}, x.t.scrim);
            px -= w;
        }
        for (int px = m.right(), n = 0; px < x.c.cols() && n < kMaxWipe && wordy(px, y); ++n) {
            const int w = x.c.at(px, y).width == 2 ? 2 : 1;
            x.c.fill(Rect{px, y, w, 1}, x.t.scrim);
            px += w;
        }
    }
}

}  // namespace

Rect dialog(Ctx& x, int w, int h, std::string_view title, Style border) {
    w = clampi(w, 12, x.c.cols() - 2);
    h = clampi(h, 5, x.c.rows() - 2);
    Rect r{(x.c.cols() - w) / 2, (x.c.rows() - h) / 2, w, h};
    if (r.y < 1) r.y = 1;
    clear_margin(x, r);
    x.c.fill(r, x.t.text);
    frame(x, r, border, title, x.t.strong);
    return Rect{r.x + 3, r.y + 2, r.w - 6, r.h - 4};
}

int hint(Ctx& x, int px, int y, std::string_view key, std::string_view label, int max_w) {
    const int kw = x.c.text(px, y, key, x.t.key, max_w);
    if (label.empty() || kw + 1 >= max_w) return kw;
    const int lw = x.c.text(px + kw + 1, y, label, x.t.key_label, max_w - kw - 1);
    return kw + 1 + lw;
}

int keycap(Ctx& x, int px, int y, std::string_view key) {
    const int w = width_of(x.c, key) + 2;
    x.c.fill(Rect{px, y, w, 1}, x.t.pill);
    x.c.text(px + 1, y, key, x.t.pill_key, w - 2);
    return w;
}

int button(Ctx& x, int px, int y, std::string_view key, std::string_view label, int kind,
           const KeyEvent& ev) {
    const Style body = kind == 2 ? x.t.danger_pill : (kind == 1 ? x.t.primary_pill : x.t.pill);
    const Style keys = kind == 2 ? x.t.danger_key : (kind == 1 ? x.t.primary_key : x.t.pill_key);
    const int w = button_width(x, key, label);
    x.c.fill(Rect{px, y, w, 1}, body);
    int c = px + 1;
    if (!key.empty()) {
        c += x.c.text(c, y, key, keys, 12);
        c += 2;
    }
    x.c.text(c, y, label, body, 24);
    zone(x, Rect{px, y, w, 1}, ev);
    return w;
}

int button_width(const Ctx& x, std::string_view key, std::string_view label) {
    return (key.empty() ? 0 : width_of(x.c, key) + 2) + width_of(x.c, label) + 2;
}

void inline_hints(Ctx& x, int right, int y,
                  std::initializer_list<std::pair<const char*, const char*>> hs,
                  std::initializer_list<KeyEvent> evs) {
    int w = 0;
    for (const auto& h : hs) w += width_of(x.c, h.first) + 1 + width_of(x.c, h.second) + 2;
    w -= 2;
    int px = right - w;
    const KeyEvent* ev = evs.begin();
    for (const auto& h : hs) {
        const int used = hint(x, px, y, h.first, h.second, 40);
        if (ev != evs.end()) {
            zone(x, Rect{px, y, used, 1}, *ev);
            ++ev;
        }
        px += used + 2;
    }
}

void footer(Ctx& x, int y, const std::vector<Hint>& hints, std::string_view right,
            Style right_style) {
    const int cols = x.c.cols();
    int right_w = 0;
    if (!right.empty()) {
        right_w = width_of(x.c, right);
        if (right_w < cols / 2) {
            x.c.text(cols - 2 - right_w, y, right, right_style, right_w);
            right_w += 3;
        } else {
            right_w = 0;
        }
    }
    const std::string sep = std::string(" ") + utf8(x.g.dot) + " ";
    const int sep_w = width_of(x.c, sep);
    std::vector<bool> keep(hints.size(), false);
    int used = 2 + right_w;
    for (int pri = 0; pri < 10; ++pri) {
        for (size_t i = 0; i < hints.size(); ++i) {
            if (hints[i].priority != pri) continue;
            const int w =
                width_of(x.c, hints[i].key) + 1 + width_of(x.c, hints[i].label) + sep_w;
            if (used + w <= cols) {
                keep[i] = true;
                used += w;
            }
        }
    }
    int px = 2;
    bool first = true;
    for (size_t i = 0; i < hints.size(); ++i) {
        if (!keep[i]) continue;
        if (!first) px += x.c.text(px, y, sep, x.t.subtle, sep_w);
        first = false;
        const int w = hint(x, px, y, hints[i].key, hints[i].label, cols - px);
        if (hints[i].click) zone(x, Rect{px, y, w, 1}, hints[i].ev);
        px += w;
    }
}

void toast(Ctx& x, int y, int px, const std::string& message, MessageKind kind) {
    if (message.empty()) return;
    Style st = x.t.muted;
    char32_t mark = x.g.note;
    switch (kind) {
        case MessageKind::Success: st = x.t.ok; mark = x.g.ok; break;
        case MessageKind::Warning: st = x.t.warn; mark = x.g.warn; break;
        case MessageKind::Error: st = x.t.err; mark = x.g.fail; break;
        case MessageKind::Info: st = x.t.accent; break;
        case MessageKind::None: break;
    }
    x.c.glyph(px, y, mark, st);
    x.c.text(px + 2, y, message, kind == MessageKind::Info ? x.t.muted : st,
             x.c.cols() - px - 4);
}

void countdown(Ctx& x, int px, int y, int w, uint64_t remaining, uint64_t total,
               std::string_view what, Style label) {
    const std::string text = std::string(what) + " in " + seconds_text(remaining);
    const int lw = width_of(x.c, text);
    const int bw = w - lw - 2;
    if (bw < 6) {
        x.c.text(px, y, text, label, w);
        return;
    }
    int full = total > 0 ? static_cast<int>((remaining * static_cast<uint64_t>(bw) + total - 1) /
                                            total)
                         : 0;
    full = clampi(full, 0, bw);
    x.c.hline(px, y, full, x.g.bar_full, x.t.bar_full);
    x.c.hline(px + full, y, bw - full, x.g.bar_empty, x.t.bar_empty);
    x.c.text(px + bw + 2, y, text, label, lw);
}

void input_strip(Ctx& x, Rect r, std::string_view v, size_t caret, bool focus,
                 const char* empty_hint) {
    const Style st = focus ? x.t.input_focus : x.t.input;
    x.c.fill(r, st);
    const int inner = r.w - 2;
    if (inner < 1) return;
    if (v.empty()) {
        if (empty_hint != nullptr) x.c.text(r.x + 1, r.y, empty_hint, on(x.t.subtle, st), inner);
        if (focus) x.c.set_cursor(r.x + 1, r.y);
        return;
    }
    if (caret > v.size()) caret = v.size();
    int caret_col = width_of(x.c, v.substr(0, caret));
    size_t start = 0;
    if (focus && caret_col > inner - 1) {  // scroll so the caret stays visible
        size_t i = 0;
        Cluster cl;
        int drop = caret_col - (inner - 1);
        while (drop > 0 && next_cluster(v.data(), v.size(), &i, x.c.width_policy(), &cl))
            drop -= cl.width;
        start = i;
        caret_col = width_of(x.c, v.substr(start, caret - start));
    }
    x.c.text(r.x + 1, r.y, v.substr(start), st, inner, !focus);
    if (focus) x.c.set_cursor(r.x + 1 + caret_col, r.y);
}

// ---------------------------------------------------------------------------
// Entry badges
// ---------------------------------------------------------------------------
namespace {

// Initials: the first letters of the first two words ("GitHub Work" -> GW),
// the first letter and next capital of one CamelCase word (GitHub -> GH), the
// first two letters of another single word (Bank -> BA), or one character
// that is two cells wide on its own (CJK).
std::string initials(const Ctx& x, const std::string& name, int* width) {
    std::string out;
    int w = 0;
    bool word_start = true;
    size_t i = 0;
    Cluster cl;
    const WidthPolicy& wp = x.c.width_policy();
    std::vector<std::pair<size_t, size_t>> letters;  // byte ranges of word-initial letters
    std::vector<std::pair<size_t, size_t>> firsts;   // first word's letters
    int words = 0;
    while (i < name.size()) {
        const size_t at = i;
        if (!next_cluster(name.data(), name.size(), &i, wp, &cl)) break;
        const bool sep = cl.placeholder || (cl.ncp == 1 && cl.cp[0] < 0x80 &&
                                            !((cl.cp[0] >= 'a' && cl.cp[0] <= 'z') ||
                                              (cl.cp[0] >= 'A' && cl.cp[0] <= 'Z') ||
                                              (cl.cp[0] >= '0' && cl.cp[0] <= '9')));
        if (sep) {
            word_start = true;
            continue;
        }
        if (word_start) {
            letters.push_back({at, i});
            ++words;
        }
        if (words == 1) firsts.push_back({at, i});
        word_start = false;
    }
    std::vector<std::pair<size_t, size_t>> pick = words >= 2 ? letters : firsts;
    if (words == 1) {
        // One CamelCase word (GitHub, PayPal): its first letter and next capital.
        for (size_t k = 1; k < firsts.size(); ++k) {
            const char c = name[firsts[k].first];
            if (firsts[k].second - firsts[k].first == 1 && c >= 'A' && c <= 'Z') {
                pick = {firsts[0], firsts[k]};
                break;
            }
        }
    }
    for (const auto& r : pick) {
        std::string piece = name.substr(r.first, r.second - r.first);
        const int pw = width_of(x.c, piece);
        if (w + pw > 2) break;
        if (piece.size() == 1 && piece[0] >= 'a' && piece[0] <= 'z')
            piece[0] = static_cast<char>(piece[0] - 'a' + 'A');
        out += piece;
        w += pw;
        if (w == 2) break;
    }
    if (out.empty()) {
        out = "?";
        w = 1;
    }
    *width = w;
    return out;
}

}  // namespace

Style entry_style(const Ctx& x, const std::string& name, uint8_t color) {
    if (x.t.mono) return x.t.strong;
    if (color >= 1 && color <= ENTRY_COLORS) return x.t.chip[color - 1];
    // Automatic: a palette color picked by the name, stable across sessions.
    uint32_t h = 2166136261u;
    for (char ch : name) h = (h ^ static_cast<uint8_t>(ch)) * 16777619u;
    return x.t.chip[h % ENTRY_COLORS];
}

const char* entry_color_name(uint8_t color) {
    static const char* const kNames[ENTRY_COLORS + 1] = {
        "Auto", "Red", "Amber", "Green", "Teal", "Blue", "Violet", "Pink", "Grey"};
    return color <= ENTRY_COLORS ? kNames[color] : "Auto";
}

void badge(Ctx& x, int px, int y, const std::string& name, uint8_t color) {
    const Style st = entry_style(x, name, color);
    if (!x.t.mono) x.c.fill(Rect{px, y, BADGE_W, 1}, st);
    int w = 0;
    const std::string ini = initials(x, name, &w);
    // Two cells of content sit exactly centered; a lone narrow letter leans
    // left by half a cell, which no terminal can split.
    x.c.text(px + 1, y, ini, st, 2, false);
}

}  // namespace ui
}  // namespace secraxis
