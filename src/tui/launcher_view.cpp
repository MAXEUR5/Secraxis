// launcher_view.cpp — draws the start page (LauncherModel). Shares the theme
// and components with the vault screens (ui_kit), and lays everything out in
// one centered column the width of the logo widget, so the page reads as a
// single composition at any window size.
#include <cstdio>
#include <string>
#include <vector>

#include "secraxis/renderer.h"
#include "ui_kit.h"

namespace secraxis {

namespace {

using namespace ui;
using C = KeyEvent::Code;

KeyEvent chr(char32_t c) { return KeyEvent::chr(c); }
KeyEvent ctrl(char32_t c) { return KeyEvent::chr(c, KEYMOD_CTRL); }
KeyEvent keyev(C c) { return KeyEvent::key(c); }

// ---------------------------------------------------------------------------
// The logo widget: a fixed-size block that never stretches or reflows with
// the window. The wordmark is written with ASCII stand-ins for its glyphs so
// the source stays readable: '#' full block, '=' '|' double lines, 'r' '7'
// 'L' 'J' the double corners (top-left, top-right, bottom-left, bottom-right).
// ---------------------------------------------------------------------------
const char* const kBlockLogo[] = {
    "#######7#######7 ######7######7  #####7 ##7  ##7##7#######7",
    "##r====J##r====J##r====J##r==##7##r==##7L##7##rJ##|##r====J",
    "#######7#####7  ##|     ######rJ#######| L###rJ ##|#######7",
    "L====##|##r==J  ##|     ##r==##7##r==##| ##r##7 ##|L====##|",
    "#######|#######7L######7##|  ##|##|  ##|##rJ ##7##|#######|",
    "L======JL======J L=====JL=J  L=JL=J  L=JL=J  L=JL=JL======J",
};
constexpr int kBlockRows = 6;

const char* const kAsciiLogo[] = {
    " ____   _____   ____  ____       _     __  __  ___   ____  ",
    "/ ___| | ____| / ___||  _ \\     / \\    \\ \\/ / |_ _| / ___| ",
    "\\___ \\ |  _|  | |    | |_) |   / _ \\    \\  /   | |  \\___ \\ ",
    " ___) || |___ | |___ |  _ <   / ___ \\   /  \\   | |   ___) |",
    "|____/ |_____| \\____||_| \\_\\ /_/   \\_\\ /_/\\_\\ |___| |____/ ",
};
constexpr int kAsciiRows = 5;

constexpr int kWidgetW = 66;   // the full widget (logo + info block)
constexpr int kWidgetH = 10;   // 6 logo rows, a gap, 3 info rows

char32_t logo_glyph(char c) {
    switch (c) {
        case '#': return U'\x2588';
        case '=': return U'\x2550';
        case '|': return U'\x2551';
        case 'r': return U'\x2554';
        case '7': return U'\x2557';
        case 'L': return U'\x255A';
        case 'J': return U'\x255D';
        default: return U' ';
    }
}

// The wordmark at (x0, y0), with a left-to-right gradient on the strokes and
// the shadow lines a step back.
void draw_wordmark(Ctx& x, int x0, int y0) {
    const bool blocks = x.g.blocks;
    const char* const* art = blocks ? kBlockLogo : kAsciiLogo;
    const int rows = blocks ? kBlockRows : kAsciiRows;
    for (int r = 0; r < rows; ++r) {
        const std::string line = art[r];
        const int n = static_cast<int>(line.size());
        for (int c = 0; c < n; ++c) {
            const char ch = line[static_cast<size_t>(c)];
            if (ch == ' ') continue;
            const int t = n > 1 ? c * 1000 / (n - 1) : 0;
            Style stroke{blend(x.t.logo_from, x.t.logo_to, t), 0, ATTR_BOLD};
            if (x.t.mono) stroke = x.t.strong;
            if (blocks) {
                const bool shade = ch != '#';
                x.c.glyph(x0 + c, y0 + r, logo_glyph(ch), shade ? x.t.logo_shadow : stroke);
            } else {
                x.c.glyph(x0 + c, y0 + r, static_cast<char32_t>(ch), stroke);
            }
        }
    }
}

// The metasploit-style info block:  "       =[ ... ]" / "+ -- --=[ ... ]".
void info_line(Ctx& x, int x0, int y, bool first, const std::string& text, bool strong) {
    const char* prefix = first ? "       =[ " : "+ -- --=[ ";
    const int pw = 10;
    x.c.text(x0, y, prefix, x.t.subtle, pw);
    x.c.text(x0 + pw, y, text, strong ? x.t.strong : x.t.muted, kWidgetW - pw - 2);
    x.c.text(x0 + kWidgetW - 1, y, "]", x.t.subtle, 1);
}

void logo_widget(Ctx& x, const LauncherModel& m, int x0, int y0) {
    const int art_w = static_cast<int>(std::string(x.g.blocks ? kBlockLogo[0] : kAsciiLogo[0]).size());
    draw_wordmark(x, x0 + (kWidgetW - art_w) / 2, y0);
    const int iy = y0 + kWidgetH - 3;
    const std::string sep = " - ";
    info_line(x, x0, iy, true, "secraxis v" + m.version + sep + "local password vault", true);
    info_line(x, x0, iy + 1, false,
              std::string("AES-256-GCM-SIV") + sep + "XChaCha20-Poly1305" + sep + "Argon2id",
              false);
    std::string third;
    if (m.history_enabled)
        third = std::to_string(m.recent.size()) +
                (m.recent.size() == 1 ? " recent vault" : " recent vaults");
    else
        third = "history off";
    third += sep + "no cloud" + sep + "no telemetry";
    info_line(x, x0, iy + 2, false, third, false);
}

// The compact widget for smaller windows: also fixed (2 rows).
void compact_widget(Ctx& x, const LauncherModel& m, int y0) {
    std::string word;
    for (const char* p = "SECRAXIS"; *p; ++p) {
        if (!word.empty()) word += ' ';
        word += *p;
    }
    const std::string mark = utf8(x.g.brand) + "  ";
    const int w = width_of(x.c, mark) + width_of(x.c, word);
    int px = centered_x(x, w);
    px += x.c.text(px, y0, mark, x.t.accent_bold, w);
    x.c.text(px, y0, word, x.t.strong, w);
    center_text(x, y0 + 1, "vault manager  v" + m.version, x.t.subtle);
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------
std::string folder_of(const std::string& path, bool win) {
    const size_t s = path.find_last_of(win ? "\\/" : "/");
    if (s == std::string::npos) return "";
    if (s == 0) return path.substr(0, 1);
    if (win && s == 2 && path.size() > 2 && path[1] == ':') return path.substr(0, 3);
    return path.substr(0, s);
}

std::string file_of(const std::string& path, bool win) {
    const size_t s = path.find_last_of(win ? "\\/" : "/");
    return s == std::string::npos ? path : path.substr(s + 1);
}

// The icon column: one cell, a glyph from the terminal's own font (no emoji:
// their fonts place them off the cell grid).
int icon_slot(const Ctx&) { return 1; }

// A vault icon: the brand diamond, or a cross for a file no longer there.
void vault_icon(Ctx& x, int px, int y, bool missing, const Style& surface) {
    if (missing) {
        x.c.glyph(px, y, x.g.fail, on(x.t.warn, surface));
        return;
    }
    x.c.glyph(px, y, x.g.brand, on(x.t.accent_bold, surface));
}

void folder_icon(Ctx& x, int px, int y, const Style& surface) {
    x.c.glyph(px, y, x.g.right, on(x.t.subtle, surface));
}

size_t recent_list(Ctx& x, const LauncherModel& m, Rect r) {
    if (r.h < 1) return 0;
    const int count = static_cast<int>(m.recent.size());
    const int cap = r.h;
    // Keep the selection in view.
    int top = 0;
    const int sel = static_cast<int>(m.recent_sel);
    if (sel >= cap) top = sel - cap + 1;
    const int time_w = 9;
    const int icon_w = icon_slot(x) + 1;
    const int rest = r.w - 2 - icon_w - time_w - 2;
    const int name_w = clampi(rest * 42 / 100, 10, 40);
    const int dir_w = rest - name_w - 2;
    for (int k = 0; k < cap && top + k < count; ++k) {
        const int i = top + k;
        const RecentVault& v = m.recent[static_cast<size_t>(i)];
        const int y = r.y + k;
        const bool selected = i == sel;
        const Style surface = selected ? x.t.sel : x.t.text;
        if (selected) {
            x.c.fill(Rect{r.x, y, r.w, 1}, x.t.sel);
            x.c.glyph(r.x, y, x.g.sel_bar, x.t.sel_bar);
        }
        int px = r.x + 2;
        vault_icon(x, px, y, v.missing, surface);
        px += icon_w;
        x.c.text(px, y, file_of(v.path, m.windows_paths),
                 selected ? x.t.sel_strong : x.t.strong, name_w);
        px += name_w + 2;
        if (dir_w > 6)
            x.c.text(px, y, ellipsize_middle(x.c, folder_of(v.path, m.windows_paths), dir_w),
                     selected ? x.t.sel_muted : x.t.muted, dir_w, false);
        const std::string when = v.missing ? std::string("missing")
                                           : relative_time(v.last_opened, m.wall_now_s);
        x.c.text_right(r.right() - 1 - time_w, y, when,
                       v.missing ? on(x.t.warn, surface) : (selected ? x.t.sel_muted : x.t.subtle),
                       time_w);
        zone(x, Rect{r.x, y, r.w, 1}, KeyEvent::pick(i), /*opens=*/true);
    }
    return static_cast<size_t>(cap);
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------
void title_line(Ctx& x, const LauncherModel& m, const char* title) {
    int px = 1;
    x.c.glyph(px, 0, x.g.brand, x.t.accent_bold);
    px += 2;
    px += x.c.text(px, 0, "Secraxis", x.t.strong, x.c.cols() - px);
    if (title != nullptr) {
        px += 2;
        x.c.text(px, 0, title, x.t.muted, x.c.cols() - px);
    }
    const std::string v = "v" + m.version;
    x.c.text_right(x.c.cols() - 2 - width_of(x.c, v), 0, v, x.t.subtle, width_of(x.c, v));
}

size_t home(Ctx& x, const LauncherModel& m) {
    const int cols = x.c.cols(), rows = x.c.rows();
    const int cw = clampi(cols - 4, 30, kWidgetW);
    const int x0 = (cols - cw) / 2;
    const int avail = rows - 3;  // the tip, toast and footer live below
    // One fixed-size composition: the logo widget, the list region (room for
    // the whole history), the buttons. Centered vertically as a block, so
    // nothing moves when vaults are added or the window grows.
    int logo_h = 0;
    if (cols >= kWidgetW + 4 && avail >= kWidgetH + 2 + 2 + 4 + 2) logo_h = kWidgetH;
    else if (avail >= 2 + 2 + 4 + 2) logo_h = 2;
    const int fixed = (logo_h > 0 ? logo_h + 2 : 0) + 2 /*label*/ + 2 /*gap+buttons*/;
    constexpr int kListRows = 8;  // scrolls beyond this
    const int list_h = clampi(avail - fixed - 1, 1, kListRows);
    const int block = fixed + list_h;
    int y = clampi((avail - block) / 2, 1, avail);
    if (logo_h == kWidgetH) {
        logo_widget(x, m, (cols - kWidgetW) / 2, y);
        y += logo_h + 2;
    } else if (logo_h == 2) {
        compact_widget(x, m, y);
        y += 4;
    } else {
        title_line(x, m, nullptr);
    }

    // Recent vaults.
    const char* label = m.history_enabled ? "RECENT VAULTS" : "RECENT VAULTS (history is off)";
    x.c.text(x0, y, label, x.t.label, cw);
    if (!m.recent.empty())
        x.c.text_right(x0, y, std::to_string(m.recent.size()), x.t.subtle, cw);
    y += 2;
    const Rect list{x0, y, cw, list_h};
    size_t cap = 0;
    if (m.recent.empty()) {
        const int cy = list.y + (list.h > 2 ? (list.h - 2) / 2 : 0);
        center_text(x, cy, m.history_enabled ? "No vaults opened yet" : "Nothing is remembered",
                    x.t.muted);
        if (cy + 1 < list.bottom())
            center_text(x, cy + 1, "Create one, or open an existing .seis file.", x.t.subtle);
        cap = static_cast<size_t>(list.h);
    } else {
        cap = recent_list(x, m, list);
    }

    // Actions, right under the list region.
    const int by = list.bottom() + 1;
    if (by < avail) {
        const int w1 = button_width(x, "n", "New vault");
        const int w2 = button_width(x, "o", "Open a vault");
        int px = x0 + (cw - w1 - w2 - 2) / 2;
        px += button(x, px, by, "n", "New vault", 1, chr(U'n')) + 2;
        button(x, px, by, "o", "Open a vault", 0, chr(U'o'));
    }

    // The tip of the day, metasploit-style.
    if (m.message.empty() && rows >= 16) {
        const int used = x.c.text(x0, rows - 3, "tip  ", x.t.accent_bold, 5);
        x.c.text(x0 + used, rows - 3, m.tip, x.t.subtle, cw - used);
    }
    return cap;
}

size_t browse(Ctx& x, const LauncherModel& m) {
    const int cols = x.c.cols(), rows = x.c.rows();
    title_line(x, m, m.pick_folder ? "Choose a folder" : "Open a vault");
    const int cw = clampi(cols - 4, 30, 96);
    const int x0 = (cols - cw) / 2;
    int y = 2;
    // Filter / path input.
    {
        const Style surface = x.t.input_focus;
        x.c.fill(Rect{x0, y, cw, 1}, surface);
        x.c.glyph(x0 + 1, y, x.g.prompt, on(x.t.accent_bold, surface));
        const std::string note = std::to_string(m.rows_total) + (m.rows_total == 1 ? " item" : " items");
        const int nw = width_of(x.c, note);
        x.c.text(x0 + cw - 1 - nw, y, note, on(x.t.muted, surface), nw);
        input_strip(x, Rect{x0 + 2, y, cw - nw - 4, 1}, m.filter, m.filter_caret, true,
                    m.pick_folder ? "Filter, or type a path" : "Filter, or type a path (~ is home)");
    }
    y += 1;
    const std::string where = m.dir.empty() ? std::string("This PC") : m.dir;
    x.c.text(x0 + 1, y, ellipsize_middle(x.c, where, cw - 2), x.t.muted, cw - 2, false);
    y += 2;
    const int list_h = rows - 3 - y;
    if (list_h < 1) return 1;
    if (m.rows_total == 0) {
        center_text(x, y + list_h / 3,
                    m.filter.empty() ? (m.pick_folder ? "No folders here" : "No vaults or folders here")
                                     : "Nothing matches the filter",
                    x.t.muted);
        return static_cast<size_t>(list_h);
    }
    for (size_t k = 0; k < m.rows.size() && static_cast<int>(k) < list_h; ++k) {
        const BrowseRow& r = m.rows[k];
        const int ry = y + static_cast<int>(k);
        const Style surface = r.selected ? x.t.sel : x.t.text;
        if (r.selected) {
            x.c.fill(Rect{x0, ry, cw, 1}, x.t.sel);
            x.c.glyph(x0, ry, x.g.sel_bar, x.t.sel_bar);
        }
        int px = x0 + 2;
        const int slot = icon_slot(x);
        std::string name = r.name;
        Style st = r.selected ? x.t.sel : x.t.text;
        switch (r.kind) {
            case BrowseRow::Kind::Parent:
                x.c.glyph(px + slot - 1, ry, x.g.up, on(x.t.subtle, surface));
                name = "..";
                st = r.selected ? x.t.sel_muted : x.t.muted;
                break;
            case BrowseRow::Kind::UseFolder:
                x.c.glyph(px + slot - 1, ry, x.g.ok, on(x.t.ok, surface));
                st = r.selected ? x.t.sel_strong : x.t.accent_bold;
                break;
            case BrowseRow::Kind::Dir:
                folder_icon(x, px, ry, surface);
                name += m.windows_paths ? "\\" : "/";
                if (m.dir.empty()) name = r.name;  // a drive
                break;
            case BrowseRow::Kind::Vault:
                vault_icon(x, px, ry, false, surface);
                st = r.selected ? x.t.sel_strong : x.t.strong;
                break;
        }
        x.c.text(px + slot + 1, ry, name, st, cw - 4 - slot);
        zone(x, Rect{x0, ry, cw, 1}, KeyEvent::pick(static_cast<int32_t>(r.index)),
             /*opens=*/true);
    }
    // Scrollbar thumb.
    const int total = static_cast<int>(m.rows_total);
    if (total > list_h && list_h > 1) {
        int thumb = list_h * list_h / total;
        if (thumb < 1) thumb = 1;
        const int range = total - list_h;
        const int pos = range > 0 ? (static_cast<int>(m.rows_top) * (list_h - thumb) + range / 2) / range : 0;
        for (int k = 0; k < thumb; ++k) x.c.glyph(x0 + cw, y + pos + k, x.g.thumb, x.t.thumb);
    }
    return static_cast<size_t>(list_h);
}

const char* profile_note(KdfProfileId id) {
    switch (id) {
        case KdfProfileId::Floor: return "384 MiB, 3 passes: the quickest unlock";
        case KdfProfileId::Strong: return "1 GiB, 5 passes, 8 lanes: the slowest to attack";
        default: return "512 MiB, 4 passes: recommended";
    }
}

void new_vault(Ctx& x, const LauncherModel& m) {
    title_line(x, m, "New vault");
    const int w = clampi(x.c.cols() - 6, 46, 74);
    Rect in = dialog(x, w, 15, "New vault", x.t.accent);
    const int lw = 11;
    const int fx = in.x + lw;
    const int fw = in.w - lw;
    int y = in.y;
    auto label = [&](int i, const char* text, bool required) {
        const bool focus = m.new_cursor == static_cast<size_t>(i);
        if (focus) x.c.glyph(in.x - 2, y, x.g.sel_bar, x.t.accent_bold);
        const int used = x.c.text(in.x, y, text, focus ? x.t.label_focus : x.t.muted, lw - 2);
        if (required) x.c.text(in.x + used, y, "*", x.t.accent, 1);
    };
    // Name (".seis" is added).
    label(0, "Name", true);
    const int ext_w = 5;
    input_strip(x, Rect{fx, y, fw - ext_w - 1, 1}, m.new_name, m.new_name_caret, m.new_cursor == 0,
                m.new_cursor == 0 ? nullptr : "personal");
    x.c.text(fx + fw - ext_w, y, ".seis", x.t.subtle, ext_w);
    zone(x, Rect{in.x - 2, y, lw + 2 + fw, 1}, KeyEvent::pick(LAUNCHER_PICK_FIELD + 0));
    y += 2;
    // Folder, with a browse pill.
    label(1, "Folder", true);
    const char* bl = "browse";
    const int bw = width_of(x.c, bl) + 2;
    input_strip(x, Rect{fx, y, fw - bw - 2, 1}, m.new_folder, m.new_folder_caret, m.new_cursor == 1,
                nullptr);
    zone(x, Rect{in.x - 2, y, lw + 2 + fw - bw - 2, 1}, KeyEvent::pick(LAUNCHER_PICK_FIELD + 1));
    x.c.fill(Rect{fx + fw - bw, y, bw, 1}, x.t.pill);
    x.c.text(fx + fw - bw + 1, y, bl, x.t.pill_key, bw - 2);
    zone(x, Rect{fx + fw - bw, y, bw, 1}, ctrl(U'o'));
    y += 2;
    // Security profile: three pills, the chosen one filled.
    label(2, "Security", false);
    {
        const char* names[3] = {"Floor", "Default", "Strong"};
        int px = fx;
        for (int k = 0; k < 3; ++k) {
            const bool on_ = static_cast<int>(m.new_kdf) == k + 1;
            const int pw = width_of(x.c, names[k]) + 2;
            x.c.fill(Rect{px, y, pw, 1}, on_ ? x.t.primary_pill : x.t.pill);
            x.c.text(px + 1, y, names[k], on_ ? x.t.primary_key : x.t.pill, pw - 2);
            zone(x, Rect{px, y, pw, 1}, KeyEvent::pick(LAUNCHER_PICK_PROFILE + k));
            px += pw + 1;
        }
        zone(x, Rect{in.x - 2, y, lw + 2, 1}, KeyEvent::pick(LAUNCHER_PICK_FIELD + 2));
    }
    ++y;
    x.c.text(fx, y, profile_note(m.new_kdf), x.t.subtle, fw);
    y += 2;
    // Where it will go.
    if (!m.new_path.empty()) {
        const int used = x.c.text(in.x, y, "Creates  ", x.t.subtle, 9);
        x.c.text(in.x + used, y, ellipsize_middle(x.c, m.new_path, in.w - used), x.t.muted,
                 in.w - used, false);
    }
    // Message or the buttons.
    const int by = in.bottom() - 1;
    if (!m.message.empty() && m.message_kind != MessageKind::Success) {
        const Style ms = m.message_kind == MessageKind::Error ? x.t.err : x.t.warn;
        x.c.glyph(in.x, by - 1, m.message_kind == MessageKind::Error ? x.g.fail : x.g.warn, ms);
        x.c.text(in.x + 2, by - 1, m.message, ms, in.w - 2);
    }
    {
        const int cw2 = button_width(x, "esc", "Cancel");
        const int sw = button_width(x, "ctrl+s", "Create");
        int px = in.right() - cw2 - sw - 2;
        px += button(x, px, by, "esc", "Cancel", 0, keyev(C::Esc)) + 2;
        const bool focus = m.new_cursor == 3;
        button(x, px, by, focus ? "enter" : "ctrl+s", "Create", 1, ctrl(U's'));
    }
}

void help(Ctx& x) {
    struct Row {
        const char* k;
        const char* l;
    };
    const Row rows[] = {
        {"enter", "open the selected vault"},       {"n", "create a new vault"},
        {"o", "browse for a vault"},                {"x  del", "forget (the file is kept)"},
        {"q  esc", "quit"},                         {"", ""},
        {"in the browser", ""},                     {"type", "filter, or a path such as ~/vaults"},
        {"enter", "open a folder or a vault"},      {"backspace", "up one folder"},
        {"esc", "clear the filter, then go back"},  {"", ""},
        {"mouse", "click selects, double-click opens"},
    };
    const int n = static_cast<int>(sizeof(rows) / sizeof(rows[0]));
    Rect in = dialog(x, clampi(x.c.cols() - 6, 40, 66), n + 4, "Start page", x.t.border);
    zone(x, Rect{in.x - 3, in.y - 2, in.w + 6, in.h + 4}, keyev(C::Esc));
    for (int k = 0; k < n && in.y + k < in.bottom(); ++k) {
        if (rows[k].l[0] == '\0' && rows[k].k[0] != '\0') {
            x.c.text(in.x, in.y + k, rows[k].k, x.t.accent_bold, in.w);
            continue;
        }
        x.c.text(in.x, in.y + k, rows[k].k, x.t.key, 13);
        x.c.text(in.x + 14, in.y + k, rows[k].l, x.t.muted, in.w - 14);
    }
}

std::vector<Hint> hints_for(const LauncherModel& m, const Glyphs& g) {
    const std::string updown = g.unicode() ? utf8(g.up) + utf8(g.down) : std::string("up/dn");
    switch (m.screen) {
        case LauncherScreen::Browse:
            return {{"type", "filter", 2, keyev(C::Down), false},
                    {"enter", m.pick_folder ? "choose" : "open", 0, keyev(C::Enter)},
                    {"backspace", "up", 1, keyev(C::Backspace)},
                    {"esc", "back", 0, keyev(C::Esc)}};
        case LauncherScreen::NewVault:
            return {{"tab", "next", 0, keyev(C::Tab)},
                    {g.unicode() ? utf8(g.left) + utf8(g.right) : std::string("left/right"),
                     "security", 2, keyev(C::Right), false},
                    {"ctrl+o", "browse", 1, ctrl(U'o')},
                    {"ctrl+s", "create", 0, ctrl(U's')},
                    {"esc", "cancel", 0, keyev(C::Esc)}};
        case LauncherScreen::Help:
            return {{"any key", "close", 0, keyev(C::Esc)}};
        case LauncherScreen::Home:
            break;
    }
    return {{updown, "move", 4, keyev(C::Down), false},
            {"enter", "open", 0, keyev(C::Enter)},
            {"n", "new", 0, chr(U'n')},
            {"o", "browse", 1, chr(U'o')},
            {"x", "forget", 3, chr(U'x')},
            {"?", "help", 2, chr(U'?')},
            {"q", "quit", 0, chr(U'q')}};
}

}  // namespace

RenderResult render_launcher(const LauncherModel& m, const RenderEnv& env, int cols, int rows,
                             Canvas* out) {
    RenderResult res;
    const TermCaps& caps = env.caps;
    const Glyphs& g = caps.glyph_set != nullptr ? *caps.glyph_set : glyphs_for(caps.glyphs);
    const Theme t = make_theme(caps);
    out->reset(cols, rows, g, caps.width, t.text);
    Ctx x{env, *out, t, g, &res};
    cols = out->cols();
    rows = out->rows();
    if (cols < MIN_COLS || rows < MIN_ROWS) {
        char b[64];
        std::snprintf(b, sizeof(b), "needs %dx%d, now %dx%d", MIN_COLS, MIN_ROWS, cols, rows);
        center_text(x, rows / 2 - 1, "Window too small", t.strong);
        center_text(x, rows / 2, b, t.muted);
        return res;
    }
    switch (m.screen) {
        case LauncherScreen::Home: res.list_rows = home(x, m); break;
        case LauncherScreen::Browse: res.list_rows = browse(x, m); break;
        case LauncherScreen::NewVault: new_vault(x, m); break;
        case LauncherScreen::Help:
            res.list_rows = home(x, m);
            x.c.fade(t.scrim);
            modal(x);
            help(x);
            break;
    }
    if (m.screen != LauncherScreen::NewVault || m.message_kind == MessageKind::Success)
        toast(x, rows - 2, (cols - clampi(cols - 4, 30, kWidgetW)) / 2, m.message, m.message_kind);
    footer(x, rows - 1, hints_for(m, g), "", t.muted);
    return res;
}

}  // namespace secraxis
