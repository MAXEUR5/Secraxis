#include "secraxis/renderer.h"

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "ui_kit.h"

namespace secraxis {

bool hit_test(const RenderResult& rr, int x, int y, KeyEvent* out, bool* opens) {
    for (size_t k = rr.zones.size(); k-- > 0;) {
        const HitZone& z = rr.zones[k];
        if (x >= z.r.x && x < z.r.right() && y >= z.r.y && y < z.r.bottom()) {
            *out = z.ev;
            if (opens != nullptr) *opens = z.opens;
            return true;
        }
    }
    return false;
}

bool same_click_meaning(const RenderResult& seen, const RenderResult& now, int x, int y) {
    KeyEvent a, b;
    bool opens_a = false, opens_b = false;
    const bool hit_a = hit_test(seen, x, y, &a, &opens_a);
    const bool hit_b = hit_test(now, x, y, &b, &opens_b);
    if (hit_a != hit_b) return false;
    return !hit_a || (a.code == b.code && a.cp == b.cp && a.mods == b.mods && a.arg == b.arg &&
                      opens_a == opens_b);
}

namespace {

using namespace ui;
using C = KeyEvent::Code;

KeyEvent chr(char32_t c) { return KeyEvent::chr(c); }
KeyEvent ctrl(char32_t c) { return KeyEvent::chr(c, KEYMOD_CTRL); }
KeyEvent keyev(C c) { return KeyEvent::key(c); }

const char* kdf_name(uint32_t id) {
    switch (id) {
        case 1: return "Argon2id Floor";
        case 2: return "Argon2id Default";
        case 3: return "Argon2id Strong";
        default: return "Argon2id";
    }
}

const char* aead_name(uint32_t id) {
    switch (id) {
        case 1: return "XChaCha20-Poly1305";
        case 2: return "AES-256-GCM-SIV";
        default: return "AEAD";
    }
}

std::string mask_for_bucket(const Glyphs& g, uint8_t bucket) {
    if (bucket == 0) return "-";
    return repeat(g.bullet, bucket > 5 ? 20 : bucket * 4);
}

// "https://github.com/login" -> "github.com".
std::string host_of(const std::string& url) {
    size_t b = url.find("://");
    b = (b == std::string::npos) ? 0 : b + 3;
    size_t e = url.find_first_of("/?#", b);
    std::string h = url.substr(b, e == std::string::npos ? std::string::npos : e - b);
    const size_t at = h.rfind('@');
    if (at != std::string::npos) h = h.substr(at + 1);
    if (h.compare(0, 4, "www.") == 0) h = h.substr(4);
    return h;
}

// Byte ranges of case-insensitive (ASCII) occurrences of needle in hay: the
// same matching VaultSession::query performs.
std::vector<size_t> find_matches(std::string_view hay, std::string_view needle) {
    std::vector<size_t> out;
    if (needle.empty() || needle.size() > hay.size()) return out;
    auto low = [](char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (size_t i = 0; i + needle.size() <= hay.size();) {
        size_t k = 0;
        while (k < needle.size() && low(hay[i + k]) == low(needle[k])) ++k;
        if (k == needle.size()) {
            out.push_back(i);
            out.push_back(i + k);
            i += k;
        } else {
            ++i;
        }
    }
    return out;
}

const RenderRow* selected_row(const RenderModel& m) {
    for (const RenderRow& r : m.rows)
        if (r.selected) return &r;
    return nullptr;
}

std::string_view secret_view(ByteView b) {
    return std::string_view(reinterpret_cast<const char*>(b.ptr), b.len);
}

// The revealed secret, wrapped into `r` straight from the model's view: no
// copy of it exists anywhere but the canvas cells. Returns rows used.
int wrapped_secret(Ctx& x, Rect r, ByteView secret, Style st) {
    const std::string_view s = secret_view(secret);
    const WidthPolicy& wp = x.c.width_policy();
    int y = r.y;
    size_t line_start = 0, i = 0;
    int col = 0;
    Cluster cl;
    while (i < s.size() && y < r.bottom()) {
        const size_t at = i;
        if (!next_cluster(s.data(), s.size(), &i, wp, &cl)) break;
        if (col + cl.width > r.w) {
            x.c.text(r.x, y, s.substr(line_start, at - line_start), st, r.w, false);
            if (y + 1 >= r.bottom()) {
                // Out of room: mark the truncation explicitly.
                const int ew = width_of(x.c, x.g.ellipsis);
                x.c.text(r.right() - ew, y, x.g.ellipsis, st, ew);
                return y - r.y + 1;
            }
            ++y;
            line_start = at;
            col = 0;
        }
        col += cl.width;
    }
    if (y < r.bottom()) x.c.text(r.x, y, s.substr(line_start), st, r.w, false);
    return y - r.y + 1;
}

int secret_lines(const Ctx& x, ByteView secret, int w) {
    const int sw = static_cast<int>(display_width(secret_view(secret), x.c.width_policy()));
    return w > 0 ? clampi((sw + w - 1) / w, 1, 3) : 1;
}

// A one-line field showing a secret being typed: the tail stays visible
// (that is where the caret is), drawn from the editor's own buffer.
void secret_strip(Ctx& x, Rect r, ByteView secret, bool focus) {
    const Style st = on(x.t.secret, focus ? x.t.input_focus : x.t.input);
    x.c.fill(r, focus ? x.t.input_focus : x.t.input);
    const int inner = r.w - 2;
    if (inner < 1) return;
    const std::string_view s = secret_view(secret);
    int total = static_cast<int>(display_width(s, x.c.width_policy()));
    size_t start = 0;
    if (total > inner - 1) {
        size_t i = 0;
        Cluster cl;
        int drop = total - (inner - 1);
        while (drop > 0 && next_cluster(s.data(), s.size(), &i, x.c.width_policy(), &cl))
            drop -= cl.width;
        start = i;
        total = static_cast<int>(display_width(s.substr(start), x.c.width_policy()));
    }
    x.c.text(r.x + 1, r.y, s.substr(start), st, inner, false);
    if (focus) x.c.set_cursor(r.x + 1 + total, r.y);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------
void header(Ctx& x, const RenderModel& m, bool wide) {
    const int cols = x.c.cols();
    int px = 1;
    x.c.glyph(px, 0, x.g.brand, x.t.accent_bold);
    px += 2;
    px += x.c.text(px, 0, "Secraxis", x.t.strong, cols - px);
    if (!m.vault_name.empty() && px + 4 < cols / 2) {
        px += 2;
        px += x.c.text(px, 0, m.vault_name, x.t.muted, cols / 2 - px);
    }
    struct Seg {
        std::string text;
        Style st;
    };
    std::vector<Seg> segs;
    if (m.vault_open) {
        if (m.dirty) segs.push_back({utf8(x.g.dot_on) + " unsaved", x.t.warn});
        segs.push_back({std::to_string(m.entry_total) +
                            (m.entry_total == 1 ? " entry" : " entries"),
                        x.t.muted});
        if (m.settings.save == SaveMode::Auto) segs.push_back({"autosave", x.t.subtle});
        if (wide) {
            segs.push_back({aead_name(m.aead_profile), x.t.subtle});
            segs.push_back({kdf_name(m.kdf_profile), x.t.subtle});
        }
    } else {
        segs.push_back({m.create_mode ? "new vault" : "locked", x.t.muted});
    }
    const std::string sep = std::string(" ") + utf8(x.g.dot) + " ";
    const int sep_w = width_of(x.c, sep);
    int right = cols - 1;
    const int floor_x = px + 3;
    for (size_t k = 0; k < segs.size(); ++k) {
        const int w = width_of(x.c, segs[k].text);
        const int need = w + (k > 0 ? sep_w : 0);
        if (right - need < floor_x) break;
        if (k > 0) {
            x.c.text(right - sep_w, 0, sep, x.t.subtle, sep_w);
            right -= sep_w;
        }
        x.c.text(right - w, 0, segs[k].text, segs[k].st, w);
        right -= w;
    }
}

std::vector<Hint> hints_for(const RenderModel& m, const Glyphs& g, bool wide) {
    const std::string updown = g.unicode() ? utf8(g.up) + utf8(g.down) : std::string("up/dn");
    const char* esc_label = m.from_launcher ? "back" : "quit";
    switch (m.state) {
        case TuiState::Locked:
            if (m.create_mode && m.confirm_stage)
                return {{"enter", "create vault", 0, keyev(C::Enter)},
                        {"esc", "back", 0, keyev(C::Esc)},
                        {"ctrl+u", "clear", 1, ctrl(U'u')}};
            return {{"enter", m.create_mode ? "continue" : "unlock", 0, keyev(C::Enter)},
                    {"esc", esc_label, 0, keyev(C::Esc)},
                    {"ctrl+u", "clear", 1, ctrl(U'u')}};
        case TuiState::Unlocking:
            return {{"esc", "cancel", 0, keyev(C::Esc)}};
        case TuiState::Query:
            return {{"enter", "done", 0, keyev(C::Enter)}, {updown, "pick", 1, keyev(C::Down), false},
                    {"esc", "cancel", 0, keyev(C::Esc)}, {"ctrl+u", "clear", 2, ctrl(U'u')}};
        case TuiState::AddEntry:
        case TuiState::EditEntry:
            return {{"tab", "next field", 0, keyev(C::Tab)},
                    {"shift+tab", "previous", 3, keyev(C::BackTab)},
                    {"ctrl+r", m.form_revealed ? "hide password" : "show password", 1, ctrl(U'r')},
                    {"ctrl+s", "save", 0, ctrl(U's')},
                    {"esc", "cancel", 0, keyev(C::Esc)}};
        case TuiState::DeleteConfirm:
            return {{"y", "delete", 0, chr(U'y')}, {"n", "keep", 0, chr(U'n')}};
        case TuiState::SaveConflict:
            return {{"c", "save a copy", 0, chr(U'c')}, {"o", "overwrite", 0, chr(U'o')},
                    {"esc", "back", 0, keyev(C::Esc)}};
        case TuiState::CloseConfirm:
            return {{"s", "save and lock", 0, chr(U's')}, {"d", "discard and lock", 0, chr(U'd')},
                    {"esc", "cancel", 0, keyev(C::Esc)}};
        case TuiState::Settings:
            return {{updown, "choose", 1, keyev(C::Down), false},
                    {g.unicode() ? utf8(g.left) + utf8(g.right) : std::string("left/right"),
                     "change", 0, keyev(C::Right)},
                    {"esc", "done", 0, keyev(C::Esc)}};
        case TuiState::RevealSecret:
            return {{"any key", "hide", 0, keyev(C::Esc)}};
        case TuiState::Help:
        case TuiState::Error:
            return {{"any key", "close", 0, keyev(C::Esc)}};
        default:
            break;
    }
    std::vector<Hint> h = {{updown, "move", 6, keyev(C::Down), false},
                           {"/", "search", 1, chr(U'/')}};
    if (!wide)
        h.push_back({"enter", m.details_open ? "close" : "details", 2, keyev(C::Enter)});
    h.push_back({"a", "add", 1, chr(U'a')});
    h.push_back({"s", "show", 0, chr(U's')});
    h.push_back({"p", "copy", 0, chr(U'p')});
    h.push_back({"m", "edit", 4, chr(U'm')});
    h.push_back({"d", "delete", 5, chr(U'd')});
    h.push_back({"w", "save", m.dirty ? 1 : 3, chr(U'w')});
    h.push_back({"q", "lock", 3, chr(U'q')});
    h.push_back({"o", "settings", 6, chr(U'o')});
    h.push_back({"?", "help", 0, chr(U'?')});
    return h;
}

// ---------------------------------------------------------------------------
// Search bar and entry list
// ---------------------------------------------------------------------------
void search_bar(Ctx& x, const RenderModel& m, Rect r) {
    const bool active = m.state == TuiState::Query;
    const Style surface = active ? x.t.input_focus : x.t.input;
    x.c.fill(r, surface);
    x.c.glyph(r.x + 1, r.y, x.g.prompt, on(active ? x.t.accent_bold : x.t.subtle, surface));
    const int tx = r.x + 3;
    int tw = r.w - 4;
    std::string note;
    Style note_st = on(x.t.muted, surface);
    if (active || !m.filter.empty()) {
        note = std::to_string(m.view_total) + " of " + std::to_string(m.entry_total);
        if (active && !m.live_search) note = "enter to search";
    } else {
        note = "/";
        note_st = on(x.t.subtle, surface);
    }
    const int nw = width_of(x.c, note);
    if (nw + 4 < tw / 2) {
        x.c.text(r.right() - 1 - nw, r.y, note, note_st, nw);
        tw -= nw + 2;
    }
    if (active) {
        Rect field{tx - 1, r.y, tw + 2, 1};
        input_strip(x, field, m.query_text, m.query_caret, true,
                    "Search names, users, sites, tags");
        return;
    }
    zone(x, r, chr(U'/'));
    if (!m.filter.empty()) x.c.text(tx, r.y, m.filter, surface, tw);
    else x.c.text(tx, r.y, "Search", on(x.t.subtle, surface), tw);
}

struct Columns {
    int badge = 0;  // badge + gap
    int name = 0, user = 0, time = 0;
};

Columns plan_columns(const Ctx& x, const RenderModel& m, int w) {
    Columns c;
    if ((!x.t.mono || x.g.emoji) && w >= 44) c.badge = BADGE_W + 1;
    if (real_time(m.wall_now_s) && w >= 54) c.time = 9;
    const int rest = w - c.badge - (c.time > 0 ? c.time + 2 : 0);
    if (rest >= 40) {
        c.name = rest * 48 / 100;
        c.user = rest - c.name - 2;
    } else if (rest >= 28) {
        c.name = rest * 55 / 100;
        c.user = rest - c.name - 2;
    } else {
        c.name = rest;
    }
    return c;
}

void empty_list(Ctx& x, const RenderModel& m, Rect r) {
    const int cy = r.y + (r.h - 3) / 2;
    std::string title;
    const char* key;
    const char* label;
    KeyEvent ev;
    if (!m.filter.empty() || m.state == TuiState::Query) {
        const std::string& q = m.state == TuiState::Query ? m.query_text : m.filter;
        title = "No entries match \"" + q + "\"";
        key = "esc";
        label = "to clear the search";
        ev = keyev(C::Esc);
    } else {
        title = "Your vault is empty";
        key = "a";
        label = "to add your first entry";
        ev = chr(U'a');
    }
    const int tw = width_of(x.c, title);
    x.c.text(r.x + (r.w - (tw < r.w ? tw : r.w)) / 2, cy, title, x.t.strong, r.w);
    const int hw = 6 + width_of(x.c, key) + 2 + 1 + width_of(x.c, label);
    if (hw <= r.w && cy + 2 < r.bottom()) {
        int px = r.x + (r.w - hw) / 2;
        const int start = px;
        px += x.c.text(px, cy + 2, "Press ", x.t.muted, 6);
        px += keycap(x, px, cy + 2, key);
        x.c.text(px + 1, cy + 2, label, x.t.muted, r.right() - px - 1);
        zone(x, Rect{start, cy + 2, hw, 1}, ev);
    }
}

// The list occupies `r`: a column header row, then entries. Returns the
// number of entry rows shown.
size_t entry_list(Ctx& x, const RenderModel& m, Rect r) {
    if (r.w < 8 || r.h < 2) return 0;
    const int list_y = r.y + 1;
    const int list_h = r.h - 1;
    if (m.view_total == 0) {
        empty_list(x, m, Rect{r.x, list_y, r.w, list_h});
        return static_cast<size_t>(list_h);
    }
    const int cx = r.x + 2;  // after the selection bar + space
    const int cw = r.w - 4;  // keep the scrollbar column free
    const Columns col = plan_columns(x, m, cw);
    int px = cx + col.badge;
    x.c.text(px, r.y, "NAME", x.t.label, col.name);
    px += col.name + 2;
    if (col.user > 0) x.c.text(px, r.y, "USERNAME", x.t.label, col.user);
    if (col.time > 0) x.c.text_right(cx + cw - col.time, r.y, "UPDATED", x.t.label, col.time);

    const std::string& needle = m.state == TuiState::Query ? m.query_text : m.filter;
    for (size_t k = 0; k < m.rows.size() && static_cast<int>(k) < list_h; ++k) {
        const RenderRow& row = m.rows[k];
        const int y = list_y + static_cast<int>(k);
        const bool sel = row.selected;
        if (sel) {
            x.c.fill(Rect{r.x, y, r.w - 1, 1}, x.t.sel);
            x.c.glyph(r.x, y, x.g.sel_bar, x.t.sel_bar);
        }
        px = cx;
        if (col.badge > 0) {
            badge(x, px, y, row.name, row.url, row.tags);
            px += col.badge;
        }
        const Style s_name = sel ? x.t.sel_strong : x.t.text;
        const Style s_dim = sel ? x.t.sel_muted : x.t.muted;
        const Style s_hl = sel ? x.t.match_sel : x.t.match;
        if (row.name.empty())
            x.c.text(px, y, "(no name)", s_dim, col.name);
        else
            x.c.text_hl(px, y, row.name, s_name, col.name, find_matches(row.name, needle), s_hl);
        px += col.name + 2;
        if (col.user > 0)
            x.c.text_hl(px, y, row.username, s_dim, col.user, find_matches(row.username, needle),
                        s_hl);
        if (col.time > 0)
            x.c.text_right(cx + cw - col.time, y, relative_time(row.updated_at, m.wall_now_s),
                           sel ? x.t.sel_muted : x.t.subtle, col.time);
        zone(x, Rect{r.x, y, r.w - 1, 1}, KeyEvent::pick(static_cast<int32_t>(row.ordinal - 1)),
             /*opens=*/true);
    }

    // Scrollbar thumb only (no track): quiet until the list overflows.
    const int total = static_cast<int>(m.view_total);
    if (total > list_h && list_h > 1) {
        int thumb = list_h * list_h / total;
        if (thumb < 1) thumb = 1;
        const int range = total - list_h;
        const int top = static_cast<int>(m.view_top);
        const int pos = range > 0 ? (top * (list_h - thumb) + range / 2) / range : 0;
        for (int k = 0; k < thumb; ++k)
            x.c.glyph(r.right() - 1, list_y + pos + k, x.g.thumb, x.t.thumb);
    }
    return static_cast<size_t>(list_h);
}

// ---------------------------------------------------------------------------
// Details (pane in wide layouts, sheet otherwise)
// ---------------------------------------------------------------------------
void tag_pills(Ctx& x, int px, int y, int w, const std::string& tags) {
    int col = 0;
    size_t b = 0;
    while (b < tags.size()) {
        size_t e = tags.find(',', b);
        if (e == std::string::npos) e = tags.size();
        size_t s0 = b, s1 = e;
        while (s0 < s1 && tags[s0] == ' ') ++s0;
        while (s1 > s0 && tags[s1 - 1] == ' ') --s1;
        b = e + 1;
        if (s1 == s0) continue;
        const std::string_view tag(tags.data() + s0, s1 - s0);
        const int tw = width_of(x.c, tag) + 2;
        if (col > 0 && col + tw > w) {
            x.c.text(px + col, y, x.g.ellipsis, x.t.subtle, w - col);
            return;
        }
        x.c.glyph(px + col, y, U' ', x.t.pill);
        const int used = x.c.text(px + col + 1, y, tag, x.t.pill, w - col - 2);
        x.c.glyph(px + col + 1 + used, y, U' ', x.t.pill);
        col += used + 3;
    }
}

void details_pane(Ctx& x, const RenderModel& m, Rect r) {
    const RenderRow* row = selected_row(m);
    if (row == nullptr) {
        x.c.text(r.x, r.y, "Nothing selected", x.t.subtle, r.w);
        return;
    }
    const bool revealing = m.state == TuiState::RevealSecret && m.reveal_text.len > 0;
    int y = r.y;
    const int bottom = r.bottom() - 2;  // keep the timestamp line free
    // Title: the entry's badge, its name, and the site under it.
    int tx = r.x;
    if ((!x.t.mono || x.g.emoji) && r.w > 20) {
        badge(x, r.x, y, row->name, row->url, row->tags);
        tx = r.x + BADGE_W + 1;
    }
    x.c.text(tx, y++, row->name.empty() ? std::string_view("(no name)") : row->name, x.t.strong,
             r.right() - tx);
    const std::string sub = row->url.empty() ? std::string() : host_of(row->url);
    if (!sub.empty()) x.c.text(tx, y, sub, x.t.muted, r.right() - tx);
    y += 2;

    auto section = [&](const char* label) { x.c.text(r.x, y++, label, x.t.label, r.w); };
    if (y + 1 < bottom) {
        section("USERNAME");
        x.c.text(r.x, y, row->username.empty() ? std::string_view("-") : row->username,
                 row->username.empty() ? x.t.subtle : x.t.text, r.w - 10);
        if (!row->username.empty() && r.w > 24)
            inline_hints(x, r.right(), y, {{"u", "copy"}}, {chr(U'u')});
        y += 2;
    }
    if (y + 1 < bottom) {
        section("PASSWORD");
        if (revealing) {
            const int lines = clampi(bottom - y - 1, 1, 3);
            y += wrapped_secret(x, Rect{r.x, y, r.w, lines}, m.reveal_text, x.t.secret);
            if (y < bottom)
                countdown(x, r.x, y++, r.w, m.reveal_remaining_ms, m.reveal_ttl_ms, "hides",
                          x.t.subtle);
        } else {
            x.c.text(r.x, y, mask_for_bucket(x.g, row->pw_bucket), x.t.muted, r.w - 18);
            if (r.w > 30)
                inline_hints(x, r.right(), y, {{"s", "show"}, {"p", "copy"}},
                             {chr(U's'), chr(U'p')});
            ++y;
        }
        ++y;
    }
    if (!row->url.empty() && y + 1 < bottom) {
        section("WEBSITE");
        x.c.text(r.x, y, row->url, x.t.accent, r.w);
        y += 2;
    }
    if (!row->tags.empty() && y + 1 < bottom) {
        section("TAGS");
        tag_pills(x, r.x, y, r.w, row->tags);
        y += 2;
    }
    if (!row->remark.empty() && y + 1 < bottom) {
        section("REMARK");
        const std::vector<Span> ls = wrap(row->remark, r.w, x.c.width_policy());
        for (size_t k = 0; k < ls.size() && y < bottom; ++k) {
            const bool last = (k + 1 == ls.size()) || y + 1 >= bottom || k == 3;
            if (last && k + 1 < ls.size()) {
                std::string tail(slice(row->remark, ls[k]));
                tail += x.g.ellipsis;
                x.c.text(r.x, y++, tail, x.t.text, r.w);
                break;
            }
            x.c.text(r.x, y++, slice(row->remark, ls[k]), x.t.text, r.w);
        }
    }
    if (real_time(row->created_at) || real_time(row->updated_at)) {
        std::string ts;
        if (real_time(row->created_at))
            ts = "created " + format_date(row->created_at, x.env.utc_offset_s, false);
        const std::string rel = relative_time(row->updated_at, m.wall_now_s);
        if (real_time(row->updated_at)) {
            if (!ts.empty()) ts += std::string("  ") + utf8(x.g.dot) + "  ";
            ts += "updated " +
                  (rel.empty() ? format_date(row->updated_at, x.env.utc_offset_s, true) : rel);
        }
        x.c.text(r.x, r.bottom() - 1, ts, x.t.subtle, r.w);
    }
}

void details_sheet(Ctx& x, const RenderModel& m) {
    const int w = clampi(x.c.cols() - 6, 34, 72);
    const int h = clampi(x.c.rows() - 4, 12, 24);
    Rect in = dialog(x, w, h, "Entry", x.t.border);
    details_pane(x, m, in);
}

void reveal_dialog(Ctx& x, const RenderModel& m) {
    const RenderRow* row = selected_row(m);
    const int w = clampi(x.c.cols() - 8, 32, 64);
    const int lines = secret_lines(x, m.reveal_text, w - 6);
    const std::string title =
        (row != nullptr && !row->name.empty()) ? row->name : std::string("Entry");
    Rect in = dialog(x, w, 8 + lines, title, x.t.border);
    zone(x, Rect{in.x - 3, in.y - 2, in.w + 6, in.h + 4}, keyev(C::Esc));  // a click hides
    x.c.text(in.x, in.y, "PASSWORD", x.t.label, in.w);
    wrapped_secret(x, Rect{in.x, in.y + 1, in.w, lines}, m.reveal_text, x.t.secret);
    countdown(x, in.x, in.y + lines + 2, in.w, m.reveal_remaining_ms, m.reveal_ttl_ms, "hides",
              x.t.subtle);
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------
void delete_dialog(Ctx& x, const RenderModel& m) {
    const RenderRow* row = selected_row(m);
    const int w = clampi(x.c.cols() - 8, 36, 60);
    Rect in = dialog(x, w, 12, "Delete entry", x.t.err);
    int y = in.y;
    std::string q = "Delete \"";
    q += (row != nullptr && !row->name.empty()) ? row->name : std::string("(no name)");
    q += "\"?";
    x.c.text(in.x, y++, q, x.t.strong, in.w);
    if (row != nullptr && !row->username.empty()) x.c.text(in.x, y, row->username, x.t.muted, in.w);
    y += 2;
    const char* note = "It leaves this session now, and the vault file when you save.";
    for (const Span& sp : wrap(note, in.w, x.c.width_policy())) {
        if (y >= in.bottom() - 2) break;
        x.c.text(in.x, y++, slice(note, sp), x.t.muted, in.w);
    }
    const int by = in.bottom() - 1;
    const int dw = button_width(x, "y", "Delete");
    const int kw = button_width(x, "n", "Keep");
    int px = in.right() - dw - kw - 2;
    if (px < in.x) px = in.x;
    px += button(x, px, by, "n", "Keep", 0, chr(U'n')) + 2;
    button(x, px, by, "y", "Delete", 2, chr(U'y'));
}

// A save found the vault file changed on disk (another window, a sync tool).
void conflict_dialog(Ctx& x, const RenderModel& m) {
    const int w = clampi(x.c.cols() - 8, 40, 64);
    Rect in = dialog(x, w, 13, "Vault changed on disk", x.t.warn);
    int y = in.y;
    const std::string what =
        "Another window or program (a sync tool?) saved this vault after you opened it. "
        "Saving here would erase what it saved.";
    for (const Span& sp : wrap(what, in.w, x.c.width_policy())) {
        if (y >= in.bottom() - 4) break;
        x.c.text(in.x, y++, slice(what, sp), x.t.strong, in.w);
    }
    ++y;
    const std::string copy = "A copy keeps both: this window's version goes to " +
                             (m.conflict_copy.empty() ? std::string("a new file") : m.conflict_copy) +
                             ", next to the vault.";
    for (const Span& sp : wrap(copy, in.w, x.c.width_policy())) {
        if (y >= in.bottom() - 2) break;
        x.c.text(in.x, y++, slice(copy, sp), x.t.muted, in.w);
    }
    const int by = in.bottom() - 1;
    const int bw = button_width(x, "esc", "Back");
    const int ow = button_width(x, "o", "Overwrite");
    const int cw = button_width(x, "c", "Save a copy");
    int px = in.right() - bw - ow - cw - 4;
    if (px < in.x) px = in.x;
    px += button(x, px, by, "esc", "Back", 0, keyev(KeyEvent::Code::Esc)) + 2;
    px += button(x, px, by, "o", "Overwrite", 2, chr(U'o')) + 2;
    button(x, px, by, "c", "Save a copy", 1, chr(U'c'));
}

// Lines `s` takes wrapped to `w` columns.
int wrapped_lines(const Ctx& x, std::string_view s, int w) {
    return static_cast<int>(wrap(s, w, x.c.width_policy()).size());
}

// The interior width dialog(x, w, ...) will give.
int dialog_inner(const Ctx& x, int w) { return clampi(w, 12, x.c.cols() - 2) - 6; }

// q with unsaved changes: save and lock, discard and lock, or cancel.
void close_dialog(Ctx& x) {
    const std::string what =
        "This vault has changes that are not saved yet. Save them before it locks?";
    const std::string note = "Discarding leaves the vault file as it was last saved.";
    const int w = clampi(x.c.cols() - 8, 40, 64);
    const int iw = dialog_inner(x, w);
    const char* save_l = "Save and lock";
    const char* drop_l = "Discard and lock";
    const int cw = button_width(x, "esc", "Cancel");
    if (cw + button_width(x, "d", drop_l) + button_width(x, "s", save_l) + 4 > iw) {
        save_l = "Save";
        drop_l = "Discard";
    }
    const int dw = button_width(x, "d", drop_l);
    const int sw = button_width(x, "s", save_l);
    const bool one_row = cw + dw + sw + 4 <= iw;
    const int h = 4 + wrapped_lines(x, what, iw) + 1 + wrapped_lines(x, note, iw) + 1 +
                  (one_row ? 1 : 2);
    Rect in = dialog(x, w, h, "Unsaved changes", x.t.warn);
    const int by = in.bottom() - 1;
    const int text_end = by - (one_row ? 1 : 2);
    int y = in.y;
    for (const Span& sp : wrap(what, in.w, x.c.width_policy())) {
        if (y >= text_end) break;
        x.c.text(in.x, y++, slice(what, sp), x.t.strong, in.w);
    }
    ++y;
    for (const Span& sp : wrap(note, in.w, x.c.width_policy())) {
        if (y >= text_end) break;
        x.c.text(in.x, y++, slice(note, sp), x.t.muted, in.w);
    }
    // One row when the buttons fit, else Cancel above the other two.
    int px = in.right() - (one_row ? cw + dw + sw + 4 : dw + sw + 2);
    if (px < in.x) px = in.x;
    if (one_row) px += button(x, px, by, "esc", "Cancel", 0, keyev(C::Esc)) + 2;
    else button(x, in.right() - cw, by - 1, "esc", "Cancel", 0, keyev(C::Esc));
    px += button(x, px, by, "d", drop_l, 2, chr(U'd')) + 2;
    button(x, px, by, "s", save_l, 1, chr(U's'));
}

// How changes are saved: two items, the focused one marked. A click on an
// item changes it.
void settings_dialog(Ctx& x, const RenderModel& m) {
    struct Item {
        const char* label;
        const char* value;
        const char* note;
    };
    const bool autosave = m.settings.save == SaveMode::Auto;
    const bool keep = m.settings.unattended == Unattended::Save;
    const Item items[] = {
        {"SAVE CHANGES", autosave ? "automatically" : "when I press w",
         autosave ? "Every entry you add, edit or delete is saved at once."
                  : "w or Ctrl+S saves. Locking with unsaved changes asks what to do."},
        {"AT AN IDLE LOCK, OR WHEN THE TERMINAL CLOSES",
         keep ? "save unsaved changes" : "discard unsaved changes",
         keep ? "Nobody is there to ask, so they are saved: to a copy next to the vault if "
                "it changed on disk."
              : "Nobody is there to ask, so they are dropped. Nothing is written without you."},
    };
    constexpr int kItems = 2;
    const int w = clampi(x.c.cols() - 8, 40, 72);
    const int iw = dialog_inner(x, w) - 2;  // items are indented past the focus bar
    // Each item: its label and value, its note, a gap. A short window keeps
    // every label and value (no setting may change unseen), and the focused
    // item's note if it still fits.
    int notes[kItems];
    for (int i = 0; i < kItems; ++i) notes[i] = wrapped_lines(x, items[i].note, iw);
    const int room = x.c.rows() - 2 - 4 - 1;  // dialog() keeps 2 rows free; the button row
    bool show_note[kItems] = {true, true};
    int body = 0;
    for (int i = 0; i < kItems; ++i) body += 2 + notes[i] + 1;
    if (body > room) {
        body = kItems * 3 - 1;
        const int f = m.settings_cursor < static_cast<size_t>(kItems)
                          ? static_cast<int>(m.settings_cursor)
                          : 0;
        for (int i = 0; i < kItems; ++i) show_note[i] = i == f && body + notes[i] <= room;
        if (show_note[f]) body += notes[f];
    }
    Rect in = dialog(x, w, 4 + body + 1, "Settings", x.t.border);
    const std::string left = x.g.unicode() ? utf8(x.g.left) : std::string("<");
    const std::string right = x.g.unicode() ? utf8(x.g.right) : std::string(">");
    const int by = in.bottom() - 1;
    int y = in.y;
    for (int i = 0; i < kItems; ++i) {
        const Item& it = items[i];
        const bool focus = m.settings_cursor == static_cast<size_t>(i);
        const int top = y;
        if (y >= by) break;
        x.c.text(in.x + 2, y++, it.label, focus ? x.t.label_focus : x.t.label, in.w - 2);
        if (y >= by) break;
        const std::string value = left + " " + it.value + " " + right;
        const int vw = width_of(x.c, value) + 2 < in.w - 2 ? width_of(x.c, value) + 2 : in.w - 2;
        x.c.fill(Rect{in.x + 2, y, vw, 1}, focus ? x.t.primary_pill : x.t.pill);
        x.c.text(in.x + 3, y++, value, focus ? x.t.primary_key : x.t.pill_key, vw - 2);
        if (show_note[i]) {
            for (const Span& sp : wrap(it.note, in.w - 2, x.c.width_policy())) {
                if (y >= by) break;
                x.c.text(in.x + 2, y++, slice(it.note, sp), x.t.muted, in.w - 2);
            }
        }
        if (focus)
            for (int k = top; k < y; ++k) x.c.glyph(in.x, k, x.g.sel_bar, x.t.sel_bar);
        zone(x, Rect{in.x, top, in.w, y - top}, KeyEvent::pick(i));
        ++y;
    }
    const int dw = button_width(x, "esc", "Done");
    button(x, in.right() - dw, by, "esc", "Done", 0, keyev(C::Esc));
}

void help_dialog(Ctx& x, const RenderModel& m) {
    struct Row {
        const char* k;
        const char* l;
    };
    struct Section {
        const char* title;
        std::vector<Row> rows;
    };
    const std::string updown = x.g.unicode() ? utf8(x.g.up) + utf8(x.g.down) + "  j k"
                                             : std::string("up dn  j k");
    const std::string leftright =
        x.g.unicode() ? utf8(x.g.left) + utf8(x.g.right) : std::string("left right");
    const Section secs[] = {
        {"Navigate", {{updown.c_str(), "move"}, {"pgup pgdn", "page"},
                      {"home end", "first, last"}, {"enter", "details"},
                      {"click", "select; double-click opens"}}},
        {"Entries", {{"a", "add"}, {"m", "edit"}, {"d", "delete"},
                     {"/", "search (never passwords)"}, {"esc", "back, clear search"}}},
        {"Secrets", {{"s", "show password"}, {"p", "copy password"}, {"u", "copy username"}}},
        {"Vault", {{"w  ctrl+s", "save"}, {"r", "re-seal memory"},
                   {"q", "lock (asks if unsaved)"}, {"o", "settings"}}},
        {"Forms", {{"tab", "next field"}, {"shift+tab", "previous field"},
                   {leftright.c_str(), "move the cursor"}, {"ctrl+r", "show password"},
                   {"ctrl+u", "clear field"}, {"ctrl+s", "save entry"}}},
    };
    constexpr int kSections = 5;
    constexpr int kSplit = 3;
    auto lines_of = [&](int from, int to) {
        int n = 0;
        for (int k = from; k < to; ++k) n += 2 + static_cast<int>(secs[k].rows.size());
        return n - 1;
    };
    const int w = clampi(x.c.cols() - 6, 40, 84);
    const bool two_col = w - 6 >= 72;
    const int body = two_col ? (lines_of(0, kSplit) > lines_of(kSplit, kSections)
                                    ? lines_of(0, kSplit)
                                    : lines_of(kSplit, kSections))
                             : lines_of(0, kSections);
    Rect in = dialog(x, w, body + 6, "Shortcuts", x.t.border);
    zone(x, Rect{in.x - 3, in.y - 2, in.w + 6, in.h + 4}, keyev(C::Esc));  // a click closes
    const int colw = two_col ? (in.w - 4) / 2 : in.w;
    const int keyw = 12;
    int y = in.y;
    int col_x = in.x;
    for (int k = 0; k < kSections; ++k) {
        if (two_col && k == kSplit) {
            col_x = in.x + colw + 4;
            y = in.y;
        }
        if (y >= in.bottom() - 1) continue;
        x.c.text(col_x, y++, secs[k].title, x.t.accent_bold, colw);
        for (const Row& rr : secs[k].rows) {
            if (y >= in.bottom() - 1) break;
            x.c.text(col_x, y, rr.k, x.t.key, keyw - 1);
            x.c.text(col_x + keyw, y, rr.l, x.t.muted, colw - keyw);
            ++y;
        }
        ++y;
    }
    char foot[112];
    std::snprintf(foot, sizeof(foot),
                  "Shown passwords hide after %llus. Copied ones leave the clipboard after %llus.",
                  static_cast<unsigned long long>(m.reveal_ttl_ms / 1000),
                  static_cast<unsigned long long>(m.clip_ttl_ms / 1000));
    x.c.text(in.x, in.bottom() - 1, foot, x.t.subtle, in.w);
}

void form_dialog(Ctx& x, const RenderModel& m) {
    const int n = static_cast<int>(m.form.size());
    const bool roomy = x.c.rows() >= n * 2 + 8;  // a blank line between fields
    const int step = roomy ? 2 : 1;
    const int h = n * step + (roomy ? 5 : 6);
    const int w = clampi(x.c.cols() - 6, 44, 76);
    Rect in = dialog(x, w, h, m.editing_existing ? "Edit entry" : "New entry", x.t.accent);
    const int lw = 11;
    const int fx = in.x + lw;
    const int fw = in.w - lw;
    // The password field carries the show/hide pill; the confirm field the
    // match mark. Both stay in the same column so the fields line up.
    const char* pill = m.form_revealed ? "hide" : "show";
    const int pill_w = width_of(x.c, pill) + 2;
    const int side_w = 9;  // fits the pill and "x differ" alike
    int y = in.y;
    for (int i = 0; i < n && y < in.bottom() - 1; ++i) {
        const FormField& f = m.form[static_cast<size_t>(i)];
        const bool focus = static_cast<size_t>(i) == m.form_cursor;
        if (focus) x.c.glyph(in.x - 2, y, x.g.sel_bar, x.t.accent_bold);
        const int used = x.c.text(in.x, y, f.label, focus ? x.t.label_focus : x.t.muted, lw - 2);
        if (f.required) x.c.text(in.x + used, y, "*", x.t.accent, 1);
        int field_w = fw;
        if (f.secret && fw - side_w - 2 > 10) {
            field_w = fw - side_w - 2;
            const int px = fx + field_w + 2;
            if (i == n - 2 || (i == n - 1 && m.pw_match < 0)) {
                if (i == n - 2) {
                    // Show / hide (Ctrl+R or a click).
                    x.c.fill(Rect{px, y, pill_w, 1}, m.form_revealed ? x.t.primary_pill : x.t.pill);
                    x.c.text(px + 1, y, pill,
                             m.form_revealed ? x.t.primary_key : x.t.pill_key, pill_w - 2);
                    zone(x, Rect{px, y, pill_w, 1}, ctrl(U'r'));
                }
            } else if (i == n - 1) {
                const bool okm = m.pw_match == 1;
                x.c.glyph(px, y, okm ? x.g.ok : x.g.fail, okm ? x.t.ok : x.t.err);
                x.c.text(px + 2, y, okm ? "match" : "differ", okm ? x.t.ok : x.t.err, side_w - 2);
            }
        }
        const Rect field{fx, y, field_w, 1};
        if (f.secret && f.reveal.len > 0) {
            secret_strip(x, field, f.reveal, focus);
        } else if (f.secret) {
            const char* hint_text = f.required ? nullptr : "unchanged";
            const Style st = focus ? x.t.input_focus : x.t.input;
            x.c.fill(field, st);
            const int cnt = static_cast<int>(f.secret_chars);
            if (cnt == 0 && hint_text != nullptr) {
                x.c.text(fx + 1, y, hint_text, on(x.t.subtle, st), field_w - 2);
                if (focus) x.c.set_cursor(fx + 1, y);
            } else {
                const int shown = cnt < field_w - 3 ? cnt : field_w - 3;
                x.c.hline(fx + 1, y, shown, x.g.bullet, st);
                if (focus) x.c.set_cursor(fx + 1 + shown, y);
            }
        } else {
            input_strip(x, field, f.value, f.caret, focus,
                        f.required ? nullptr : (focus ? nullptr : "optional"));
        }
        zone(x, Rect{in.x - 2, y, lw + 2 + field_w, 1}, KeyEvent::pick(i));
        y += step;
    }
    // Message (validation) or the actions, along the bottom.
    const int my = in.bottom() - 1;
    if (!m.message.empty()) {
        const Style ms = m.message_kind == MessageKind::Error ? x.t.err : x.t.warn;
        x.c.glyph(in.x, my, m.message_kind == MessageKind::Error ? x.g.fail : x.g.warn, ms);
        x.c.text(in.x + 2, my, m.message, ms, in.w - 2);
    } else {
        if (m.form_revealed && m.form_reveal_remaining_ms > 0) {
            const std::string t = "shown, hides in " + seconds_text(m.form_reveal_remaining_ms);
            x.c.text(in.x, my, t, x.t.subtle, in.w / 2);
        }
        const int sw = button_width(x, "ctrl+s", "Save");
        const int cw = button_width(x, "esc", "Cancel");
        int px = in.right() - sw - cw - 2;
        px += button(x, px, my, "esc", "Cancel", 0, keyev(C::Esc)) + 2;
        button(x, px, my, "ctrl+s", "Save", 1, ctrl(U's'));
    }
}

// ---------------------------------------------------------------------------
// Lock screen (Locked / Unlocking)
// ---------------------------------------------------------------------------
std::string spaced(const char* s) {
    std::string out;
    for (const char* p = s; *p; ++p) {
        if (!out.empty()) out += ' ';
        out += *p;
    }
    return out;
}

void lock_screen(Ctx& x, const RenderModel& m) {
    const int cols = x.c.cols(), rows = x.c.rows();
    const bool busy = m.state == TuiState::Unlocking;
    const int bw = clampi(cols - 8, 30, 52);
    const int bx = centered_x(x, bw);
    const bool boxed = rows >= 16;  // three-row input box
    const int block = (boxed ? 13 : 10) + (m.create_mode ? 3 : 0);
    int y = clampi((rows - block) / 2, 1, rows);

    const std::string word = spaced("SECRAXIS");
    const std::string mark = utf8(x.g.brand) + "   ";
    const int ww = width_of(x.c, mark) + width_of(x.c, word);
    int px = centered_x(x, ww);
    px += x.c.text(px, y, mark, x.t.accent_bold, ww);
    x.c.text(px, y, word, x.t.strong, ww);
    y += 1;
    center_text(x, y, "vault manager", x.t.subtle);
    y += 3;

    const char* heading = busy ? (m.create_mode ? "Creating" : "Unlocking")
                               : (m.create_mode ? "New vault" : "Unlock");
    const int hw = width_of(x.c, heading) + 2 + width_of(x.c, m.vault_name);
    const int hx = centered_x(x, hw < bw ? hw : bw);
    px = hx + x.c.text(hx, y, heading, x.t.muted, bw);
    x.c.text(px + 2, y, m.vault_name, x.t.strong, bw - (px + 2 - hx));
    y += 2;

    if (busy) {
        char el[32];
        std::snprintf(el, sizeof(el), "%llu.%llus",
                      static_cast<unsigned long long>(m.busy_elapsed_ms / 1000),
                      static_cast<unsigned long long>((m.busy_elapsed_ms % 1000) / 100));
        const std::string line = "Deriving the key with Argon2id";
        if (x.g.spinner != nullptr) {
            const int frame_i =
                static_cast<int>((m.now_ms / 80) % static_cast<uint64_t>(x.g.spinner_len));
            const int lw = 2 + width_of(x.c, line) + 2 + width_of(x.c, el);
            px = centered_x(x, lw);
            x.c.glyph(px, y, x.g.spinner[frame_i], x.t.accent_bold);
            px += 2;
            px += x.c.text(px, y, line, x.t.text, bw);
            x.c.text(px + 2, y, el, x.t.subtle, 12);
        } else {
            center_text(x, y, line, x.t.text);
            const int seg = bw / 5 > 3 ? bw / 5 : 3;
            const int span = bw + seg;
            const int pos =
                static_cast<int>((m.now_ms / 40) % static_cast<uint64_t>(span)) - seg;
            x.c.hline(bx, y + 2, bw, x.g.bar_empty, x.t.bar_empty);
            for (int k = 0; k < seg; ++k)
                if (pos + k >= 0 && pos + k < bw)
                    x.c.glyph(bx + pos + k, y + 2, x.g.bar_full, x.t.bar_full);
            center_text(x, y + 3, el, x.t.subtle);
        }
        center_text(x, y + (x.g.spinner != nullptr ? 2 : 5),
                    "memory-hard on purpose: this is what slows down guessing", x.t.subtle);
        return;
    }

    std::string label = !m.create_mode ? "Master password"
                        : m.confirm_stage ? "Type it again to confirm"
                                          : "Choose a master password";
    if (m.create_mode) {
        label += "   ";
        label += utf8(x.g.dot_on);
        label += " ";
        label += utf8(m.confirm_stage ? x.g.dot_on : x.g.dot_off);
    }
    x.c.text(bx + 1, y, label, x.t.muted, bw);
    ++y;
    if (boxed) {
        x.c.box(Rect{bx, y, bw, 3}, x.t.accent);
        x.c.glyph(bx + 2, y + 1, x.g.prompt, x.t.accent_bold);
        const int inner = bw - 7;
        const int n = static_cast<int>(m.pw_chars);
        const int shown = n < inner ? n : inner;
        x.c.hline(bx + 4, y + 1, shown, x.g.bullet, x.t.text);
        x.c.set_cursor(bx + 4 + shown, y + 1);
        y += 4;
    } else {
        const Style st = x.t.input_focus;
        x.c.fill(Rect{bx, y, bw, 1}, st);
        const int n = static_cast<int>(m.pw_chars);
        const int shown = n < bw - 3 ? n : bw - 3;
        x.c.hline(bx + 1, y, shown, x.g.bullet, st);
        x.c.set_cursor(bx + 1 + shown, y);
        y += 2;
    }

    auto note = [&](char32_t glyph_cp, Style st, std::string_view text) {
        for (const Span& sp : wrap(text, bw - 3, x.c.width_policy())) {
            if (y >= rows - 2) return;
            const int tx = glyph_cp != 0 || st.fg != x.t.muted.fg ? bx + 3 : bx + 1;
            if (glyph_cp != 0) x.c.glyph(bx + 1, y, glyph_cp, st);
            x.c.text(tx, y++, slice(text, sp), st, bw - 3);
            glyph_cp = 0;
        }
    };
    if (!m.message.empty()) {
        const bool error = m.message_kind == MessageKind::Error;
        const bool warn = m.message_kind == MessageKind::Warning;
        note(error ? x.g.fail : (warn ? x.g.warn : x.g.note),
             error ? x.t.err : (warn ? x.t.warn : x.t.accent), m.message);
    } else if (m.caps_lock) {
        note(x.g.warn, x.t.warn, "Caps Lock is on");
    } else if (m.create_mode) {
        note(0, x.t.muted,
             "Use a long passphrase you will remember. It cannot be recovered if lost.");
    }
    if (m.create_mode && !m.create_kdf_label.empty() && y + 1 < rows - 2)
        x.c.text(bx + 1, y + 1, m.create_kdf_label, x.t.subtle, bw - 2);
}

void too_small(Ctx& x) {
    const int rows = x.c.rows();
    char b[64];
    std::snprintf(b, sizeof(b), "needs %dx%d, now %dx%d", MIN_COLS, MIN_ROWS, x.c.cols(),
                  x.c.rows());
    center_text(x, rows / 2 - 1, "Window too small", x.t.strong);
    center_text(x, rows / 2, b, x.t.muted);
}

}  // namespace

RenderResult render(const RenderModel& m, const RenderEnv& env, int cols, int rows,
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
        too_small(x);
        return res;
    }

    const bool locked =
        m.state == TuiState::Locked || m.state == TuiState::Unlocking || !m.vault_open;
    const bool wide = !locked && cols >= 100 && rows >= 16;
    const int toast_y = rows - 2;
    const int footer_y = rows - 1;
    if (locked) {
        lock_screen(x, m);
        footer(x, footer_y, hints_for(m, g, false), "", t.muted);
        return res;
    }
    header(x, m, wide);

    // Overview family. Vertical rhythm: header, gap, search, gap, list.
    const int margin = cols >= 70 ? 2 : 1;
    const bool airy = rows >= 20;
    const int top = airy ? 2 : 1;
    Rect area{margin, top, cols - 2 * margin, toast_y - top - (airy ? 1 : 0)};
    Rect list = area;
    if (wide) {
        const int dw = clampi(cols * 38 / 100, 40, 64);
        list.w = area.w - dw - 3;
        x.c.vline(list.right() + 1, area.y, area.h, g.v, t.border);
        details_pane(x, m, Rect{list.right() + 3, area.y, dw, area.h});
    }
    search_bar(x, m, Rect{list.x, list.y, list.w, 1});
    const int gap = airy ? 1 : 0;
    res.list_rows = entry_list(x, m, Rect{list.x, list.y + 1 + gap, list.w, list.h - 1 - gap});

    toast(x, toast_y, 2, m.message, m.message_kind);

    // Modals sit on a faded copy of the screen and take over the pointer.
    const bool sheet = m.details_open && !wide;
    const bool is_modal = m.state == TuiState::DeleteConfirm ||
                          m.state == TuiState::SaveConflict || m.state == TuiState::AddEntry ||
                          m.state == TuiState::EditEntry || m.state == TuiState::Help ||
                          m.state == TuiState::CloseConfirm || m.state == TuiState::Settings ||
                          (m.state == TuiState::RevealSecret && !wide) || sheet;
    if (is_modal) {
        x.c.fade(t.scrim);
        modal(x);
    }
    switch (m.state) {
        case TuiState::RevealSecret:
            if (!wide) {
                if (sheet) details_sheet(x, m);
                else reveal_dialog(x, m);
            }
            break;
        case TuiState::DeleteConfirm: delete_dialog(x, m); break;
        case TuiState::SaveConflict: conflict_dialog(x, m); break;
        case TuiState::CloseConfirm: close_dialog(x); break;
        case TuiState::Settings: settings_dialog(x, m); break;
        case TuiState::AddEntry:
        case TuiState::EditEntry: form_dialog(x, m); break;
        case TuiState::Help: help_dialog(x, m); break;
        default:
            if (sheet) details_sheet(x, m);
            break;
    }
    std::string right;
    if (m.clip_remaining_ms > 0) right = "clipboard clears in " + seconds_text(m.clip_remaining_ms);
    footer(x, footer_y, hints_for(m, g, wide), right, t.warn);
    return res;
}

}  // namespace secraxis
