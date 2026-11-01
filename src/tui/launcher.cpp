#include "secraxis/launcher.h"

#include "secraxis/tui_text.h"

namespace secraxis {

namespace {

// ASCII, one line each: at most LAUNCHER_TIP_MAX cells (test_launcher checks).
const char* const kTips[] = {
    "Press / in a vault to search; passwords are never searched.",
    "Shown passwords hide again after 10 seconds.",
    "Copied passwords are cleared from the clipboard after 20 s.",
    "Ctrl+R in the entry form shows the password you are typing.",
    "Esc always steps back one level.",
    "Click a row to select it; double-click opens it.",
    "secraxis backup <vault> <copy.seis> makes an encrypted copy.",
    "secraxis upgrade <vault> --kdf strong raises the KDF cost.",
    "Nothing leaves this machine: no cloud, no telemetry.",
    "An idle vault locks itself after 5 minutes.",
};
constexpr size_t kNumTips = sizeof(kTips) / sizeof(kTips[0]);

bool is_sep(char c, bool win) { return c == '/' || (win && c == '\\'); }

bool is_drive_root(const std::string& d) {
    return d.size() == 3 && d[1] == ':' && (d[2] == '\\' || d[2] == '/');
}

bool absolute(const std::string& p, bool win) {
    if (win) return (p.size() >= 2 && p[1] == ':') || (p.size() >= 2 && is_sep(p[0], true) && is_sep(p[1], true));
    return !p.empty() && p[0] == '/';
}

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool ends_with_seis(const std::string& n) {
    return n.size() >= 5 && lower(n.substr(n.size() - 5)) == ".seis";
}

bool is_ctrl(const KeyEvent& k, char32_t c) {
    return k.code == KeyEvent::Code::Char && (k.mods & KEYMOD_CTRL) && k.cp == c;
}

// Text editing shared by the filter and the form fields.
bool edit_line(LineEdit& e, const KeyEvent& k) {
    using C = KeyEvent::Code;
    switch (k.code) {
        case C::Char:
            if (k.mods & KEYMOD_CTRL) {
                if (k.cp == U'u') e.clear();
                else if (k.cp == U'a') e.home();
                else if (k.cp == U'e') e.end();
                else return false;
                return true;
            }
            e.insert(k.cp);
            return true;
        case C::Backspace: e.backspace(); return true;
        case C::Del: e.del(); return true;
        case C::Left: e.left(); return true;
        case C::Right: e.right(); return true;
        case C::Home: e.home(); return true;
        case C::End: e.end(); return true;
        default: return false;
    }
}

// Why `n` (ending in .seis) cannot be the vault's file name, or nullptr: it
// must be text the TUI draws as is (no controls or bidi overrides, which the
// history would refuse too), without the characters Windows forbids, not end
// in a dot or space, and not be a Windows device name ("con.seis" names the
// console device, not a file).
const char* file_name_problem(const std::string& n) {
    if (n.size() <= 5) return "Give the vault a name.";
    if (n.size() > 200) return "That name is too long.";
    size_t i = 0;
    while (i < n.size()) {
        char32_t cp = 0;
        if (!utf8_decode(n.data(), n.size(), &i, &cp) || !is_text_cp(cp))
            return "A file name cannot contain control or text-direction characters.";
        if (cp < 0x80 && std::string("/\\:*?\"<>|").find(static_cast<char>(cp)) != std::string::npos)
            return "A file name cannot contain / \\ : * ? \" < > |";
    }
    if (n.back() == '.' || n.back() == ' ') return "A file name cannot end with a dot or a space.";
    std::string stem = n.substr(0, n.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    for (char& c : stem)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    const bool numbered = stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 ||
                                               stem.compare(0, 3, "LPT") == 0) &&
                          stem[3] >= '0' && stem[3] <= '9';
    if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || numbered)
        return "CON, PRN, AUX, NUL, COM0-9 and LPT0-9 are reserved names on Windows.";
    return nullptr;
}

}  // namespace

std::string Launcher::parent_of(const std::string& dir, bool win) {
    if (win) {
        if (dir.empty() || is_drive_root(dir)) return "";  // the drives
        std::string d = dir;
        while (d.size() > 3 && is_sep(d.back(), true)) d.pop_back();
        const size_t s = d.find_last_of("\\/");
        if (s == std::string::npos) return "";
        if (s <= 2 && d.size() >= 2 && d[1] == ':') return d.substr(0, 2) + "\\";
        return d.substr(0, s);
    }
    if (dir.empty() || dir == "/") return "/";
    std::string d = dir;
    while (d.size() > 1 && d.back() == '/') d.pop_back();
    const size_t s = d.find_last_of('/');
    if (s == std::string::npos || s == 0) return "/";
    return d.substr(0, s);
}

std::string Launcher::join(const std::string& dir, const std::string& name, bool win) {
    if (dir.empty()) return name;
    if (is_sep(dir.back(), win)) return dir + name;
    return dir + (win ? "\\" : "/") + name;
}

Launcher::Launcher(std::vector<RecentVault> recent, LauncherConfig cfg)
    : cfg_(static_cast<LauncherConfig&&>(cfg)),
      recent_(static_cast<std::vector<RecentVault>&&>(recent)) {
    const std::string start = cfg_.start_dir.empty() ? cfg_.home_dir : cfg_.start_dir;
    new_folder_.set(ByteView(start.data(), start.size()));
    if (cfg_.startup_note != nullptr) {
        msg_ = cfg_.startup_note;  // until the first key
        msg_kind_ = MessageKind::Info;
    }
}

void Launcher::say(MessageKind kind, const char* text) {
    msg_ = text;
    msg_kind_ = kind;
    msg_deadline_ = (kind == MessageKind::Success || kind == MessageKind::Info)
                        ? now_ + cfg_.message_ttl_ms
                        : 0;
}

void Launcher::request(LauncherRequest::Kind kind, std::string path) {
    pending_ = LauncherRequest();
    pending_.kind = kind;
    pending_.path = static_cast<std::string&&>(path);
    pending_.kdf = new_kdf_;
}

LauncherRequest Launcher::take_request() {
    LauncherRequest r = static_cast<LauncherRequest&&>(pending_);
    pending_ = LauncherRequest();
    return r;
}

void Launcher::set_recent(std::vector<RecentVault> recent) {
    recent_ = static_cast<std::vector<RecentVault>&&>(recent);
    if (recent_sel_ >= recent_.size()) recent_sel_ = recent_.empty() ? 0 : recent_.size() - 1;
}

void Launcher::set_page_rows(size_t n) { page_ = n == 0 ? 1 : n; }

void Launcher::on_tick(uint64_t now) {
    now_ = now;
    if (msg_deadline_ != 0 && now >= msg_deadline_) {
        msg_.clear();
        msg_kind_ = MessageKind::None;
        msg_deadline_ = 0;
    }
}

// List movement shared by the recent list and the browser.
void Launcher::move(const KeyEvent& k, size_t count, size_t* sel, size_t* top) {
    using C = KeyEvent::Code;
    if (count == 0) {
        *sel = 0;
        *top = 0;
        return;
    }
    const bool up = k.code == C::Up || (k.code == C::Char && !(k.mods & KEYMOD_CTRL) && k.cp == U'k');
    const bool down = k.code == C::Down || (k.code == C::Char && !(k.mods & KEYMOD_CTRL) && k.cp == U'j');
    if (k.code == C::Pick) {
        if (k.arg >= 0 && static_cast<size_t>(k.arg) < count) *sel = static_cast<size_t>(k.arg);
    } else if (up) {
        if (*sel > 0) --*sel;
    } else if (down) {
        if (*sel + 1 < count) ++*sel;
    } else if (k.code == C::PageUp) {
        *sel = *sel > page_ ? *sel - page_ : 0;
    } else if (k.code == C::PageDown) {
        *sel = *sel + page_ < count ? *sel + page_ : count - 1;
    } else if (k.code == C::Home) {
        *sel = 0;
    } else if (k.code == C::End) {
        *sel = count - 1;
    }
    if (*sel >= count) *sel = count - 1;
    if (*sel < *top) *top = *sel;
    if (*sel >= *top + page_) *top = *sel + 1 - page_;
    if (*top + page_ > count) *top = count > page_ ? count - page_ : 0;
}

void Launcher::on_key(const KeyEvent& k, uint64_t now) {
    now_ = now;
    if (k.code == KeyEvent::Code::Mouse) return;
    msg_.clear();
    msg_kind_ = MessageKind::None;
    msg_deadline_ = 0;
    switch (screen_) {
        case LauncherScreen::Home: key_home(k); break;
        case LauncherScreen::Browse: key_browse(k); break;
        case LauncherScreen::NewVault: key_new(k); break;
        case LauncherScreen::Help: screen_ = help_return_; break;
    }
}

void Launcher::key_home(const KeyEvent& k) {
    using C = KeyEvent::Code;
    if (k.mods & KEYMOD_PASTE) return;  // pasted text never commands
    if (is_ctrl(k, U'v')) {
        say(MessageKind::Info, "Paste into a field: o to open a vault by path, n for a new one.");
        return;
    }
    const bool nav = k.code == C::Up || k.code == C::Down || k.code == C::PageUp ||
                     k.code == C::PageDown || k.code == C::Home || k.code == C::End ||
                     k.code == C::Pick ||
                     (k.code == C::Char && !(k.mods & KEYMOD_CTRL) && (k.cp == U'j' || k.cp == U'k'));
    if (nav) {
        move(k, recent_.size(), &recent_sel_, &recent_top_);
        return;
    }
    if (k.code == C::Esc) {
        request(LauncherRequest::Kind::Quit, "");
        return;
    }
    if (k.code == C::Enter) {
        if (recent_.empty()) {
            open_browser(cfg_.start_dir, false);
        } else if (recent_[recent_sel_].missing) {
            say(MessageKind::Warning, "That file is no longer there. Press x to forget it.");
        } else {
            request(LauncherRequest::Kind::Open, recent_[recent_sel_].path);
        }
        return;
    }
    if (k.code == C::Del) {
        if (!recent_.empty()) {
            request(LauncherRequest::Kind::Forget, recent_[recent_sel_].path);
            recent_.erase(recent_.begin() + static_cast<long>(recent_sel_));
            if (recent_sel_ >= recent_.size() && recent_sel_ > 0) --recent_sel_;
            say(MessageKind::Info, "Removed from the list. The file itself was not touched.");
        }
        return;
    }
    if (k.code != C::Char || (k.mods & KEYMOD_CTRL)) return;
    switch (k.cp) {
        case U'o': {
            // Start where the selected vault lives, else the default folder.
            std::string d = cfg_.start_dir;
            if (!recent_.empty()) d = parent_of(recent_[recent_sel_].path, cfg_.windows_paths);
            open_browser(d, false);
            return;
        }
        case U'n':
            screen_ = LauncherScreen::NewVault;
            new_cursor_ = 0;
            return;
        case U'x':
            on_key(KeyEvent::key(C::Del), now_);
            return;
        case U'?':
            help_return_ = LauncherScreen::Home;
            screen_ = LauncherScreen::Help;
            return;
        case U'q':
            request(LauncherRequest::Kind::Quit, "");
            return;
        default:
            return;
    }
}

void Launcher::open_browser(const std::string& dir, bool pick_folder) {
    pick_folder_ = pick_folder;
    screen_ = LauncherScreen::Browse;
    filter_.clear();
    sel_ = 0;
    top_ = 0;
    rebuild_rows();  // if the listing fails, the last folder shows unfiltered
    go(dir.empty() && !cfg_.windows_paths ? std::string("/") : dir);
}

void Launcher::go(const std::string& dir) { request(LauncherRequest::Kind::List, dir); }

void Launcher::on_listing(const std::string& dir, std::vector<DirEntry> entries, bool ok) {
    if (!ok) {
        say(MessageKind::Error, "That folder cannot be opened.");
        if (!listed_) {  // nothing to show yet: fall back to the start folder
            const std::string fallback = cfg_.windows_paths ? std::string() : std::string("/");
            if (dir != fallback) go(fallback);
        }
        return;
    }
    dir_ = dir;
    listed_ = true;
    all_.clear();
    for (DirEntry& e : entries)
        if (e.dir || (!pick_folder_ && e.vault)) all_.push_back(static_cast<DirEntry&&>(e));
    filter_.clear();
    sel_ = 0;
    top_ = 0;
    rebuild_rows();
    if (!reselect_.empty()) {
        for (size_t k = 0; k < view_.size(); ++k)
            if (view_[k].name == reselect_) sel_ = k;
        reselect_.clear();
    } else if (!pick_folder_) {
        // Land on the first vault when there is one.
        for (size_t k = 0; k < view_.size(); ++k)
            if (view_[k].kind == BrowseRow::Kind::Vault) {
                sel_ = k;
                break;
            }
    }
    KeyEvent none = KeyEvent::key(KeyEvent::Code::Char);
    none.cp = 0;
    move(none, view_.size(), &sel_, &top_);
}

bool Launcher::at_root() const {
    return cfg_.windows_paths ? dir_.empty() : (dir_ == "/" || dir_.empty());
}

void Launcher::rebuild_rows() {
    view_.clear();
    const std::string f = lower(filter_.text());
    if (f.empty()) {
        if (pick_folder_ && !dir_.empty()) {
            BrowseRow r;
            r.kind = BrowseRow::Kind::UseFolder;
            r.name = "Use this folder";
            view_.push_back(r);
        }
        if (!at_root()) {
            BrowseRow r;
            r.kind = BrowseRow::Kind::Parent;
            r.name = "..";
            view_.push_back(r);
        }
    }
    for (const DirEntry& e : all_) {
        if (!f.empty() && lower(e.name).find(f) == std::string::npos) continue;
        BrowseRow r;
        r.kind = e.dir ? BrowseRow::Kind::Dir : BrowseRow::Kind::Vault;
        r.name = e.name;
        view_.push_back(r);
    }
    for (size_t k = 0; k < view_.size(); ++k) view_[k].index = k;
    if (sel_ >= view_.size()) sel_ = view_.empty() ? 0 : view_.size() - 1;
}

std::string Launcher::typed_path() const {
    const std::string& t = filter_.text();
    if (t.empty()) return "";
    const bool win = cfg_.windows_paths;
    std::string p;
    if (t[0] == '~' && (t.size() == 1 || is_sep(t[1], win))) {
        p = cfg_.home_dir + t.substr(1);
    } else if (absolute(t, win)) {
        p = t;
    } else if (t.find('/') != std::string::npos || (win && t.find('\\') != std::string::npos)) {
        p = join(dir_, t, win);
    } else {
        return "";
    }
    return p;
}

void Launcher::activate_row() {
    if (view_.empty()) return;
    const BrowseRow& r = view_[sel_];
    const bool win = cfg_.windows_paths;
    switch (r.kind) {
        case BrowseRow::Kind::Parent:
            reselect_.clear();
            if (!dir_.empty()) {
                const size_t s = dir_.find_last_of(win ? "\\/" : "/");
                std::string child = s == std::string::npos ? dir_ : dir_.substr(s + 1);
                if (win && is_drive_root(dir_)) child = dir_;
                reselect_ = child;
            }
            go(parent_of(dir_, win));
            return;
        case BrowseRow::Kind::UseFolder:
            new_folder_.set(ByteView(dir_.data(), dir_.size()));
            screen_ = LauncherScreen::NewVault;
            new_cursor_ = 0;
            return;
        case BrowseRow::Kind::Dir:
            go(join(dir_, r.name, win));
            return;
        case BrowseRow::Kind::Vault:
            request(LauncherRequest::Kind::Open, join(dir_, r.name, win));
            return;
    }
}

void Launcher::key_browse(const KeyEvent& k) {
    using C = KeyEvent::Code;
    switch (k.code) {
        case C::Esc:
            if (!filter_.empty()) {
                filter_.clear();
                rebuild_rows();
                return;
            }
            screen_ = pick_folder_ ? LauncherScreen::NewVault : LauncherScreen::Home;
            return;
        case C::Up:
        case C::Down:
        case C::PageUp:
        case C::PageDown:
        case C::Pick:
            move(k, view_.size(), &sel_, &top_);
            return;
        case C::Home:
        case C::End:
            if (filter_.empty()) move(k, view_.size(), &sel_, &top_);
            else edit_line(filter_, k);
            return;
        case C::Left:
            if (filter_.empty() && !at_root()) {
                sel_ = 0;
                for (size_t q = 0; q < view_.size(); ++q)
                    if (view_[q].kind == BrowseRow::Kind::Parent) sel_ = q;
                activate_row();
            } else {
                edit_line(filter_, k);
            }
            return;
        case C::Right:
            if (filter_.empty() && !view_.empty() && view_[sel_].kind == BrowseRow::Kind::Dir)
                activate_row();
            else
                edit_line(filter_, k);
            return;
        case C::Backspace:
            if (filter_.empty()) {
                if (!at_root()) {
                    for (size_t q = 0; q < view_.size(); ++q)
                        if (view_[q].kind == BrowseRow::Kind::Parent) sel_ = q;
                    activate_row();
                }
                return;
            }
            edit_line(filter_, k);
            sel_ = 0;
            top_ = 0;
            rebuild_rows();
            return;
        case C::Enter: {
            const std::string p = typed_path();
            if (!p.empty()) {
                if (ends_with_seis(p) && !pick_folder_) request(LauncherRequest::Kind::Open, p);
                else go(p);
                return;
            }
            activate_row();
            return;
        }
        default: {
            if (k.mods & KEYMOD_PASTE && (k.cp == U'\r' || k.cp == U'\n')) return;
            if (is_ctrl(k, U'v')) {
                paste_clipboard();
                return;
            }
            const std::string before = filter_.text();
            edit_line(filter_, k);
            if (filter_.text() != before) {
                sel_ = 0;
                top_ = 0;
                rebuild_rows();
                // Prefer the first match over the ".." row.
                for (size_t q = 0; q < view_.size(); ++q)
                    if (view_[q].kind == BrowseRow::Kind::Dir || view_[q].kind == BrowseRow::Kind::Vault) {
                        sel_ = q;
                        break;
                    }
            }
            return;
        }
    }
}

void Launcher::submit_new() {
    std::string name = new_name_.text();
    while (!name.empty() && name.back() == ' ') name.pop_back();
    if (name.empty()) {
        new_cursor_ = 0;
        say(MessageKind::Error, "Give the vault a name.");
        return;
    }
    if (!ends_with_seis(name)) name += ".seis";
    if (const char* why = file_name_problem(name)) {
        new_cursor_ = 0;
        say(MessageKind::Error, why);
        return;
    }
    if (new_folder_.empty()) {
        new_cursor_ = 1;
        say(MessageKind::Error, "Choose a folder for the vault.");
        return;
    }
    request(LauncherRequest::Kind::Create, join(new_folder_.text(), name, cfg_.windows_paths));
}

void Launcher::key_new(const KeyEvent& k) {
    using C = KeyEvent::Code;
    constexpr size_t kFields = 4;
    if (k.code == C::Pick) {
        if (k.arg >= LAUNCHER_PICK_PROFILE && k.arg < LAUNCHER_PICK_PROFILE + 3) {
            new_cursor_ = 2;
            new_kdf_ = static_cast<KdfProfileId>(k.arg - LAUNCHER_PICK_PROFILE + 1);
        } else if (k.arg >= LAUNCHER_PICK_FIELD && k.arg < LAUNCHER_PICK_FIELD + static_cast<int32_t>(kFields)) {
            new_cursor_ = static_cast<size_t>(k.arg - LAUNCHER_PICK_FIELD);
        }
        return;
    }
    switch (k.code) {
        case C::Esc:
            screen_ = LauncherScreen::Home;
            return;
        case C::Tab:
        case C::Down:
            new_cursor_ = (new_cursor_ + 1) % kFields;
            return;
        case C::BackTab:
        case C::Up:
            new_cursor_ = (new_cursor_ + kFields - 1) % kFields;
            return;
        case C::Enter:
            if (new_cursor_ + 1 < kFields) {
                ++new_cursor_;
                return;
            }
            submit_new();
            return;
        default:
            break;
    }
    if (is_ctrl(k, U's')) {
        submit_new();
        return;
    }
    if (is_ctrl(k, U'o') || (new_cursor_ == 1 && is_ctrl(k, U'b'))) {
        const std::string f = new_folder_.text();
        open_browser(f.empty() ? cfg_.start_dir : f, true);
        return;
    }
    if (is_ctrl(k, U'v')) {
        if (new_cursor_ <= 1) paste_clipboard();
        return;
    }
    if (new_cursor_ >= 2 && (k.mods & KEYMOD_PASTE)) return;  // pasted text never commands
    if (new_cursor_ == 2) {
        // Floor (1) - Default (2) - Strong (3).
        uint32_t v = static_cast<uint32_t>(new_kdf_);
        if (k.code == C::Left && v > 1) --v;
        if (k.code == C::Right && v < 3) ++v;
        if (k.code == C::Char && k.cp == U' ') v = v % 3 + 1;
        new_kdf_ = static_cast<KdfProfileId>(v);
        return;
    }
    if (new_cursor_ == 0) edit_line(new_name_, k);
    else if (new_cursor_ == 1) edit_line(new_folder_, k);
    else if (k.code == C::Char && k.cp == U' ') submit_new();
}

// Ctrl+V: the clipboard's text arrives as a terminal paste would (see
// TuiMachine::paste_clipboard).
void Launcher::paste_clipboard() {
    if (cfg_.clipboard == nullptr) {
        say(MessageKind::Warning, "Clipboard unavailable.");
        return;
    }
    SecureBuffer text;
    switch (cfg_.clipboard->read_text(&text)) {
        case PasteStatus::Ok:
            break;
        case PasteStatus::Empty:
            say(MessageKind::Info, "The clipboard has no text.");
            return;
        case PasteStatus::TooLong:
            say(MessageKind::Warning, "The clipboard text is too long to paste.");
            return;
        case PasteStatus::Unavailable:
            say(MessageKind::Info, cfg_.clipboard->paste_hint());
            return;
    }
    for_each_pasted(
        text.view(),
        [](void* ctx, char32_t cp) {
            Launcher* l = static_cast<Launcher*>(ctx);
            l->on_key(KeyEvent::chr(cp, KEYMOD_PASTE), l->now_);
        },
        this);
}

const LauncherModel& Launcher::model() {
    LauncherModel& m = model_;
    m.screen = screen_;
    m.now_ms = now_;
    m.wall_now_s = wall_s_;
    m.recent = recent_;
    m.recent_sel = recent_sel_;
    m.dir = dir_;
    m.windows_paths = cfg_.windows_paths;
    m.pick_folder = pick_folder_;
    m.rows.clear();
    m.rows_total = view_.size();
    m.rows_top = top_;
    m.row_sel = sel_;
    const size_t end = top_ + page_ < view_.size() ? top_ + page_ : view_.size();
    for (size_t k = top_; k < end; ++k) {
        BrowseRow r = view_[k];
        r.selected = (k == sel_);
        m.rows.push_back(r);
    }
    m.filter = filter_.text();
    m.filter_caret = filter_.caret();
    m.new_name = new_name_.text();
    m.new_name_caret = new_name_.caret();
    m.new_folder = new_folder_.text();
    m.new_folder_caret = new_folder_.caret();
    m.new_kdf = new_kdf_;
    m.new_cursor = new_cursor_;
    {
        std::string name = new_name_.text();
        if (!name.empty() && !ends_with_seis(name)) name += ".seis";
        m.new_path = name.empty() ? std::string() : join(new_folder_.text(), name, cfg_.windows_paths);
    }
    m.message = msg_;
    m.message_kind = msg_kind_;
    m.version = cfg_.version;
    m.tip = kTips[cfg_.tip_seed % kNumTips];
    m.history_file = cfg_.history_file;
    m.history_enabled = cfg_.history_enabled;
    return m;
}

}  // namespace secraxis
