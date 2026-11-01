#include "secraxis/tui_core.h"

#include <cstring>

#include "secraxis/crypto.h"
#include "secraxis/fs_atomic.h"
#include "secraxis/tui_text.h"

namespace secraxis {

// ---------------------------------------------------------------------------
// SecretLineEdit
// ---------------------------------------------------------------------------
bool SecretLineEdit::append(char32_t cp) {
    if (ascii_only_ ? (cp < 0x20 || cp > 0x7E) : !is_text_cp(cp)) return false;
    char b[4];
    const size_t n = utf8_encode(cp, b);
    if (len_ + n > MAX_LEN) {
        secure_wipe(b, sizeof(b));
        return false;
    }
    if (!buf_.valid()) {
        buf_ = SecureBuffer::alloc(MAX_LEN);
        if (!buf_.valid()) {
            secure_wipe(b, sizeof(b));
            return false;
        }
    }
    std::memcpy(buf_.data() + len_, b, n);
    secure_wipe(b, sizeof(b));
    len_ += n;
    ++chars_;
    return true;
}

void SecretLineEdit::backspace() {
    if (len_ == 0 || !buf_.valid()) return;
    size_t p = len_ - 1;
    while (p > 0 && (buf_.data()[p] & 0xC0) == 0x80) --p;  // whole code point
    secure_wipe(buf_.data() + p, len_ - p);
    len_ = p;
    --chars_;
}

void SecretLineEdit::clear() {
    buf_.reset();
    len_ = 0;
    chars_ = 0;
}

ByteView SecretLineEdit::view() const noexcept {
    if (!buf_.valid() || len_ == 0) return ByteView();
    return ByteView(buf_.data(), len_);
}

SecureBuffer SecretLineEdit::take() {
    SecureBuffer out = SecureBuffer::alloc(len_);
    // No secure memory left: the text stays here, and the caller (which sees
    // an invalid buffer while length() > 0) fails rather than go on with an
    // empty password.
    if (len_ > 0 && !out.valid()) return out;
    if (len_ > 0) std::memcpy(out.data(), buf_.data(), len_);
    clear();
    return out;
}

// ---------------------------------------------------------------------------
// LineEdit
// ---------------------------------------------------------------------------
size_t LineEdit::next_unit(size_t pos) const {
    if (pos >= s_.size()) return s_.size();
    size_t i = pos;
    char32_t cp = 0;
    utf8_decode(s_.data(), s_.size(), &i, &cp);  // ill-formed: one subpart
    return i;
}

size_t LineEdit::prev_unit(size_t pos) const {
    if (pos == 0) return 0;
    // Step back over up to three continuation bytes, then confirm that one
    // decode step from there lands exactly on pos; otherwise the previous
    // unit is a single stray byte.
    size_t p = pos - 1;
    for (int k = 0; k < 3 && p > 0 && (static_cast<uint8_t>(s_[p]) & 0xC0) == 0x80; ++k)
        --p;
    return next_unit(p) == pos ? p : pos - 1;
}

bool LineEdit::insert(char32_t cp) {
    if (!is_text_cp(cp)) return false;
    char b[4];
    const size_t n = utf8_encode(cp, b);
    if (s_.size() + n > max_) return false;
    if (s_.capacity() < max_) s_.reserve(max_);
    s_.insert(caret_, b, n);
    caret_ += n;
    return true;
}

void LineEdit::backspace() {
    if (caret_ == 0) return;
    const size_t p = prev_unit(caret_);
    s_.erase(p, caret_ - p);
    caret_ = p;
}

void LineEdit::del() {
    if (caret_ >= s_.size()) return;
    s_.erase(caret_, next_unit(caret_) - caret_);
}

void LineEdit::left() {
    size_t p = prev_unit(caret_);
    // Never park the caret between a base character and its marks.
    while (p > 0) {
        size_t i = p;
        char32_t cp = 0;
        if (!utf8_decode(s_.data(), s_.size(), &i, &cp)) break;
        if (classify_cp(cp) != CpClass::Zero) break;
        p = prev_unit(p);
    }
    caret_ = p;
}

void LineEdit::right() {
    size_t p = next_unit(caret_);
    while (p < s_.size()) {
        size_t i = p;
        char32_t cp = 0;
        if (!utf8_decode(s_.data(), s_.size(), &i, &cp)) break;
        if (classify_cp(cp) != CpClass::Zero) break;
        p = i;
    }
    caret_ = p;
}

void LineEdit::clear() {
    if (!s_.empty()) secure_wipe(&s_[0], s_.size());
    s_.clear();
    caret_ = 0;
}

void LineEdit::set(ByteView b) {
    clear();
    size_t n = b.len > max_ ? max_ : b.len;
    while (n < b.len && n > 0 && (b.ptr[n] & 0xC0) == 0x80) --n;  // never split a character
    s_.reserve(max_);
    s_.assign(reinterpret_cast<const char*>(b.ptr), n);
    caret_ = s_.size();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const char* tui_state_name(TuiState s) noexcept {
    switch (s) {
        case TuiState::Locked: return "Locked";
        case TuiState::Unlocking: return "Unlocking";
        case TuiState::Overview: return "Overview";
        case TuiState::Query: return "Query";
        case TuiState::AddEntry: return "AddEntry";
        case TuiState::EditEntry: return "EditEntry";
        case TuiState::DeleteConfirm: return "DeleteConfirm";
        case TuiState::RevealSecret: return "RevealSecret";
        case TuiState::CopySecret: return "CopySecret";
        case TuiState::ExportEntry: return "ExportEntry";
        case TuiState::ExportVault: return "ExportVault";
        case TuiState::Import: return "Import";
        case TuiState::SaveInProgress: return "SaveInProgress";
        case TuiState::RekeyInProgress: return "RekeyInProgress";
        case TuiState::Error: return "Error";
        case TuiState::Help: return "Help";
        case TuiState::SaveConflict: return "SaveConflict";
        case TuiState::CloseConfirm: return "CloseConfirm";
        case TuiState::Settings: return "Settings";
    }
    return "?";
}

namespace {

const char* GENERIC_AUTH_MSG = "Wrong password or corrupted vault.";
const char* GENERIC_OPEN_MSG = "Vault could not be opened.";
const char* GENERIC_SAVE_MSG = "Save failed. The previous vault file is intact.";
// The vault's master password or keys were changed elsewhere (VaultRekeyed).
const char* REKEYED_SAVE_MSG =
    "Not saved: this vault's master password was changed in another program, and saving "
    "here would bring the old one back. Lock, then unlock with the new password.";

// Out of secure memory while saving (a save decrypts every entry at once, so
// a very large vault reaches the limit there first): say so; the file on
// disk is untouched.
const char* NO_SECURE_MEMORY_SAVE_MSG =
    "Not saved: not enough secure memory for this vault. The previous vault file is intact. "
    "A very large vault may need a higher limit on memory maps (vm.max_map_count on Linux).";

// Random numbers come only from RDSEED and the system's generator together
// (crypto.h): once RDSEED is missing or has failed, whatever needs them is
// refused for the rest of the run.
const char* NO_ENTROPY_SAVE_MSG =
    "Not saved: the processor's RDSEED is missing or failed its checks, and Secraxis never "
    "uses the system's random generator alone. The previous vault file is intact; restart "
    "Secraxis to try again.";
const char* NO_ENTROPY_MSG =
    "Refused: the processor's RDSEED is missing or failed its checks, and Secraxis never uses "
    "the system's random generator alone. Nothing that needs random numbers works until "
    "Secraxis restarts; the vault file is unchanged.";

const char* save_failed_text(Err e) {
    if (e == Err::VaultRekeyed) return REKEYED_SAVE_MSG;
    if (e == Err::AllocationFailed) return NO_SECURE_MEMORY_SAVE_MSG;
    if (e == Err::RngFailed) return NO_ENTROPY_SAVE_MSG;
    return GENERIC_SAVE_MSG;
}

// Each entry is held in two guarded allocations, each of them memory maps of
// its own: a system's limit on those (vm.max_map_count on Linux, 65530 by
// default, about 8,000 entries) can be reached by a very large vault.
const char* NO_SECURE_MEMORY_MSG =
    "Not enough secure memory for this vault. A very large vault may need a higher limit on "
    "memory maps (vm.max_map_count on Linux).";

// The clipboard could not be cleared yet (another program has it open).
const char* CLIP_BUSY_MSG =
    "Could not clear the clipboard yet: another program has it open. Trying again.";
constexpr uint64_t CLIP_RETRY_MS = 1000;

constexpr size_t FORM_TEXT_FIELDS = 5;  // Name, Remark, Username, URL, Tags
constexpr size_t FORM_FIELD_COUNT = 7;  // + Password + Confirm
const char* FORM_LABELS[FORM_FIELD_COUNT] = {
    "Name", "Remark", "Username", "URL", "Tags", "Password", "Confirm",
};
constexpr size_t FIELD_PASSWORD = 5;  // the confirmation follows it

// Display copies of metadata are bounded (the renderer clips anyway).
constexpr size_t META_DISPLAY_CAP = 512;

std::string meta_text(const Bytes& b) {
    const size_t n = b.size() > META_DISPLAY_CAP ? META_DISPLAY_CAP : b.size();
    return std::string(reinterpret_cast<const char*>(b.data()), n);
}

std::string basename_of(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return (s == std::string::npos) ? p : p.substr(s + 1);
}

// Where "save a copy" puts this window's version: next to the vault,
// "<name>-conflict.seis", else "-conflict-2" and on, the first name free.
std::string conflict_copy_path(const std::string& path) {
    std::string stem = path, ext;
    const size_t dot = path.find_last_of('.');
    const size_t sep = path.find_last_of("/\\");
    if (dot != std::string::npos && (sep == std::string::npos || dot > sep + 1)) {
        stem = path.substr(0, dot);
        ext = path.substr(dot);
    }
    for (int n = 1; n < 1000; ++n) {
        const std::string p =
            stem + "-conflict" + (n > 1 ? "-" + std::to_string(n) : std::string()) + ext;
        if (!file_exists(p)) return p;
    }
    return std::string();
}

bool is_ctrl(const KeyEvent& k, char32_t c) {
    return k.code == KeyEvent::Code::Char && (k.mods & KEYMOD_CTRL) && k.cp == c;
}

struct PasteTarget {
    TuiMachine* m;
    uint64_t now;
};

// Shared editing keys for a visible text field. Returns true if consumed.
bool edit_text(LineEdit& e, const KeyEvent& k) {
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

// Shared editing keys for a hidden field.
bool edit_secret(SecretLineEdit& e, const KeyEvent& k) {
    using C = KeyEvent::Code;
    if (k.code == C::Char) {
        if (k.mods & KEYMOD_CTRL) {
            if (k.cp != U'u') return false;
            e.clear();
            return true;
        }
        e.append(k.cp);
        return true;
    }
    if (k.code == C::Backspace) {
        e.backspace();
        return true;
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// TuiMachine
// ---------------------------------------------------------------------------
TuiMachine::TuiMachine(std::string vault_path, Clipboard* clipboard,
                       TuiConfig cfg)
    : path_(static_cast<std::string&&>(vault_path)),
      clipboard_(clipboard),
      cfg_(static_cast<TuiConfig&&>(cfg)) {
    create_mode_ = !file_exists(path_);
    // Each editor holds what the vault allows for its field (name, remark,
    // username, URL, tags): an edit must never cut what an import stored.
    static const FieldId kFormFields[FORM_TEXT_FIELDS] = {
        FieldId::Name, FieldId::Remark, FieldId::Username, FieldId::Url, FieldId::Tags};
    for (size_t i = 0; i < FORM_TEXT_FIELDS; ++i)
        form_text_.emplace_back(field_max_len(static_cast<uint16_t>(kFormFields[i])));
    if (cfg_.startup_note != nullptr) {
        msg_ = cfg_.startup_note;  // until the first key
        msg_kind_ = MessageKind::Info;
    }
}

TuiMachine::~TuiMachine() {
    hide_reveal();
    reset_form();
    if (clip_armed_ && clipboard_ != nullptr) clipboard_->clear_if_ours();
    session_.lock();
    pending_password_.reset();
}

void TuiMachine::enter_state(TuiState s, uint64_t now) {
    if (state_ == TuiState::RevealSecret && s != TuiState::RevealSecret)
        hide_reveal();
    state_ = s;
    last_activity_ = now;
}

void TuiMachine::say(MessageKind kind, const char* text) {
    msg_ = text;
    msg_kind_ = kind;
    // Successes and notes fade on their own; warnings and errors stay until
    // the next key so they cannot be missed.
    msg_deadline_ = (kind == MessageKind::Success || kind == MessageKind::Info)
                        ? now_ + cfg_.message_ttl_ms
                        : 0;
}

void TuiMachine::set_error() { say(MessageKind::Error, GENERIC_AUTH_MSG); }

uint64_t TuiMachine::record_time() const noexcept {
    return wall_s_ != 0 ? wall_s_ : now_ / 1000;
}

void TuiMachine::hide_reveal() {
    if (reveal_buf_.valid()) {
        reveal_buf_.reset();
        // Exposure happened: rotate this entry's runtime keys (§12.4).
        if (session_.is_open() && sel_ < view_.size())
            session_.note_secret_exposure(view_[sel_]);
    }
    reveal_deadline_ = 0;
    if (state_ == TuiState::RevealSecret) state_ = TuiState::Overview;
}

void TuiMachine::reset_form() {
    for (LineEdit& f : form_text_) f.clear();
    form_pw_.clear();
    form_pw2_.clear();
    form_cursor_ = 0;
    editing_existing_ = false;
    form_reveal_ = false;
    form_reveal_deadline_ = 0;
}

void TuiMachine::set_page_rows(size_t n) {
    page_ = n == 0 ? 1 : n;
    ensure_visible();
}

void TuiMachine::ensure_visible() {
    if (view_.empty()) {
        sel_ = 0;
        top_ = 0;
        return;
    }
    if (sel_ >= view_.size()) sel_ = view_.size() - 1;
    if (sel_ < top_) top_ = sel_;
    if (sel_ >= top_ + page_) top_ = sel_ + 1 - page_;
    // Keep the viewport full when the list shrinks or the window grows.
    if (top_ + page_ > view_.size())
        top_ = view_.size() > page_ ? view_.size() - page_ : 0;
}

void TuiMachine::refresh_rows() {
    view_.clear();
    if (!session_.is_open()) return;
    if (active_query_.empty()) {
        for (size_t i = 0; i < session_.entry_count(); ++i) view_.push_back(i);
    } else {
        Result<std::vector<size_t>> q =
            session_.query(ByteView(active_query_.data(), active_query_.size()));
        if (q.ok()) view_ = q.value;
    }
    ensure_visible();
}

bool TuiMachine::live_search() const {
    return session_.is_open() && session_.entry_count() <= LIVE_SEARCH_MAX;
}

void TuiMachine::preview_query() {
    search_pending_ = false;
    if (!live_search()) return;
    const std::string& q = query_edit_.text();
    view_.clear();
    if (q.empty()) {
        for (size_t i = 0; i < session_.entry_count(); ++i) view_.push_back(i);
        searched_.clear();
    } else {
        // Whatever contains the longer needle contains the shorter one: when
        // the needle grew, only the last hits need searching.
        const bool narrow = !searched_.empty() && q.size() > searched_.size() &&
                            q.compare(0, searched_.size(), searched_) == 0;
        Result<std::vector<size_t>> r =
            narrow ? session_.query_within(ByteView(q.data(), q.size()), searched_hits_)
                   : session_.query(ByteView(q.data(), q.size()));
        if (r.ok()) {
            view_ = r.value;
            searched_ = q;
            searched_hits_ = r.value;
        } else {
            searched_.clear();
        }
    }
    sel_ = 0;
    top_ = 0;
    ensure_visible();
}

void TuiMachine::lock_session(uint64_t now) {
    hide_reveal();
    reset_form();
    details_open_ = false;
    if (clip_armed_ && clipboard_ != nullptr) {
        // Busy: still armed, so the tick tries again (also while locked).
        if (clipboard_->clear_if_ours()) {
            clip_armed_ = false;
            clip_busy_ = false;
        } else {
            clip_busy_ = true;
            clip_deadline_ = now + CLIP_RETRY_MS;
        }
    }
    session_.lock();
    view_.clear();
    active_query_.clear();
    query_edit_.clear();
    sel_ = 0;
    top_ = 0;
    pw_edit_.clear();
    pw_confirm_.clear();
    confirm_stage_ = false;
    close_after_save_ = false;
    conflict_path_.clear();
    create_mode_ = !file_exists(path_);
    phase_ = ProgressPhase::None;
    enter_state(TuiState::Locked, now);
}

// ---- input dispatch --------------------------------------------------------
void TuiMachine::on_key(const KeyEvent& k, uint64_t now) {
    now_ = now;
    last_activity_ = now;
    caps_lock_ = (k.mods & KEYMOD_CAPS_LOCK) != 0;
    msg_.clear();
    msg_kind_ = MessageKind::None;
    msg_deadline_ = 0;
    if (k.code == KeyEvent::Code::Mouse) return;  // the app resolves pointers
    switch (state_) {
        case TuiState::Locked: key_locked(k, now); break;
        case TuiState::Unlocking:
            // Input waits while the key is derived, but Esc stops waiting: a
            // vault on a stalled network drive can block the read for
            // minutes. Back to the prompt; the shell drops the result. No
            // file is looked at here: on that drive, that would block too.
            if (k.code == KeyEvent::Code::Esc && !(k.mods & KEYMOD_PASTE)) {
                unlock_requested_ = false;
                unlock_canceled_ = true;
                pending_password_.reset();
                phase_ = ProgressPhase::None;
                enter_state(TuiState::Locked, now);
                say(MessageKind::Info, "Canceled.");
            }
            break;
        case TuiState::Overview: key_overview(k, now); break;
        case TuiState::Query: key_query(k, now); break;
        case TuiState::AddEntry:
        case TuiState::EditEntry: key_form(k, now); break;
        case TuiState::DeleteConfirm: key_delete_confirm(k, now); break;
        case TuiState::RevealSecret: key_reveal(k, now); break;
        case TuiState::CopySecret:
            // The copy notice stays in the status line; the key acts normally.
            enter_state(TuiState::Overview, now);
            key_overview(k, now);
            break;
        case TuiState::ExportEntry:
        case TuiState::ExportVault:
        case TuiState::Import:
            // Wired in Phase 5; Esc returns.
            if (k.code == KeyEvent::Code::Esc)
                enter_state(TuiState::Overview, now);
            break;
        case TuiState::SaveInProgress:
        case TuiState::RekeyInProgress: break;
        case TuiState::Error:
        case TuiState::Help: key_help_error(k); break;
        case TuiState::SaveConflict: key_save_conflict(k, now); break;
        case TuiState::CloseConfirm: key_close_confirm(k, now); break;
        case TuiState::Settings: key_settings(k, now); break;
    }
}

void TuiMachine::key_locked(const KeyEvent& k, uint64_t now) {
    SecretLineEdit& edit = confirm_stage_ ? pw_confirm_ : pw_edit_;
    switch (k.code) {
        case KeyEvent::Code::Char:
            if (k.mods & KEYMOD_CTRL) {
                if (k.cp == U'u') edit.clear();
                if (k.cp == U'v') paste_clipboard(now);
                return;
            }
            if (k.cp > 0x7E && is_text_cp(k.cp)) {
                say(MessageKind::Warning,
                    "Master passwords use printable ASCII characters only.");
                return;
            }
            if (!edit.append(k.cp) && edit.length() >= SecretLineEdit::MAX_LEN)
                say(MessageKind::Warning, "Master password is too long.");
            break;
        case KeyEvent::Code::Backspace:
            edit.backspace();
            break;
        case KeyEvent::Code::Esc:
            if (confirm_stage_) {
                // Back to the first prompt rather than quitting.
                pw_confirm_.clear();
                pw_edit_.clear();
                confirm_stage_ = false;
                return;
            }
            quit_ = true;
            break;
        case KeyEvent::Code::Enter: {
            if (create_mode_ && !confirm_stage_) {
                if (pw_edit_.length() == 0) {
                    say(MessageKind::Warning, "Master password must not be empty.");
                    return;
                }
                confirm_stage_ = true;
                return;
            }
            if (create_mode_ && confirm_stage_) {
                const bool match =
                    pw_edit_.length() == pw_confirm_.length() &&
                    pw_edit_.length() > 0 &&
                    ct_equal(pw_edit_.view().ptr, pw_confirm_.view().ptr,
                             pw_edit_.length());
                pw_confirm_.clear();
                confirm_stage_ = false;
                if (!match) {
                    pw_edit_.clear();
                    say(MessageKind::Error, "Passwords do not match. Try again.");
                    return;
                }
            } else if (pw_edit_.length() == 0) {
                return;  // nothing typed
            }
            pending_password_ = pw_edit_.take();
            if (!pending_password_.valid()) {
                // Never on with an empty password (creating, that would make
                // a vault anyone can open): no secure memory to copy it to.
                pw_edit_.clear();
                say(MessageKind::Error, NO_SECURE_MEMORY_MSG);
                return;
            }
            unlock_requested_ = true;
            phase_ = ProgressPhase::KdfStarted;
            busy_since_ = now;
            enter_state(TuiState::Unlocking, now);
            return;
        }
        default:
            break;
    }
}

bool TuiMachine::unlock_requested() {
    const bool r = unlock_requested_;
    unlock_requested_ = false;
    return r;
}

bool TuiMachine::take_unlock_canceled() {
    const bool r = unlock_canceled_;
    unlock_canceled_ = false;
    return r;
}

bool TuiMachine::take_settings_changed() {
    const bool r = settings_changed_;
    settings_changed_ = false;
    return r;
}

void TuiMachine::on_settings_write_failed() {
    say(MessageKind::Warning,
        "The settings file could not be written: the settings last until you quit.");
}

SecureBuffer TuiMachine::take_pending_password() {
    return static_cast<SecureBuffer&&>(pending_password_);
}

void TuiMachine::on_progress(ProgressPhase p) { phase_ = p; }

void TuiMachine::on_unlock_result(Result<VaultSession>&& r, uint64_t now) {
    if (state_ != TuiState::Unlocking) return;
    now_ = now;
    if (r.ok()) {
        session_ = static_cast<VaultSession&&>(r.value);
        phase_ = ProgressPhase::Ready;
        const bool created = create_mode_;
        create_mode_ = false;
        active_query_.clear();
        sel_ = 0;
        top_ = 0;
        refresh_rows();
        enter_state(TuiState::Overview, now);
        last_reseal_ = now;
        if (created) say(MessageKind::Success, "Vault created.");
        return;
    }
    phase_ = ProgressPhase::GenericFailure;
    enter_state(TuiState::Locked, now);
    create_mode_ = !file_exists(path_);
    if (r.err == Err::Exists && !create_mode_) {
        // Creating found a vault already there: made meanwhile by another
        // program, or by an earlier attempt whose Esc came as it finished.
        // Never replaced; it is unlocked like any other.
        say(MessageKind::Warning,
            "A vault with this name exists now. Enter its master password to unlock it.");
        return;
    }
    // Out of secure memory (a very large vault on a system with a low limit
    // on memory maps): the core reports it only once the password has opened
    // the vault, so saying so tells nobody anything about the password.
    if (r.err == Err::AllocationFailed) {
        say(MessageKind::Error, NO_SECURE_MEMORY_MSG);
        return;
    }
    // No random numbers (RDSEED missing or failed): refused before the
    // password was tried, so this too says nothing about the password.
    if (r.err == Err::RngFailed) {
        say(MessageKind::Error, entropy_state_text(entropy_state()));
        return;
    }
    // One generic sentence for auth-shaped failures; distinct only for IO.
    say(MessageKind::Error,
        (r.err == Err::IoRead || r.err == Err::IoWrite || r.err == Err::Exists)
            ? GENERIC_OPEN_MSG
            : GENERIC_AUTH_MSG);
}

bool TuiMachine::pick_row(const KeyEvent& k) {
    if (k.code != KeyEvent::Code::Pick) return false;
    if (k.arg >= 0 && static_cast<size_t>(k.arg) < view_.size()) {
        sel_ = static_cast<size_t>(k.arg);
        ensure_visible();
    }
    return true;
}

bool TuiMachine::key_navigate(const KeyEvent& k) {
    if (pick_row(k)) return true;
    if (k.mods & (KEYMOD_PASTE | KEYMOD_CTRL)) return false;
    const size_t n = view_.size();
    using C = KeyEvent::Code;
    const bool up = k.code == C::Up || (k.code == C::Char && k.cp == U'k');
    const bool down = k.code == C::Down || (k.code == C::Char && k.cp == U'j');
    if (up) {
        if (sel_ > 0) --sel_;
    } else if (down) {
        if (n > 0 && sel_ + 1 < n) ++sel_;
    } else if (k.code == C::PageUp) {
        sel_ = (sel_ > page_) ? sel_ - page_ : 0;
    } else if (k.code == C::PageDown) {
        if (n > 0) sel_ = (sel_ + page_ < n) ? sel_ + page_ : n - 1;
    } else if (k.code == C::Home) {
        sel_ = 0;
    } else if (k.code == C::End) {
        if (n > 0) sel_ = n - 1;
    } else {
        return false;
    }
    ensure_visible();
    return true;
}

void TuiMachine::key_overview(const KeyEvent& k, uint64_t now) {
    // Pasted text never triggers commands (a stray paste must not delete,
    // reveal, or copy anything).
    if (k.mods & KEYMOD_PASTE) return;
    if (key_navigate(k)) return;  // keys, wheel, and a picked row
    const bool have = !view_.empty();
    if (k.code == KeyEvent::Code::Esc) {
        // Esc backs out one level: the details sheet, then the filter.
        if (details_open_) {
            details_open_ = false;
        } else if (!active_query_.empty()) {
            active_query_.clear();
            refresh_rows();
        }
        return;
    }
    if (k.code == KeyEvent::Code::Enter) {
        if (have) details_open_ = !details_open_;
        return;
    }
    if (is_ctrl(k, U's')) {
        do_save(now);
        return;
    }
    if (is_ctrl(k, U'v')) {
        say(MessageKind::Info, "Paste into a field: / to search, a to add an entry.");
        return;
    }
    if (k.code != KeyEvent::Code::Char || (k.mods & KEYMOD_CTRL)) return;
    switch (k.cp) {
        case U'/':
            query_edit_.set(ByteView(active_query_.data(), active_query_.size()));
            searched_.clear();
            search_pending_ = false;
            details_open_ = false;
            enter_state(TuiState::Query, now);
            return;
        case U'a':
            reset_form();
            editing_existing_ = false;
            enter_state(TuiState::AddEntry, now);
            return;
        case U'm': {
            if (!have) return;
            reset_form();
            Result<EntryRecord> m = session_.view_metadata(view_[sel_]);
            if (!m.ok()) {
                set_error();
                return;
            }
            form_text_[0].set(ByteView(m.value.name));
            form_text_[1].set(ByteView(m.value.remark));
            form_text_[2].set(ByteView(m.value.username));
            form_text_[3].set(ByteView(m.value.url));
            form_text_[4].set(ByteView(m.value.tags));
            editing_existing_ = true;
            edit_index_ = view_[sel_];
            enter_state(TuiState::EditEntry, now);
            return;
        }
        case U'd':
            if (have) enter_state(TuiState::DeleteConfirm, now);
            return;
        case U's': {
            if (!have) return;
            Result<EntryRecord> full = session_.open_entry_secrets(view_[sel_]);
            if (!full.ok()) {
                if (full.err == Err::RngFailed)
                    say(MessageKind::Error, NO_ENTROPY_MSG);
                else
                    set_error();
                return;
            }
            reveal_buf_ = static_cast<SecureBuffer&&>(full.value.password);
            reveal_deadline_ = now + cfg_.reveal_ttl_ms;
            enter_state(TuiState::RevealSecret, now);
            return;
        }
        case U'p':
            if (have) do_copy(/*username=*/false, now);
            return;
        case U'u':
            if (have) do_copy(/*username=*/true, now);
            return;
        case U'w':
            do_save(now);
            return;
        case U'r':
            if (session_.is_open()) {
                const Status st = session_.reseal_all();
                if (st.ok())
                    say(MessageKind::Info, "Entries re-sealed under fresh runtime keys.");
                else if (st.err == Err::RngFailed)
                    say(MessageKind::Error, NO_ENTROPY_MSG);
            }
            return;
        case U'q':
            // Unsaved changes: the user decides (save and lock, discard and
            // lock, or keep working); nothing is dropped by a keystroke alone.
            if (session_.dirty()) enter_state(TuiState::CloseConfirm, now);
            else lock_session(now);
            return;
        case U'o':
            settings_cursor_ = 0;
            enter_state(TuiState::Settings, now);
            return;
        case U'?':
            enter_state(TuiState::Help, now);
            return;
        default:
            return;
    }
}

void TuiMachine::key_query(const KeyEvent& k, uint64_t now) {
    switch (k.code) {
        case KeyEvent::Code::Enter:
            active_query_ = query_edit_.text();
            query_edit_.clear();
            if (!live_search()) {
                sel_ = 0;  // the list is new; with live search it is already
                top_ = 0;  // showing these results (keep the pick)
            }
            refresh_rows();
            enter_state(TuiState::Overview, now);
            return;
        case KeyEvent::Code::Esc:
            // Cancel: the previous filter (and its list) comes back.
            query_edit_.clear();
            refresh_rows();
            enter_state(TuiState::Overview, now);
            return;
        case KeyEvent::Code::Up:
        case KeyEvent::Code::Down:
        case KeyEvent::Code::PageUp:
        case KeyEvent::Code::PageDown:
        case KeyEvent::Code::Pick:
            key_navigate(k);  // pick a result without leaving the search
            return;
        default: {
            if (is_ctrl(k, U'v')) {
                paste_clipboard(now);
                return;
            }
            const std::string before = query_edit_.text();
            edit_text(query_edit_, k);
            if (query_edit_.text() == before) return;
            // Small vaults search at once; large ones after this keystroke's
            // frame (on_tick), so typing never waits for the search.
            if (session_.entry_count() <= LIVE_SEARCH_INSTANT) preview_query();
            else search_pending_ = true;
            return;
        }
    }
}

void TuiMachine::key_form(const KeyEvent& k, uint64_t now) {
    using C = KeyEvent::Code;
    switch (k.code) {
        case C::Esc:
            reset_form();
            enter_state(TuiState::Overview, now);
            return;
        case C::Tab:
        case C::Down:
            form_cursor_ = (form_cursor_ + 1) % FORM_FIELD_COUNT;
            return;
        case C::BackTab:
        case C::Up:
            form_cursor_ = (form_cursor_ + FORM_FIELD_COUNT - 1) % FORM_FIELD_COUNT;
            return;
        case C::Enter:
            if (form_cursor_ + 1 < FORM_FIELD_COUNT) {
                ++form_cursor_;
                return;
            }
            break;  // commit below
        case C::Pick:
            if (k.arg >= 0 && static_cast<size_t>(k.arg) < FORM_FIELD_COUNT)
                form_cursor_ = static_cast<size_t>(k.arg);
            return;
        default:
            if (is_ctrl(k, U's')) break;  // commit from any field
            if (is_ctrl(k, U'r')) {
                // Show / hide the passwords being typed.
                form_reveal_ = !form_reveal_;
                form_reveal_deadline_ = form_reveal_ ? now + cfg_.reveal_ttl_ms : 0;
                return;
            }
            if (is_ctrl(k, U'v')) {
                paste_clipboard(now);
                return;
            }
            if (form_cursor_ < FORM_TEXT_FIELDS) {
                edit_text(form_text_[form_cursor_], k);
            } else {
                edit_secret(form_cursor_ == FIELD_PASSWORD ? form_pw_ : form_pw2_, k);
                // While shown, typing keeps it shown.
                if (form_reveal_) form_reveal_deadline_ = now + cfg_.reveal_ttl_ms;
            }
            return;
    }
    const bool editing = editing_existing_;
    if (commit_form(now).ok()) {
        enter_state(TuiState::Overview, now);
        switch (autosave(now)) {
            case AutoSaved::Off:
                say(MessageKind::Success, editing ? "Entry updated." : "Entry added.");
                break;
            case AutoSaved::Saved:
                say(MessageKind::Success,
                    editing ? "Entry updated and saved." : "Entry added and saved.");
                break;
            case AutoSaved::Asked:
                break;  // the conflict dialog says what happened
            case AutoSaved::Failed:
                say(MessageKind::Error, editing
                                            ? "Entry updated, but saving failed. w tries again."
                                            : "Entry added, but saving failed. w tries again.");
                break;
            case AutoSaved::Rekeyed:
                say(MessageKind::Error, REKEYED_SAVE_MSG);
                break;
        }
    }
}

Status TuiMachine::commit_form(uint64_t now) {
    (void)now;
    if (form_text_[0].empty()) {
        form_cursor_ = 0;
        say(MessageKind::Error, "Name is required.");
        return status_fail(Err::InvalidArgument);
    }
    // Constant-time confirm comparison (lengths equal + content equal).
    const bool pw_match =
        form_pw_.length() == form_pw2_.length() &&
        (form_pw_.length() == 0 ||
         ct_equal(form_pw_.view().ptr, form_pw2_.view().ptr, form_pw_.length()));
    if (!pw_match) {
        form_pw_.clear();
        form_pw2_.clear();
        form_cursor_ = FIELD_PASSWORD;
        say(MessageKind::Error, "Password confirmation does not match.");
        return status_fail(Err::InvalidArgument);
    }
    if (!editing_existing_ && form_pw_.length() == 0) {
        form_cursor_ = FIELD_PASSWORD;
        say(MessageKind::Error, "Password must not be empty.");
        return status_fail(Err::InvalidArgument);
    }

    EntryRecord e;
    auto put = [](const LineEdit& f, Bytes& out) {
        out.assign(f.text().begin(), f.text().end());
    };
    put(form_text_[0], e.name);
    put(form_text_[1], e.remark);
    put(form_text_[2], e.username);
    put(form_text_[3], e.url);
    put(form_text_[4], e.tags);

    if (editing_existing_) {
        // The form edits only the password (empty = keep it). The entry's
        // other secrets (a TOTP seed, recovery codes, a secret note: an
        // import can store them) stay as they are, also with a new password.
        Result<EntryRecord> old = session_.open_entry_secrets(edit_index_);
        if (!old.ok()) {
            if (old.err == Err::AllocationFailed)
                say(MessageKind::Error, NO_SECURE_MEMORY_MSG);
            else if (old.err == Err::RngFailed)
                say(MessageKind::Error, NO_ENTROPY_MSG);
            else
                set_error();
            return status_fail(old.err);
        }
        if (form_pw_.length() == 0)
            e.password = static_cast<SecureBuffer&&>(old.value.password);
        else
            e.password = form_pw_.take();
        e.totp_seed = static_cast<SecureBuffer&&>(old.value.totp_seed);
        e.recovery_codes = static_cast<SecureBuffer&&>(old.value.recovery_codes);
        e.secret_note = static_cast<SecureBuffer&&>(old.value.secret_note);
    } else {
        e.password = form_pw_.take();
    }
    // No secure memory to take the new password into (the form keeps it, and
    // its confirmation): nothing is stored, rather than the entry without
    // its password.
    if (form_pw_.length() > 0) {
        say(MessageKind::Error, NO_SECURE_MEMORY_MSG);
        return status_fail(Err::AllocationFailed);
    }
    form_pw2_.clear();

    Status st;
    size_t store_index = edit_index_;
    if (editing_existing_) {
        st = session_.modify_entry(edit_index_, static_cast<EntryRecord&&>(e),
                                   record_time());
    } else {
        Result<size_t> r =
            session_.add_entry(static_cast<EntryRecord&&>(e), record_time());
        st = r.ok() ? status_ok() : status_fail(r.err);
        if (r.ok()) store_index = r.value;
    }
    if (!st.ok()) {
        say(MessageKind::Error, st.err == Err::AllocationFailed ? NO_SECURE_MEMORY_MSG
                                : st.err == Err::RngFailed      ? NO_ENTROPY_MSG
                                                                : "Could not store the entry.");
        return st;
    }
    reset_form();
    // Select the stored entry if it is part of the current view.
    refresh_rows();
    for (size_t vi = 0; vi < view_.size(); ++vi)
        if (view_[vi] == store_index) sel_ = vi;
    return status_ok();
}

void TuiMachine::key_delete_confirm(const KeyEvent& k, uint64_t now) {
    if (k.mods & KEYMOD_PASTE) return;  // a paste can neither confirm nor cancel
    const bool yes = (k.code == KeyEvent::Code::Enter) ||
                     (k.code == KeyEvent::Code::Char && !(k.mods & KEYMOD_CTRL) &&
                      (k.cp == U'y' || k.cp == U'Y'));
    enter_state(TuiState::Overview, now);
    if (yes && sel_ < view_.size()) {
        // The ONLY call site allowed to pass confirmed=true (lifecycle §3).
        Status st = session_.delete_entry(view_[sel_], /*confirmed=*/true);
        // Store indices shifted: rebuild the view (the filter is re-run).
        refresh_rows();
        if (view_.empty()) details_open_ = false;
        if (!st.ok()) {
            set_error();
            return;
        }
        switch (autosave(now)) {
            case AutoSaved::Off:
                say(MessageKind::Success, "Entry deleted. Press w to save the change.");
                break;
            case AutoSaved::Saved:
                say(MessageKind::Success, "Entry deleted and saved.");
                break;
            case AutoSaved::Asked:
                break;
            case AutoSaved::Failed:
                say(MessageKind::Error, "Entry deleted, but saving failed. w tries again.");
                break;
            case AutoSaved::Rekeyed:
                say(MessageKind::Error, REKEYED_SAVE_MSG);
                break;
        }
    }
}

void TuiMachine::key_reveal(const KeyEvent& k, uint64_t now) {
    // Any key hides; navigation keys (and a picked row) then also move the
    // selection.
    hide_reveal();
    enter_state(TuiState::Overview, now);
    key_navigate(k);
}

void TuiMachine::key_help_error(const KeyEvent& k) {
    (void)k;  // any key returns
    state_ = TuiState::Overview;
    if (!session_.is_open()) state_ = TuiState::Locked;
}

// Ctrl+V: the clipboard's text arrives exactly as a terminal paste would:
// as pasted characters (text fields only), filtered like a bracketed paste.
// The text may be a secret; it lives only in a SecureBuffer.
void TuiMachine::paste_clipboard(uint64_t now) {
    if (clipboard_ == nullptr) {
        say(MessageKind::Warning, "Clipboard unavailable.");
        return;
    }
    SecureBuffer text;
    switch (clipboard_->read_text(&text)) {
        case PasteStatus::Ok:
            break;
        case PasteStatus::Empty:
            say(MessageKind::Info, "The clipboard has no text.");
            return;
        case PasteStatus::TooLong:
            say(MessageKind::Warning, "The clipboard text is too long to paste.");
            return;
        case PasteStatus::Unavailable:
            say(MessageKind::Info, clipboard_->paste_hint());
            return;
    }
    PasteTarget t{this, now};
    for_each_pasted(
        text.view(),
        [](void* ctx, char32_t cp) {
            PasteTarget* pt = static_cast<PasteTarget*>(ctx);
            pt->m->on_key(KeyEvent::chr(cp, KEYMOD_PASTE), pt->now);
        },
        &t);
}

void TuiMachine::do_copy(bool username, uint64_t now) {
    if (clipboard_ == nullptr) {
        say(MessageKind::Error, "Clipboard unavailable.");
        return;
    }
    const size_t idx = view_[sel_];
    bool ok = false;
    if (username) {
        Result<EntryRecord> m = session_.view_metadata(idx);
        if (m.ok()) ok = clipboard_->set_secret(ByteView(m.value.username));
    } else {
        Result<EntryRecord> full = session_.open_entry_secrets(idx);
        if (!full.ok() && full.err == Err::RngFailed) {
            say(MessageKind::Error, NO_ENTROPY_MSG);
            return;
        }
        if (full.ok()) {
            ok = clipboard_->set_secret(full.value.password.view());
            // full.value destructs here: plaintext scratch wiped.
            session_.note_secret_exposure(idx);
        }
    }
    if (!ok) {
        say(MessageKind::Error, clipboard_->copy_hint());
        return;
    }
    clip_armed_ = true;
    clip_busy_ = false;
    clip_deadline_ = now + cfg_.clipboard_ttl_ms;
    enter_state(TuiState::CopySecret, now);
    if (clipboard_->via_terminal()) {
        const std::string note = std::string(username ? "Username " : "Password ") +
                                 clipboard_->sent_note();
        say(MessageKind::Success, note.c_str());
    } else
        say(MessageKind::Success, username ? "Username copied." : "Password copied.");
}

void TuiMachine::do_save(uint64_t now) {
    if (!session_.is_open()) return;
    enter_state(TuiState::SaveInProgress, now);
    phase_ = ProgressPhase::Saving;
    Status st = session_.save(record_time());
    phase_ = st.ok() ? ProgressPhase::Ready : ProgressPhase::GenericFailure;
    if (st.err == Err::VaultChanged) {
        // Someone else saved the file meanwhile: never drop their changes
        // silently; the user chooses (nothing is written yet).
        phase_ = ProgressPhase::Ready;
        conflict_path_ = conflict_copy_path(path_);
        enter_state(TuiState::SaveConflict, now);
        return;
    }
    enter_state(TuiState::Overview, now);
    if (st.ok()) say(MessageKind::Success, "Vault saved.");
    else say(MessageKind::Error, save_failed_text(st.err));
}

Status TuiMachine::save_copy() {
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (conflict_path_.empty()) conflict_path_ = conflict_copy_path(path_);
        if (conflict_path_.empty()) return status_fail(Err::Exists);
        Status st = session_.save_copy(conflict_path_, record_time());
        if (st.ok()) {
            path_ = conflict_path_;
            conflict_path_.clear();
            return st;
        }
        conflict_path_.clear();
        if (st.err != Err::Exists) return st;  // else: taken meanwhile, next name
    }
    return status_fail(Err::Exists);
}

TuiMachine::Kept TuiMachine::keep_changes() {
    if (!session_.is_open() || !session_.dirty()) return Kept::Nothing;
    if (cfg_.settings.unattended == Unattended::Discard) return Kept::Discarded;
    Status st = session_.save(record_time());
    if (st.ok()) return Kept::Saved;
    // Its password was changed elsewhere: no copy with the old keys either.
    if (st.err == Err::VaultRekeyed) return Kept::Rekeyed;
    // The vault cannot take them (it changed on disk, another save of it is
    // stuck, it cannot be written): nobody can be asked, so a copy beside
    // it keeps them, where one can be written.
    const Status cs = save_copy();
    if (cs.ok()) return st.err == Err::VaultChanged ? Kept::Copied : Kept::CopiedInstead;
    return cs.err == Err::VaultRekeyed ? Kept::Rekeyed : Kept::Failed;
}

TuiMachine::AutoSaved TuiMachine::autosave(uint64_t now) {
    if (cfg_.settings.save != SaveMode::Auto || !session_.is_open() || !session_.dirty())
        return AutoSaved::Off;
    Status st = session_.save(record_time());
    if (st.ok()) return AutoSaved::Saved;
    if (st.err == Err::VaultChanged) {
        // As for w: the user, who just made the change, chooses.
        conflict_path_ = conflict_copy_path(path_);
        enter_state(TuiState::SaveConflict, now);
        return AutoSaved::Asked;
    }
    return st.err == Err::VaultRekeyed ? AutoSaved::Rekeyed : AutoSaved::Failed;
}

void TuiMachine::close_saving(uint64_t now) {
    Status st = session_.save(record_time());
    if (st.ok()) {
        lock_session(now);
        say(MessageKind::Success, "Saved and locked.");
        return;
    }
    if (st.err == Err::VaultChanged) {
        // The conflict dialog decides how; locking follows unless it is
        // backed out of.
        conflict_path_ = conflict_copy_path(path_);
        close_after_save_ = true;
        enter_state(TuiState::SaveConflict, now);
        return;
    }
    enter_state(TuiState::Overview, now);
    say(MessageKind::Error,
        st.err == Err::VaultRekeyed
            ? REKEYED_SAVE_MSG
            : "Save failed, so the vault stays open. The previous vault file is intact.");
}

// q with unsaved changes. s / Enter: save, then lock; d: lock without
// saving (the vault file stays as last saved); Esc / c: back to the vault,
// nothing changed. A paste chooses nothing, and neither does another q.
void TuiMachine::key_close_confirm(const KeyEvent& k, uint64_t now) {
    if (k.mods & KEYMOD_PASTE) return;
    const bool plain = k.code == KeyEvent::Code::Char && !(k.mods & KEYMOD_CTRL);
    if (k.code == KeyEvent::Code::Enter || (plain && (k.cp == U's' || k.cp == U'S'))) {
        close_saving(now);
        return;
    }
    if (plain && (k.cp == U'd' || k.cp == U'D')) {
        lock_session(now);
        say(MessageKind::Info, "Locked. The unsaved changes were discarded.");
        return;
    }
    if (k.code == KeyEvent::Code::Esc || (plain && (k.cp == U'c' || k.cp == U'C')))
        enter_state(TuiState::Overview, now);
}

// How changes are saved. Up/Down choose an item, Left/Right/Space change it
// (a click on an item does both); Esc, Enter or o closes. Changes apply at
// once; the shell writes them to settings.json.
void TuiMachine::key_settings(const KeyEvent& k, uint64_t now) {
    constexpr size_t kItems = 2;  // save mode, unattended
    if (k.mods & KEYMOD_PASTE) return;
    using C = KeyEvent::Code;
    const bool plain = k.code == C::Char && !(k.mods & KEYMOD_CTRL);
    if (k.code == C::Esc || k.code == C::Enter || (plain && k.cp == U'o')) {
        enter_state(TuiState::Overview, now);
        // "Automatically" leaves nothing unsaved, including what was
        // changed before it was chosen.
        switch (autosave(now)) {
            case AutoSaved::Saved: say(MessageKind::Success, "Your changes were saved."); break;
            case AutoSaved::Failed: say(MessageKind::Error, GENERIC_SAVE_MSG); break;
            case AutoSaved::Rekeyed: say(MessageKind::Error, REKEYED_SAVE_MSG); break;
            default: break;
        }
        return;
    }
    if (k.code == C::Up || k.code == C::BackTab || (plain && k.cp == U'k')) {
        settings_cursor_ = (settings_cursor_ + kItems - 1) % kItems;
        return;
    }
    if (k.code == C::Down || k.code == C::Tab || (plain && k.cp == U'j')) {
        settings_cursor_ = (settings_cursor_ + 1) % kItems;
        return;
    }
    bool change = k.code == C::Left || k.code == C::Right || (plain && k.cp == U' ');
    if (k.code == C::Pick && k.arg >= 0 && static_cast<size_t>(k.arg) < kItems) {
        settings_cursor_ = static_cast<size_t>(k.arg);
        change = true;
    }
    if (!change) return;
    Settings& s = cfg_.settings;
    if (settings_cursor_ == 0)
        s.save = s.save == SaveMode::Auto ? SaveMode::Manual : SaveMode::Auto;
    else
        s.unattended =
            s.unattended == Unattended::Save ? Unattended::Discard : Unattended::Save;
    settings_changed_ = true;
}

bool TuiMachine::on_hangup(uint64_t now) {
    now_ = now;
    const Kept kept = keep_changes();
    lock_session(now);
    quit_ = true;
    return kept != Kept::Failed && kept != Kept::Rekeyed;
}

// The vault file changed on disk since this window opened or last saved it.
// c / Enter: save this window's version as a copy next to it and go on there
// (nothing is lost); o: overwrite what the other side saved; Esc / n: back,
// still unsaved. A paste chooses nothing.
void TuiMachine::key_save_conflict(const KeyEvent& k, uint64_t now) {
    if (k.mods & KEYMOD_PASTE) return;
    const bool plain = k.code == KeyEvent::Code::Char && !(k.mods & KEYMOD_CTRL);
    // After "save and lock", a successful choice also locks.
    const bool closing = close_after_save_;
    if (k.code == KeyEvent::Code::Enter || (plain && (k.cp == U'c' || k.cp == U'C'))) {
        close_after_save_ = false;
        enter_state(TuiState::Overview, now);
        const Status cs = save_copy();
        if (cs.ok()) {
            if (closing) lock_session(now);
            const std::string note =
                "Saved as " + basename_of(path_) +
                (closing ? ". Locked." : ". The file you opened keeps the other changes.");
            say(MessageKind::Success, note.c_str());
            msg_deadline_ = 0;  // keep it until the next key
        } else {
            say(MessageKind::Error, save_failed_text(cs.err));
        }
        return;
    }
    if (plain && (k.cp == U'o' || k.cp == U'O')) {
        close_after_save_ = false;
        enter_state(TuiState::Overview, now);
        const Status os = session_.save_overwrite(record_time());
        if (os.ok()) {
            if (closing) {
                lock_session(now);
                say(MessageKind::Success, "Saved over the other changes and locked.");
            } else {
                say(MessageKind::Success, "Vault saved over the other changes.");
            }
        } else {
            say(MessageKind::Error, save_failed_text(os.err));
        }
        return;
    }
    if (k.code == KeyEvent::Code::Esc || (plain && (k.cp == U'n' || k.cp == U'N'))) {
        close_after_save_ = false;
        conflict_path_.clear();
        enter_state(TuiState::Overview, now);
        say(MessageKind::Warning, closing
                                      ? "Not saved and not locked. Your changes are still here."
                                      : "Not saved. Your changes are still here; w to choose again.");
    }
}

void TuiMachine::on_tick(uint64_t now) {
    now_ = now;
    if (search_pending_ && state_ == TuiState::Query) preview_query();
    // Reveal TTLs.
    if (state_ == TuiState::RevealSecret && now >= reveal_deadline_) {
        hide_reveal();
    }
    if (form_reveal_ && now >= form_reveal_deadline_) {
        form_reveal_ = false;
        form_reveal_deadline_ = 0;
    }
    // Clipboard TTL. While another program has the clipboard open it cannot
    // be cleared: tried again each second, and the user told once.
    if (clip_armed_ && now >= clip_deadline_) {
        if (clipboard_ == nullptr || clipboard_->clear_if_ours()) {
            clip_armed_ = false;
            if (msg_kind_ == MessageKind::None || msg_deadline_ != 0 ||
                (clip_busy_ && msg_ == CLIP_BUSY_MSG))
                say(MessageKind::Info, "Clipboard cleared.");
            clip_busy_ = false;
        } else {
            if (!clip_busy_) say(MessageKind::Warning, CLIP_BUSY_MSG);
            clip_busy_ = true;
            clip_deadline_ = now + CLIP_RETRY_MS;
        }
    }
    if (msg_deadline_ != 0 && now >= msg_deadline_) {
        msg_.clear();
        msg_kind_ = MessageKind::None;
        msg_deadline_ = 0;
    }
    if (session_.is_open()) {
        // Idle auto-lock. Nobody is there to ask about unsaved changes, so
        // the user's setting decides: saved first (to a copy if the vault
        // changed on disk; walking away must not cost work), or dropped.
        if (now - last_activity_ >= cfg_.idle_lock_ms) {
            const Kept kept = keep_changes();
            lock_session(now);
            switch (kept) {
                case Kept::Nothing:
                    say(MessageKind::Info, "Locked after a period of inactivity.");
                    break;
                case Kept::Saved:
                    say(MessageKind::Info,
                        "Locked after a period of inactivity. Your changes were saved.");
                    break;
                case Kept::Copied: {
                    const std::string note = "Locked after inactivity. The vault had changed on "
                                             "disk, so your changes were saved as " +
                                             basename_of(path_) + ".";
                    say(MessageKind::Warning, note.c_str());
                    break;
                }
                case Kept::CopiedInstead: {
                    const std::string note = "Locked after inactivity. The vault could not be "
                                             "saved in place, so your changes were saved as " +
                                             basename_of(path_) + ".";
                    say(MessageKind::Warning, note.c_str());
                    break;
                }
                case Kept::Discarded:
                    say(MessageKind::Warning,
                        "Locked after inactivity. Your unsaved changes were discarded, as set "
                        "in Settings.");
                    break;
                case Kept::Failed:
                    say(MessageKind::Error,
                        "Locked after inactivity. Your unsaved changes could not be saved.");
                    break;
                case Kept::Rekeyed:
                    say(MessageKind::Error,
                        "Locked after inactivity. Your unsaved changes were not saved: this "
                        "vault's master password was changed in another program.");
                    break;
            }
            msg_deadline_ = 0;  // keep the reason visible until a key
            return;
        }
        // Periodic moving-target reseal.
        if (now - last_reseal_ >= cfg_.reseal_interval_ms) {
            session_.reseal_all();
            last_reseal_ = now;
        }
    }
}

// ---- render model ----------------------------------------------------------
const RenderModel& TuiMachine::render_model() {
    RenderModel& m = model_;
    m.state = state_;
    m.now_ms = now_;
    m.conflict_copy = state_ == TuiState::SaveConflict ? basename_of(conflict_path_) : std::string();
    m.vault_name = basename_of(path_);
    m.vault_open = session_.is_open();
    m.create_mode = create_mode_;
    m.create_kdf_label = cfg_.create_kdf_label;
    m.dirty = m.vault_open && session_.dirty();
    m.entry_total = m.vault_open ? session_.entry_count() : 0;
    m.epoch = m.vault_open ? session_.header().epoch : 0;
    m.kdf_profile = m.vault_open ? session_.header().kdf_profile_id : 0;
    m.aead_profile = m.vault_open ? session_.header().aead_profile_id : 0;

    m.rows.clear();
    m.view_total = view_.size();
    m.view_top = top_;
    m.selected = sel_;
    m.filter = active_query_;
    m.details_open = details_open_ && !view_.empty();
    m.live_search = live_search();
    m.wall_now_s = wall_s_;
    if (m.vault_open) {
        const size_t end = (top_ + page_ < view_.size()) ? top_ + page_ : view_.size();
        for (size_t vi = top_; vi < end; ++vi) {
            Result<EntryRecord> meta = session_.view_metadata(view_[vi]);
            if (!meta.ok()) continue;
            RenderRow row;
            row.ordinal = vi + 1;
            row.name = meta_text(meta.value.name);
            row.remark = meta_text(meta.value.remark);
            row.username = meta_text(meta.value.username);
            row.url = meta_text(meta.value.url);
            row.tags = meta_text(meta.value.tags);
            row.pw_bucket = meta.value.pw_bucket;
            row.created_at = meta.value.created_at;
            row.updated_at = meta.value.updated_at;
            row.selected = (vi == sel_);
            m.rows.push_back(static_cast<RenderRow&&>(row));
        }
    }

    m.pw_chars = confirm_stage_ ? pw_confirm_.chars() : pw_edit_.chars();
    m.confirm_stage = confirm_stage_;
    m.caps_lock = caps_lock_;
    m.query_text = (state_ == TuiState::Query) ? query_edit_.text() : std::string();
    m.query_caret = (state_ == TuiState::Query) ? query_edit_.caret() : 0;

    m.message = msg_;
    m.message_kind = msg_kind_;

    m.reveal_text = ByteView();
    m.reveal_remaining_ms = 0;
    m.reveal_ttl_ms = cfg_.reveal_ttl_ms;
    if (state_ == TuiState::RevealSecret) {
        m.reveal_text = reveal_buf_.view();
        m.reveal_remaining_ms = reveal_deadline_ > now_ ? reveal_deadline_ - now_ : 0;
    }
    m.clip_remaining_ms =
        (clip_armed_ && clip_deadline_ > now_) ? clip_deadline_ - now_ : 0;
    m.clip_ttl_ms = cfg_.clipboard_ttl_ms;

    m.phase = phase_;
    m.busy_elapsed_ms =
        (state_ == TuiState::Unlocking && now_ > busy_since_) ? now_ - busy_since_ : 0;

    m.editing_existing = editing_existing_;
    m.form.clear();
    m.form_cursor = form_cursor_;
    m.pw_match = -1;
    m.from_launcher = cfg_.from_launcher;
    m.settings = cfg_.settings;
    m.settings_cursor = settings_cursor_;
    m.form_revealed = false;
    m.form_reveal_remaining_ms = 0;
    if (state_ == TuiState::AddEntry || state_ == TuiState::EditEntry) {
        for (size_t i = 0; i < FORM_FIELD_COUNT; ++i) {
            FormField f;
            f.label = FORM_LABELS[i];
            if (i < FORM_TEXT_FIELDS) {
                f.value = form_text_[i].text();
                f.caret = form_text_[i].caret();
                f.required = (i == 0);
            } else {
                const SecretLineEdit& s = (i == FIELD_PASSWORD) ? form_pw_ : form_pw2_;
                f.secret = true;
                f.secret_chars = s.chars();
                f.required = !editing_existing_;
                if (form_reveal_) f.reveal = s.view();
            }
            m.form.push_back(static_cast<FormField&&>(f));
        }
        m.form_revealed = form_reveal_;
        m.form_reveal_remaining_ms =
            (form_reveal_ && form_reveal_deadline_ > now_) ? form_reveal_deadline_ - now_ : 0;
        if (form_pw2_.length() > 0) {
            m.pw_match = (form_pw_.length() == form_pw2_.length() &&
                          ct_equal(form_pw_.view().ptr, form_pw2_.view().ptr,
                                   form_pw_.length()))
                             ? 1
                             : 0;
        }
    }
    return m;
}

void for_each_pasted(ByteView text, void (*sink)(void* ctx, char32_t cp), void* ctx) {
    const char* p = reinterpret_cast<const char*>(text.ptr);
    size_t i = 0;
    while (i < text.len) {
        char32_t cp = 0;
        // An ill-formed sequence is skipped (utf8_decode consumes it).
        if (!utf8_decode(p, text.len, &i, &cp)) continue;
        if (cp >= 0x20 && cp != 0x7F && is_text_cp(cp)) sink(ctx, cp);
    }
}

}  // namespace secraxis
