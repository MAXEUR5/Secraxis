// tui_core.h — the TUI state machine (agenda §14), PURE logic:
// no terminal IO, no threads, no wall clock of its own. The app shell feeds it
// key events, ticks (injected monotonic ms), the wall-clock time used for
// record timestamps, and async results; it mutates the VaultSession and
// produces a RenderModel. This is what the headless state-machine tests and
// the input-FSM fuzz target drive.
//
// Secret-exposure rules enforced HERE (not in the renderer):
//  * master password / entry passwords are edited only in SecretLineEdit
//    (SecureBuffer-backed, wiped on cancel/commit/state exit)
//  * reveal is entry-scoped with a TTL (default 10 s): hidden on timeout,
//    Esc, selection change, or any state change; the revealed bytes live in
//    one SecureBuffer the machine owns and wipes
//  * copy goes through the Clipboard interface with a TTL (default 20 s)
//    and clear-if-still-ours semantics
//  * delete requires the DeleteConfirm state; only 'y'/Enter there calls
//    VaultSession::delete_entry(idx, /*confirmed=*/true)
//  * pasted input (KEYMOD_PASTE) only ever lands in text fields; it can never
//    trigger a command or confirm a deletion
//  * search is explicit (agenda §14.4: never a default live search field):
//    only '/' opens it; while it is open the list filters as you type, and
//    it searches metadata only (guaranteed by VaultSession::query)
//  * idle auto-lock (default 300 s) wipes everything via session lock()
//  * unsaved changes are never dropped without the user: locking with them
//    asks (save, discard, cancel); with nobody there to ask (idle lock,
//    hangup) the user's setting decides (Settings::unattended)
//  * the master password is printable ASCII only: Unicode passphrases can
//    encode differently across input methods and platforms (NFC vs NFD),
//    which would lock the user out of the vault
//  * "show" on the master-password prompt (Ctrl+R) is off whenever a prompt
//    opens; it hides after reveal_ttl_ms without typing, on Enter or Esc, at
//    the confirm step and whenever the machine leaves the prompt, and a
//    paste can never turn it on
//  * command letters act in either case (Caps Lock, Shift): see
//    command_letter(); text and password fields keep what is typed
#ifndef SECRAXIS_TUI_CORE_H
#define SECRAXIS_TUI_CORE_H

#include <string>
#include <vector>

#include "secraxis/common.h"
#include "secraxis/secure_buffer.h"
#include "secraxis/settings.h"
#include "secraxis/vault_session.h"

namespace secraxis {

// ---------------------------------------------------------------------------
// Input events
// ---------------------------------------------------------------------------
enum : uint8_t {
    KEYMOD_CTRL = 1,
    KEYMOD_ALT = 2,
    KEYMOD_SHIFT = 4,
    KEYMOD_PASTE = 8,       // part of a bracketed paste, not typed
    KEYMOD_CAPS_LOCK = 16,  // Caps Lock was on (where the platform reports it)
};

struct KeyEvent {
    enum class Code : uint8_t {
        Char, Enter, Esc, Up, Down, Left, Right, PageUp, PageDown, Tab,
        BackTab, Backspace, Del, Home, End,
        Pick,   // pointer: choose item `arg` of the current view (a list row,
                // a form field); produced by the app from a click
        Mouse,  // raw pointer event from the terminal; the app turns it into
                // Pick or key events and never passes it to a machine
    };
    enum class Pointer : uint8_t { Press, Release, WheelUp, WheelDown };
    Code code = Code::Char;
    char32_t cp = 0;    // Unicode scalar for Code::Char
    uint8_t mods = 0;   // KEYMOD_*
    Pointer pointer = Pointer::Press;  // Mouse
    uint8_t button = 0;                // Mouse: 0 left, 1 middle, 2 right
    int16_t x = 0, y = 0;              // Mouse: zero-based cell
    int32_t arg = 0;                   // Pick: the item
    static KeyEvent chr(char32_t c, uint8_t m = 0) {
        KeyEvent k;
        k.cp = c;
        k.mods = m;
        return k;
    }
    static KeyEvent key(Code c, uint8_t m = 0) {
        KeyEvent k;
        k.code = c;
        k.mods = m;
        return k;
    }
    static KeyEvent pick(int32_t item) {
        KeyEvent k;
        k.code = Code::Pick;
        k.arg = item;
        return k;
    }
    static KeyEvent mouse(Pointer p, uint8_t btn, int16_t cx, int16_t cy) {
        KeyEvent k;
        k.code = Code::Mouse;
        k.pointer = p;
        k.button = btn;
        k.x = cx;
        k.y = cy;
        return k;
    }
};

// The letter a command key stands for: 'A'-'Z' act as 'a'-'z', so Caps Lock
// or Shift never silences a command. Text fields take KeyEvent::cp as typed.
constexpr char32_t command_letter(char32_t cp) noexcept {
    return (cp >= U'A' && cp <= U'Z') ? cp + (U'a' - U'A') : cp;
}

// ---------------------------------------------------------------------------
// Clipboard abstraction (real impl in tui/clipboard.cpp; fake in tests)
// ---------------------------------------------------------------------------
// What reading the clipboard (Ctrl+V) gave.
enum class PasteStatus : uint8_t {
    Ok,           // the text is in the buffer
    Empty,        // no text on the clipboard
    TooLong,      // more than PASTE_MAX bytes
    Unavailable,  // no clipboard this process can read (e.g. over SSH)
};
constexpr size_t PASTE_MAX = 64 * 1024;  // bytes of UTF-8 one paste may carry

class Clipboard {
  public:
    virtual ~Clipboard() = default;
    // Copies secret bytes (UTF-8); implementation must not log or persist them.
    virtual bool set_secret(ByteView data) = 0;
    // Clears the clipboard ONLY if it still holds what we set. False when it
    // could not even be looked at (another program has it open): it may
    // still hold our copy, so the caller tries again later.
    virtual bool clear_if_ours() = 0;
    // Reads the clipboard's text as UTF-8 for Ctrl+V. It may be a secret: it
    // goes straight into *out (a SecureBuffer) and is never logged.
    virtual PasteStatus read_text(SecureBuffer* out) {
        (void)out;
        return PasteStatus::Unavailable;
    }
    // How to paste when read_text is Unavailable (one status line).
    virtual const char* paste_hint() const {
        return "Paste with your terminal's paste key (often Ctrl+Shift+V).";
    }
    // True when a copy went through the terminal (OSC 52) rather than a
    // clipboard this process can see.
    virtual bool via_terminal() const { return false; }
    // Why set_secret failed (one status line).
    virtual const char* copy_hint() const { return "Clipboard unavailable."; }
    // After "Password " when the copy went through the terminal.
    virtual const char* sent_note() const { return "sent to your terminal's clipboard."; }
};

// How the platform clipboard recognizes its own copy for clear-if-ours:
// keyed BLAKE2b under a random key drawn per instance and kept in secure
// memory, so a fingerprint found elsewhere (swap, a dump) says nothing
// about the copied secret without that key.
class ClipboardFingerprint {
  public:
    ClipboardFingerprint();
    bool valid() const { return key_.valid(); }
    // Writes the 32-byte fingerprint of `data`; false, with `out` zeroed,
    // when there is no key.
    bool of(ByteView data, uint8_t out[32]) const;

  private:
    SecureBuffer key_;
};

// Calls sink(ctx, cp) for each character of a clipboard paste, keeping
// exactly what a bracketed paste keeps: CR, LF, Tab, Esc and other controls,
// and anything that is not text, are dropped.
void for_each_pasted(ByteView text, void (*sink)(void* ctx, char32_t cp), void* ctx);

// ---------------------------------------------------------------------------
// Line editors
// ---------------------------------------------------------------------------
// Secret line editor (hidden input). UTF-8, SecureBuffer-backed; appends and
// backspaces whole code points. With ascii_only, only printable ASCII is
// accepted.
class SecretLineEdit final {
  public:
    static constexpr size_t MAX_LEN = 512;  // bytes
    explicit SecretLineEdit(bool ascii_only = false) : ascii_only_(ascii_only) {}
    bool append(char32_t cp);
    void backspace();
    void clear();                 // wipe
    size_t length() const noexcept { return len_; }    // bytes
    size_t chars() const noexcept { return chars_; }   // code points
    ByteView view() const noexcept;
    SecureBuffer take();          // copy out + wipe editor
    ~SecretLineEdit() { clear(); }
    SecretLineEdit(SecretLineEdit&&) = default;
    SecretLineEdit& operator=(SecretLineEdit&&) = default;
    SecretLineEdit(const SecretLineEdit&) = delete;
    SecretLineEdit& operator=(const SecretLineEdit&) = delete;

  private:
    SecureBuffer buf_;  // MAX_LEN capacity
    size_t len_ = 0;
    size_t chars_ = 0;
    bool ascii_only_ = false;
};

// Visible single-line text editor (metadata fields, query). UTF-8 with a
// caret; caret moves skip combining marks. Existing bytes are kept verbatim
// (ill-formed sequences are treated as single units), so editing one field
// never rewrites another's bytes. Wiped on clear().
class LineEdit final {
  public:
    explicit LineEdit(size_t max_bytes = 256) : max_(max_bytes) {}
    ~LineEdit() { clear(); }
    LineEdit(LineEdit&&) = default;
    LineEdit& operator=(LineEdit&&) = default;
    LineEdit(const LineEdit&) = delete;
    LineEdit& operator=(const LineEdit&) = delete;

    bool insert(char32_t cp);
    void backspace();
    void del();
    void left();
    void right();
    void home() noexcept { caret_ = 0; }
    void end() noexcept { caret_ = s_.size(); }
    void clear();
    void set(ByteView b);   // load verbatim (truncated to max), caret at end
    const std::string& text() const noexcept { return s_; }
    size_t caret() const noexcept { return caret_; }
    bool empty() const noexcept { return s_.empty(); }

  private:
    size_t prev_unit(size_t pos) const;
    size_t next_unit(size_t pos) const;
    std::string s_;
    size_t caret_ = 0;
    size_t max_ = 256;
};

// ---------------------------------------------------------------------------
// States (agenda §14.4)
// ---------------------------------------------------------------------------
enum class TuiState : uint8_t {
    Locked, Unlocking, Overview, Query, AddEntry, EditEntry, DeleteConfirm,
    RevealSecret, CopySecret, ExportEntry, ExportVault, Import,
    SaveInProgress, RekeyInProgress, Error, Help,
    SaveConflict,  // a save found the vault file changed on disk: copy / overwrite / back
    CloseConfirm,  // q with unsaved changes: save and lock / discard and lock / cancel
    Settings,      // how changes are saved (Settings, kept in settings.json)
};
const char* tui_state_name(TuiState s) noexcept;

// Non-secret async progress phases shown on the status line (agenda §5.2).
enum class ProgressPhase : uint8_t {
    None, KdfStarted, KdfFinished, VmkUnwrap, PagesDecrypting, A2ontDecoding,
    RuntimeSealing, Ready, GenericFailure, Saving,
};

enum class MessageKind : uint8_t { None, Info, Success, Warning, Error };

// ---------------------------------------------------------------------------
// Render model: everything the renderer needs, nothing more. Metadata strings
// are raw UTF-8 from the vault (the renderer sanitizes every byte it draws).
// Secrets appear only as views into machine-owned SecureBuffers, valid until
// the next machine call: reveal_text (RevealSecret), FormField::reveal (the
// add/edit form's password fields while "show" is on) and pw_reveal (the
// master password being typed while "show" is on).
// ---------------------------------------------------------------------------
struct RenderRow {
    size_t ordinal = 0;  // 1-based position in the current view
    std::string name, remark, username, url, tags;
    uint8_t pw_bucket = 0;  // coarse length bucket, never the exact length
    uint8_t color = 0;      // 0 automatic, else 1..ENTRY_COLORS
    uint64_t created_at = 0, updated_at = 0;  // unix seconds
    bool selected = false;
};

struct FormField {
    const char* label = "";
    std::string value;        // non-secret fields only
    size_t caret = 0;         // byte offset into value
    size_t secret_chars = 0;  // secret fields: typed code points (mask)
    // Secret fields while "show" is on: a view into the machine's editor
    // (valid until the next machine call). Empty otherwise.
    ByteView reveal;
    bool secret = false;
    bool required = false;
    int color = -1;  // the Color field: 0 Auto, 1..ENTRY_COLORS; -1 any other
};

// Pick events beyond the form's fields: the Color field's arrows (a click
// does what Left and Right do on the focused field).
constexpr int32_t PICK_COLOR_PREV = 100;
constexpr int32_t PICK_COLOR_NEXT = 101;

struct RenderModel {
    TuiState state = TuiState::Locked;
    uint64_t now_ms = 0;  // monotonic; drives countdowns and animation
    std::string conflict_copy;  // SaveConflict: the file name a copy would get

    // Vault (non-secret header facts).
    std::string vault_name;
    bool vault_open = false;
    bool create_mode = false;
    bool dirty = false;
    size_t entry_total = 0;
    uint64_t epoch = 0;
    uint32_t kdf_profile = 0;
    uint32_t aead_profile = 0;
    std::string create_kdf_label;

    // Entry list: only the visible window [view_top, view_top + rows.size())
    // of the current view is materialized.
    std::vector<RenderRow> rows;
    size_t view_total = 0;
    size_t view_top = 0;
    size_t selected = 0;      // index within the view
    std::string filter;       // active query ("" = none)
    bool details_open = false;    // details sheet (Enter) over the list
    bool live_search = false;     // the list follows the search as you type
    uint64_t wall_now_s = 0;      // wall clock, for "updated 2d ago"

    // Prompts.
    size_t pw_chars = 0;      // Locked: typed master-password characters
    // Locked, while "show" is on: the master password being typed (a view
    // into the machine's editor, valid until the next machine call). Empty
    // otherwise.
    ByteView pw_reveal;
    bool pw_revealed = false;
    uint64_t pw_reveal_remaining_ms = 0;
    bool confirm_stage = false;
    bool caps_lock = false;
    std::string query_text;
    size_t query_caret = 0;

    // One status message (generic wording only for failures).
    std::string message;
    MessageKind message_kind = MessageKind::None;

    // Exposure.
    ByteView reveal_text;
    uint64_t reveal_remaining_ms = 0;
    uint64_t reveal_ttl_ms = 0;
    uint64_t clip_remaining_ms = 0;  // > 0 while the clipboard TTL runs
    uint64_t clip_ttl_ms = 0;

    // Busy (unlock / create).
    ProgressPhase phase = ProgressPhase::None;
    uint64_t busy_elapsed_ms = 0;

    // Add/Edit form.
    bool editing_existing = false;
    std::vector<FormField> form;
    size_t form_cursor = 0;
    int pw_match = -1;  // -1 nothing to compare, 0 mismatch, 1 match
    bool form_revealed = false;          // form passwords shown
    uint64_t form_reveal_remaining_ms = 0;

    bool from_launcher = false;  // opened from the start page (Esc goes back)

    // The user's settings (the header marks autosave; the Settings dialog
    // shows them with the focused item).
    Settings settings;
    size_t settings_cursor = 0;
};

// ---------------------------------------------------------------------------
// Configuration (times in ms; injected clock)
// ---------------------------------------------------------------------------
struct TuiConfig {
    const char* startup_note = nullptr;  // shown until the first key (not owned)
    uint64_t reveal_ttl_ms = 10 * 1000;
    uint64_t clipboard_ttl_ms = 20 * 1000;
    uint64_t idle_lock_ms = 300 * 1000;
    uint64_t reseal_interval_ms = 60 * 1000;
    uint64_t message_ttl_ms = 5 * 1000;   // success/info messages
    std::string create_kdf_label;         // shown when creating a vault
    bool from_launcher = false;           // Esc on the lock screen goes back
    Settings settings;                    // the user's (settings.json)
};

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------
class TuiMachine final {
  public:
    TuiMachine(std::string vault_path, Clipboard* clipboard, TuiConfig cfg);
    ~TuiMachine();
    TuiMachine(const TuiMachine&) = delete;
    TuiMachine& operator=(const TuiMachine&) = delete;

    // ---- inputs ----
    void on_key(const KeyEvent& k, uint64_t now_ms);
    void on_tick(uint64_t now_ms);
    // Async completion from the app shell's unlock worker.
    void on_unlock_result(Result<VaultSession>&& r, uint64_t now_ms);
    void on_progress(ProgressPhase p);
    // Wall-clock seconds for entry/vault timestamps (0 = unknown).
    void set_wall_clock(uint64_t unix_s) noexcept { wall_s_ = unix_s; }
    // How many list rows the current layout shows (paging, scrolling).
    void set_page_rows(size_t n);

    // ---- outputs ----
    const RenderModel& render_model();
    TuiState state() const noexcept { return state_; }
    bool wants_quit() const noexcept { return quit_; }
    // True while the shell must run the unlock worker (entered Unlocking).
    bool unlock_requested();
    // The password for the unlock worker (moved out once).
    SecureBuffer take_pending_password();
    // True once after Esc stopped an unlock: the shell stops waiting for its
    // worker (a vault on a stalled network drive can block the read for
    // minutes) and wipes the worker's result unread when it comes.
    bool take_unlock_canceled();
    bool create_mode() const noexcept { return create_mode_; }
    // The user's settings, as the Settings dialog left them.
    const Settings& settings() const noexcept { return cfg_.settings; }
    // True once after the user changed a setting: the shell writes it.
    bool take_settings_changed();
    // The shell could not write the settings file: they last this session.
    void on_settings_write_failed();
    // The file this window works on (after "save a copy", the copy).
    const std::string& vault_path() const noexcept { return path_; }
    // The terminal is going away (its window closed, the connection dropped,
    // the program asked to stop): nobody can be asked, so unsaved changes
    // are saved (to a copy if the vault changed on disk) or, if the user's
    // setting says so, discarded; then lock and quit. False if changes could
    // not be saved.
    bool on_hangup(uint64_t now_ms);

    // Test/diagnostic access (non-secret).
    size_t selected() const noexcept { return sel_; }
    bool clipboard_pending_clear() const noexcept { return clip_armed_; }
    VaultSession* session_for_test() { return session_.is_open() ? &session_ : nullptr; }

  private:
    // state handlers
    void key_locked(const KeyEvent& k, uint64_t now);
    void key_overview(const KeyEvent& k, uint64_t now);
    bool key_navigate(const KeyEvent& k);  // list movement; true if handled
    void key_query(const KeyEvent& k, uint64_t now);
    void key_form(const KeyEvent& k, uint64_t now);      // Add/Edit
    void key_delete_confirm(const KeyEvent& k, uint64_t now);
    void key_reveal(const KeyEvent& k, uint64_t now);
    void key_help_error(const KeyEvent& k);
    void key_save_conflict(const KeyEvent& k, uint64_t now);
    void key_close_confirm(const KeyEvent& k, uint64_t now);
    void key_settings(const KeyEvent& k, uint64_t now);
    bool pick_row(const KeyEvent& k);   // Code::Pick on the list

    void enter_state(TuiState s, uint64_t now);
    void hide_reveal();                 // wipe + leave RevealSecret
    void hide_password() noexcept;      // the prompt's "show" off
    void step_color(bool next) noexcept;  // the form's Color, Auto included
    // Says once that a save moved an older vault file to the current format.
    void note_format_upgrade();
    void reset_form();                  // wipe editors
    Status commit_form(uint64_t now);
    void do_copy(bool username, uint64_t now);
    void paste_clipboard(uint64_t now);  // Ctrl+V into the focused field
    void do_save(uint64_t now);
    // Saves this window's version next to the vault (conflict_path_, or the
    // next free name) and continues there.
    Status save_copy();
    // Unsaved changes when nobody can be asked (before the idle lock, on
    // hangup): saved (to a copy when the vault changed on disk, or could not
    // be saved in place: CopiedInstead), or dropped if the user's setting
    // says so.
    // Rekeyed: not saved, the vault's password was changed elsewhere.
    enum class Kept : uint8_t { Nothing, Saved, Copied, CopiedInstead, Discarded, Failed, Rekeyed };
    Kept keep_changes();
    // CloseConfirm's "save and lock" (a changed vault asks first).
    void close_saving(uint64_t now);
    // SaveMode::Auto: saves the change just made. Off: not in that mode (or
    // nothing to save); Asked: the vault changed on disk, SaveConflict is up.
    enum class AutoSaved : uint8_t { Off, Saved, Asked, Failed, Rekeyed };
    AutoSaved autosave(uint64_t now);
    void lock_session(uint64_t now);
    void refresh_rows();
    void preview_query();               // live search while Query is open
    bool live_search() const;
    void ensure_visible();
    void set_error();                   // generic message only
    void say(MessageKind kind, const char* text);
    uint64_t record_time() const noexcept;

    std::string path_;
    std::string conflict_path_;         // SaveConflict: where a copy goes
    bool close_after_save_ = false;     // SaveConflict came from "save and lock"
    Clipboard* clipboard_;
    TuiConfig cfg_;
    TuiState state_ = TuiState::Locked;
    bool quit_ = false;
    bool create_mode_ = false;          // Locked prompt creates a new vault
    ProgressPhase phase_ = ProgressPhase::None;
    uint64_t now_ = 0;
    uint64_t wall_s_ = 0;
    uint64_t busy_since_ = 0;
    bool caps_lock_ = false;

    VaultSession session_;
    uint32_t opened_version_ = 0;       // the file's SEIS-CANON revision when opened
    std::vector<size_t> view_;          // indices shown (query filter/all)
    size_t sel_ = 0;
    size_t top_ = 0;                    // first visible view row
    size_t page_ = 10;                  // visible list rows

    // Locked-state password entry (and confirmation for create mode).
    SecretLineEdit pw_edit_{true};
    SecretLineEdit pw_confirm_{true};
    bool confirm_stage_ = false;
    // "Show" for the master password being typed: on until toggled off, the
    // prompt changes (Enter, Esc, the confirm step, any state change), or
    // reveal_ttl_ms passes without typing.
    bool pw_reveal_ = false;
    uint64_t pw_reveal_deadline_ = 0;
    bool unlock_requested_ = false;
    bool unlock_canceled_ = false;
    SecureBuffer pending_password_;

    size_t settings_cursor_ = 0;        // Settings: the focused item
    bool settings_changed_ = false;

    // Query input (metadata search — non-secret by scope, still wiped).
    LineEdit query_edit_{128};
    // Live search: the last needle searched and its hits (a longer needle
    // that extends it searches only those), and a search still to run.
    std::string searched_;
    std::vector<size_t> searched_hits_;
    bool search_pending_ = false;
    std::string active_query_;
    bool details_open_ = false;
    // Live filtering re-queries every entry's metadata per keystroke; above
    // this size the search applies on Enter instead.
    static constexpr size_t LIVE_SEARCH_MAX = 5000;
    static constexpr size_t LIVE_SEARCH_INSTANT = 1000;  // ~18 ms per search

    // Add/Edit form. Field order: Name, Remark, Username, URL, Tags, Color,
    // Password, Confirm.
    std::vector<LineEdit> form_text_;   // non-secret fields
    uint8_t form_color_ = 0;            // 0 Auto, 1..ENTRY_COLORS
    SecretLineEdit form_pw_;
    SecretLineEdit form_pw2_;
    size_t form_cursor_ = 0;
    bool editing_existing_ = false;
    size_t edit_index_ = 0;
    // "Show" for the form's password fields: on until toggled off, the form
    // closes, or reveal_ttl_ms passes without typing in a password field.
    bool form_reveal_ = false;
    uint64_t form_reveal_deadline_ = 0;

    // Reveal / clipboard TTL tracking.
    SecureBuffer reveal_buf_;
    uint64_t reveal_deadline_ = 0;
    bool clip_armed_ = false;
    uint64_t clip_deadline_ = 0;
    bool clip_busy_ = false;  // a clear found the clipboard busy: retried each second

    // Status message: cleared by the next key, or at its deadline.
    std::string msg_;
    MessageKind msg_kind_ = MessageKind::None;
    uint64_t msg_deadline_ = 0;         // 0 = until the next key

    uint64_t last_activity_ = 0;
    uint64_t last_reseal_ = 0;

    RenderModel model_;
};

}  // namespace secraxis

#endif  // SECRAXIS_TUI_CORE_H
