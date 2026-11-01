// launcher.h — the start page shown when Secraxis runs without a vault path.
//
// Pure logic like TuiMachine: keys, ticks and directory listings go in; a
// LauncherModel and requests come out. The app does every piece of IO (the
// history file, directory listings, checking files, opening vaults), so the
// page is fully testable without a terminal or a file system.
//
// Screens:
//   Home      the logo, the recent vaults (Enter opens), New / Open
//   Browse    a folder browser: type to filter, Enter descends or opens a
//             vault; typing a path (or ~) and Enter goes there; in "choose a
//             folder" mode it picks the folder for a new vault
//   NewVault  name, folder, key-derivation profile, Create
//   Help      shortcuts
#ifndef SECRAXIS_LAUNCHER_H
#define SECRAXIS_LAUNCHER_H

#include <string>
#include <vector>

#include "secraxis/crypto_profile.h"
#include "secraxis/fs_dir.h"
#include "secraxis/history.h"
#include "secraxis/tui_core.h"

namespace secraxis {

enum class LauncherScreen : uint8_t { Home, Browse, NewVault, Help };

struct LauncherRequest {
    enum class Kind : uint8_t { None, Open, Create, List, Forget, Quit };
    Kind kind = Kind::None;
    std::string path;  // Open/Create/Forget: a vault file; List: a folder
    KdfProfileId kdf = KdfProfileId::Default;  // Create
};

struct LauncherConfig {
#if defined(_WIN32)
    bool windows_paths = true;
#else
    bool windows_paths = false;
#endif
    std::string home_dir;        // what "~" means
    std::string start_dir;       // first folder for Open and New
    bool history_enabled = true;
    std::string history_file;    // shown on the page
    std::string version;
    uint64_t tip_seed = 0;       // picks the tip of the day
    uint64_t message_ttl_ms = 5 * 1000;
    Clipboard* clipboard = nullptr;  // Ctrl+V in text fields; not owned
    const char* startup_note = nullptr;  // shown until the first key (not owned)
};

struct BrowseRow {
    enum class Kind : uint8_t { Parent, UseFolder, Dir, Vault };
    Kind kind = Kind::Dir;
    std::string name;
    size_t index = 0;            // position in the full (filtered) list
    bool selected = false;
};

struct LauncherModel {
    LauncherScreen screen = LauncherScreen::Home;
    uint64_t now_ms = 0;
    uint64_t wall_now_s = 0;

    // Home.
    std::vector<RecentVault> recent;   // all of them (at most HISTORY_MAX)
    size_t recent_sel = 0;

    // Browse: the visible window of rows.
    std::string dir;                   // "" = the drives (Windows)
    bool windows_paths = false;
    bool pick_folder = false;
    std::vector<BrowseRow> rows;
    size_t rows_total = 0;
    size_t rows_top = 0;
    size_t row_sel = 0;
    std::string filter;
    size_t filter_caret = 0;

    // NewVault.
    std::string new_name;
    size_t new_name_caret = 0;
    std::string new_folder;
    size_t new_folder_caret = 0;
    KdfProfileId new_kdf = KdfProfileId::Default;
    size_t new_cursor = 0;             // 0 name, 1 folder, 2 profile, 3 create
    std::string new_path;              // what Create would make

    std::string message;
    MessageKind message_kind = MessageKind::None;

    std::string version;
    std::string tip;
    std::string history_file;
    bool history_enabled = true;
};

// Pick arguments the start page understands besides list rows.
constexpr int32_t LAUNCHER_PICK_FIELD = 1000;    // + field index (NewVault)
constexpr int32_t LAUNCHER_PICK_PROFILE = 1100;  // + 0 Floor, 1 Default, 2 Strong

// The tip of the day is one line under the logo widget: 66 cells minus "tip  ".
constexpr size_t LAUNCHER_TIP_MAX = 61;

class Launcher final {
  public:
    Launcher(std::vector<RecentVault> recent, LauncherConfig cfg);

    void on_key(const KeyEvent& k, uint64_t now_ms);
    void on_tick(uint64_t now_ms);
    // The app's answer to a List request.
    void on_listing(const std::string& dir, std::vector<DirEntry> entries, bool ok);
    void set_recent(std::vector<RecentVault> recent);
    void say(MessageKind kind, const char* text);
    void set_wall_clock(uint64_t unix_s) noexcept { wall_s_ = unix_s; }
    void set_page_rows(size_t n);
    void show_home() noexcept { screen_ = LauncherScreen::Home; }

    // The next request for the app (None if there is nothing to do).
    LauncherRequest take_request();
    bool has_request() const noexcept { return pending_.kind != LauncherRequest::Kind::None; }
    const LauncherModel& model();
    LauncherScreen screen() const noexcept { return screen_; }

    // Pure path helpers (exposed for tests).
    static std::string parent_of(const std::string& dir, bool windows);
    static std::string join(const std::string& dir, const std::string& name, bool windows);

  private:
    void key_home(const KeyEvent& k);
    void key_browse(const KeyEvent& k);
    void key_new(const KeyEvent& k);
    void paste_clipboard();  // Ctrl+V into the focused field
    void open_browser(const std::string& dir, bool pick_folder);
    void go(const std::string& dir);   // request a listing
    void rebuild_rows();
    void move(const KeyEvent& k, size_t count, size_t* sel, size_t* top);
    void activate_row();
    void submit_new();
    std::string typed_path() const;    // the filter as a path, or ""
    bool at_root() const;
    void request(LauncherRequest::Kind kind, std::string path);

    LauncherConfig cfg_;
    LauncherScreen screen_ = LauncherScreen::Home;
    LauncherScreen help_return_ = LauncherScreen::Home;
    uint64_t now_ = 0;
    uint64_t wall_s_ = 0;
    size_t page_ = 10;

    std::vector<RecentVault> recent_;
    size_t recent_sel_ = 0;
    size_t recent_top_ = 0;

    std::string dir_;
    bool listed_ = false;               // dir_ holds a successful listing
    bool pick_folder_ = false;
    std::vector<DirEntry> all_;
    std::vector<BrowseRow> view_;       // filtered rows (incl. Parent/UseFolder)
    size_t sel_ = 0;
    size_t top_ = 0;
    LineEdit filter_{256};
    std::string reselect_;              // name to select after going up

    LineEdit new_name_{200};
    LineEdit new_folder_{1024};
    KdfProfileId new_kdf_ = KdfProfileId::Default;
    size_t new_cursor_ = 0;

    std::string msg_;
    MessageKind msg_kind_ = MessageKind::None;
    uint64_t msg_deadline_ = 0;

    LauncherRequest pending_;
    LauncherModel model_;
};

}  // namespace secraxis

#endif  // SECRAXIS_LAUNCHER_H
