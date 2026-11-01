// app.cpp — the interactive shell: owns the Terminal, the start page
// (Launcher), the vault TuiMachine, the real clipboard, the recent-vaults
// file and the KDF worker thread. Keeps the render loop responsive while
// Argon2id runs (agenda §5.2): unlock/create runs on a worker thread; the UI
// thread only shows non-secret progress phases.
//
// Each loop iteration renders the model into a Canvas and lets ScreenWriter
// send only what changed, so an idle screen costs no output at all and a
// resize repaints cleanly. Clicks are resolved against the frame's hit zones
// into the same events keys produce.
#include "secraxis/app.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "secraxis/fs_atomic.h"
#include "secraxis/fs_dir.h"
#include "secraxis/history.h"
#include "secraxis/launcher.h"
#include "secraxis/renderer.h"
#include "secraxis/settings.h"
#include "secraxis/terminal.h"
#include "secraxis/tui_core.h"
#include "secraxis/vault_session.h"
#include "secraxis/version.h"

namespace secraxis {

// clipboard.cpp. clear_after_s: where a clipboard tool serves the copy from
// its own process, that process ends this long after the copy at the latest
// (0: no bound; the start page only reads the clipboard).
Clipboard* make_platform_clipboard(int clipboard_escapes, unsigned clear_after_s);

namespace {

#if defined(_WIN32)
constexpr bool kFoldCase = true;  // Windows paths compare case-insensitively
#else
constexpr bool kFoldCase = false;
#endif

// Monotonic milliseconds since an arbitrary epoch (injected into the machines).
uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint64_t wall_s() { return static_cast<uint64_t>(time(nullptr)); }

// Local time zone offset (seconds east of UTC), for timestamps.
int64_t local_utc_offset() {
    const time_t now = time(nullptr);
    struct tm lt, gt;
#if defined(_WIN32)
    if (localtime_s(&lt, &now) != 0 || gmtime_s(&gt, &now) != 0) return 0;
#else
    if (localtime_r(&now, &lt) == nullptr || gmtime_r(&now, &gt) == nullptr) return 0;
#endif
    int64_t days = lt.tm_yday - gt.tm_yday;
    if (lt.tm_year != gt.tm_year) days = lt.tm_year > gt.tm_year ? 1 : -1;
    return days * 86400 + (lt.tm_hour - gt.tm_hour) * 3600 + (lt.tm_min - gt.tm_min) * 60;
}

std::string kdf_label(KdfProfileId id) {
    const KdfProfile* p = kdf_profile_by_id(static_cast<uint32_t>(id));
    if (p == nullptr) return "Argon2id";
    const char* name = id == KdfProfileId::Floor    ? "Floor"
                       : id == KdfProfileId::Strong ? "Strong"
                                                    : "Default";
    char buf[96];
    std::snprintf(buf, sizeof(buf), "Argon2id %s, %u MiB, t=%u, p=%u", name, p->memory_mib,
                  p->iterations, p->lanes);
    return buf;
}

// Runs create-or-unlock off the UI thread. The password buffer is moved in
// and wiped when done. Esc abandons a run (a vault on a stalled network
// drive can block the read for minutes): the thread then finishes on its
// own, skipping the KDF and any write if it can, and wipes its result
// unread.
class UnlockWorker {
  public:
    UnlockWorker() = default;
    UnlockWorker(const UnlockWorker&) = delete;
    UnlockWorker& operator=(const UnlockWorker&) = delete;
    ~UnlockWorker() { abandon(); }

    void start(bool create_mode, const std::string& path, SecureBuffer&& password,
               const CreateParams& create_params) {
        job_ = std::make_shared<Job>();
        running_.fetch_add(1);
        th_ = std::thread([job = job_, create_mode, path,
                           pw = static_cast<SecureBuffer&&>(password), create_params]() mutable {
            Result<VaultSession> r = Result<VaultSession>::failure(Err::Internal);
            if (create_mode) {
                CreateParams p = create_params;
                p.path = path;
                p.cancel = &job->canceled;
                r = VaultSession::create_new(p, pw.view());
            } else {
                r = VaultSession::unlock(path, pw.view(), &job->canceled);
            }
            pw.reset();
            job->result = static_cast<Result<VaultSession>&&>(r);
            job->done.store(true);
            // An abandoned job ends (and its session is wiped) here, before
            // the count says this thread is through with secrets.
            job.reset();
            running_.fetch_sub(1);
        });
    }
    bool active() const { return job_ != nullptr; }
    bool done() const { return job_ != nullptr && job_->done.load(); }
    Result<VaultSession> take() {
        th_.join();
        Result<VaultSession> r = static_cast<Result<VaultSession>&&>(job_->result);
        job_.reset();
        return r;
    }
    void abandon() {
        if (job_ == nullptr) return;
        job_->canceled.store(true);
        th_.detach();
        job_.reset();
    }
    // Runs not finished yet, abandoned ones included.
    static int running() { return running_.load(); }

  private:
    struct Job {
        std::atomic<bool> done{false};
        std::atomic<bool> canceled{false};
        Result<VaultSession> result = Result<VaultSession>::failure(Err::Internal);
    };
    std::shared_ptr<Job> job_;
    std::thread th_;
    static std::atomic<int> running_;
};
std::atomic<int> UnlockWorker::running_{0};

// The settings file (settings.h), next to the recent-vaults file. Read once;
// rewritten atomically on every change.
class SettingsFile {
  public:
    SettingsFile() {
        const std::string dir = config_directory();
        if (dir.empty()) return;
        dir_ = dir;
#if defined(_WIN32)
        file_ = dir + "\\settings.json";
#else
        file_ = dir + "/settings.json";
#endif
        if (file_exists(file_)) {
            Result<Bytes> r = read_file(file_, SETTINGS_FILE_MAX);
            if (r.ok()) parse_settings(ByteView(r.value), &s_);
        }
    }
    const Settings& get() const { return s_; }
    // False if the file could not be written (the settings still apply).
    bool set(const Settings& s) {
        s_ = s;
        if (file_.empty() || !make_directories(dir_)) return false;
        const std::string body = serialize_settings(s_);
        return write_file_atomic(file_, ByteView(body.data(), body.size())).ok();
    }

  private:
    std::string dir_, file_;
    Settings s_;
};

// The recent-vaults file (history.h): read once, rewritten atomically on
// every change, in an owner-only config directory.
class History {
  public:
    explicit History(bool enabled) : enabled_(enabled) {
        const std::string dir = config_directory();
        if (!dir.empty()) {
            dir_ = dir;
#if defined(_WIN32)
            file_ = dir + "\\recent.json";
#else
            file_ = dir + "/recent.json";
#endif
        }
        if (enabled_ && !file_.empty() && file_exists(file_)) {
            Result<Bytes> r = read_file(file_, HISTORY_FILE_MAX);
            if (r.ok()) parse_history(ByteView(r.value), &v_);
        }
    }
    bool enabled() const { return enabled_ && !file_.empty(); }
    const std::string& file() const { return file_; }

    // The list, with files that are gone marked.
    std::vector<RecentVault> list() const {
        std::vector<RecentVault> out = enabled() ? v_ : std::vector<RecentVault>();
        for (RecentVault& r : out) r.missing = !file_exists(r.path);
        return out;
    }
    void touch(const std::string& path) {
        if (!enabled()) return;
        history_touch(&v_, path, wall_s(), kFoldCase);
        save();
    }
    void forget(const std::string& path) {
        if (!enabled()) return;
        history_forget(&v_, path, kFoldCase);
        save();
    }

  private:
    void save() {
        if (!make_directories(dir_)) return;
        const std::string body = serialize_history(v_);
        (void)write_file_atomic(file_, ByteView(body.data(), body.size()));
    }
    bool enabled_;
    std::string dir_, file_;
    std::vector<RecentVault> v_;
};

// Everything one terminal screen needs, shared by the start page and vaults.
struct Screen {
    Terminal& term;
    RenderEnv env;
    Canvas canvas;
    ScreenWriter writer;
    WipeBuffer out;
    TermSize last{0, 0};
    const char* note = nullptr;  // the probe's look note, for the first screen

    explicit Screen(Terminal& t) : term(t) {
        env.caps = t.caps();
        env.utc_offset_s = local_utc_offset();
        note = env.caps.look_note;
    }
    const char* take_note() {
        const char* n = note;
        note = nullptr;
        return n;
    }
    TermSize size() {
        const TermSize sz = term.size();
        if (term.take_resize() || sz.cols != last.cols || sz.rows != last.rows) {
            writer.invalidate();
            last = sz;
        }
        return sz;
    }
    void present() {
        writer.diff(canvas, env.caps.color, env.caps.sync_output, &out);
        term.write(out);
        out.clear();
    }
    void wipe() {
        canvas.clear();
        writer.clear();
        out.release();
    }
};

// Input events handled between two frames, at most.
constexpr int kInputBatch = 4096;

// Turns raw pointer events into the events a click stands for. A second
// click on the same list row within 450 ms adds Enter (double-click opens);
// form fields are never opened that way (Enter there would commit the form).
class Pointer {
  public:
    // Fills `out` with up to two events; returns how many.
    int resolve(const KeyEvent& raw, const RenderResult& frame, uint64_t now, KeyEvent out[2]) {
        if (raw.pointer != KeyEvent::Pointer::Press || raw.button != 0) return 0;
        KeyEvent ev;
        bool opens = false;
        if (!hit_test(frame, raw.x, raw.y, &ev, &opens)) return 0;
        out[0] = ev;
        if (ev.code == KeyEvent::Code::Pick && opens) {
            const bool twice = have_last_ && last_arg_ == ev.arg && now - last_ms_ < 450;
            have_last_ = !twice;
            last_arg_ = ev.arg;
            last_ms_ = now;
            if (twice) {
                out[1] = KeyEvent::key(KeyEvent::Code::Enter);
                return 2;
            }
        } else {
            have_last_ = false;
        }
        return 1;
    }

  private:
    bool have_last_ = false;
    int32_t last_arg_ = 0;
    uint64_t last_ms_ = 0;
};

bool is_wheel(const KeyEvent& k) {
    return k.pointer == KeyEvent::Pointer::WheelUp || k.pointer == KeyEvent::Pointer::WheelDown;
}

KeyEvent wheel_key(const KeyEvent& raw) {
    return KeyEvent::key(raw.pointer == KeyEvent::Pointer::WheelUp ? KeyEvent::Code::Up
                                                                   : KeyEvent::Code::Down);
}

bool is_ctrl_l(const KeyEvent& k) {
    return k.code == KeyEvent::Code::Char && (k.mods & KEYMOD_CTRL) && k.cp == U'l';
}

// One vault, from the lock screen until the user leaves it (Esc on the lock
// screen). Returns whether it was ever open. Records the vault in the
// history once it is open, and again whenever a save went to a copy beside
// it (the vault had changed on disk, or could not be written): the start
// page then lists where the work is, also after a hangup nobody saw. After
// such a copy the window works on it (machine.vault_path()), so unlocking
// again opens the copy, not the file the window started with.
bool run_vault(Screen& s, const std::string& path, KdfProfileId kdf, bool from_launcher,
               History* history, SettingsFile* settings) {
    // Declared before the machine so it outlives the machine's destructor,
    // which clears the clipboard if it still holds our copy.
    TuiConfig cfg;
    // The copy's own server ends 5 s after the machine's clear at the latest,
    // even if this program does not live to clear it.
    std::unique_ptr<Clipboard> clip(make_platform_clipboard(
        s.env.caps.clipboard_escapes, static_cast<unsigned>(cfg.clipboard_ttl_ms / 1000 + 5)));
    cfg.create_kdf_label = kdf_label(kdf);
    cfg.from_launcher = from_launcher;
    cfg.startup_note = s.take_note();
    cfg.settings = settings->get();
    TuiMachine machine(path, clip.get(), cfg);
    UnlockWorker worker;
    std::string recorded;  // the vault last recorded in the history
    auto record = [&]() {
        if (history == nullptr || recorded == machine.vault_path()) return;
        history->touch(machine.vault_path());
        recorded = machine.vault_path();
    };
    CreateParams cp;
    cp.kdf = kdf;
    cp.a2ont = A2ontProfileId::Default;
    Pointer pointer;
    RenderResult frame;
    size_t page_rows = 0;
    KeyEvent deferred;  // a click held for the frame it can be aimed at
    bool have_deferred = false;
    RenderResult deferred_seen;                  // the frame on screen when it was made
    TuiState deferred_state = TuiState::Locked;  // and the state that frame showed
    s.writer.invalidate();

    while (!machine.wants_quit() && !Terminal::hangup()) {
        machine.set_wall_clock(wall_s());
        const TermSize sz = s.size();
        frame = render(machine.render_model(), s.env, sz.cols, sz.rows, &s.canvas);
        if (frame.list_rows > 0 && frame.list_rows != page_rows) {
            // The layout changed how many entries fit: page and scroll by that.
            page_rows = frame.list_rows;
            machine.set_page_rows(page_rows);
            frame = render(machine.render_model(), s.env, sz.cols, sz.rows, &s.canvas);
        }
        s.present();
        const TuiState shown = machine.state();
        // A click held back (below) acts only if it means here what it meant
        // on the frame the user clicked; else it is dropped.
        if (have_deferred && (shown != deferred_state ||
                              !same_click_meaning(deferred_seen, frame, deferred.x, deferred.y)))
            have_deferred = false;

        if (!worker.active() && machine.unlock_requested()) {
            cp.now_unix = wall_s();
            worker.start(machine.create_mode(), machine.vault_path(),
                         machine.take_pending_password(), cp);
            machine.on_progress(ProgressPhase::KdfStarted);
        }

        // Everything already typed or pasted is handled before the next frame
        // (a paste costs one frame, not one per character). A click acts only
        // on what the user saw: after other input in the same batch (which
        // may have changed the screen, opened a dialog even) it waits for the
        // next frame, and acts there only if it means the same as on the
        // frame it was made on. A click ends the batch.
        KeyEvent k;
        int budget = kInputBatch;
        int handled = 0;
        bool more = have_deferred || s.term.read_key(&k, 50);
        if (have_deferred) k = deferred;
        have_deferred = false;
        while (more) {
            const uint64_t t = now_ms();
            const TuiState before = machine.state();
            bool clicked = false;
            if (is_ctrl_l(k)) {
                s.writer.invalidate();  // Ctrl+L: repaint everything
            } else if (k.code == KeyEvent::Code::Mouse) {
                if (is_wheel(k)) {
                    const TuiState st = machine.state();
                    if (st == TuiState::Overview || st == TuiState::Query ||
                        st == TuiState::CopySecret)
                        for (int n = 0; n < 3; ++n) machine.on_key(wheel_key(k), t);
                } else if (handled > 0) {
                    deferred = k;
                    deferred_seen = frame;
                    deferred_state = shown;
                    have_deferred = true;
                    break;
                } else {
                    KeyEvent evs[2];
                    const int n = pointer.resolve(k, frame, t, evs);
                    for (int q = 0; q < n; ++q) machine.on_key(evs[q], t);
                    clicked = true;
                }
            } else {
                machine.on_key(k, t);
            }
            ++handled;
            // Unsaved changes are about to be kept or dropped: what was typed
            // ahead, before that question was on screen, must not answer it.
            if (before != TuiState::CloseConfirm && machine.state() == TuiState::CloseConfirm) {
                KeyEvent ahead;
                for (int n = 0; n < kInputBatch && s.term.read_key(&ahead, 0); ++n) {
                }
                break;
            }
            // (unlock_requested() consumes the request: the loop top takes it.)
            if (clicked || machine.state() == TuiState::Unlocking || machine.wants_quit() ||
                --budget == 0)
                break;
            more = s.term.read_key(&k, 0);
        }
        // Esc while unlocking: stop waiting for the worker. Its result is
        // taken only after the input, so an Esc pressed while the screen said
        // "unlocking" always cancels; it never becomes, should the worker
        // finish meanwhile, an Esc on the lock screen (leave).
        if (machine.take_unlock_canceled()) worker.abandon();
        if (worker.done()) {
            machine.on_unlock_result(worker.take(), now_ms());
            if (machine.state() == TuiState::Overview) record();
        }
        if (!recorded.empty()) record();  // a save may have gone to a copy
        if (machine.take_settings_changed() && !settings->set(machine.settings()))
            machine.on_settings_write_failed();
        machine.on_tick(now_ms());
    }
    // Never wait here for a run that may be stuck on a stalled drive.
    worker.abandon();
    // The terminal is going away (or the program was asked to stop): keep
    // the user's work, then lock (the machine's destructor clears the
    // clipboard if it still holds our copy).
    if (Terminal::hangup()) {
        machine.set_wall_clock(wall_s());
        machine.on_hangup(now_ms());
    }
    if (!recorded.empty()) record();  // the idle lock or the hangup may have made a copy
    return !recorded.empty();
}

// The folder that would hold `path` ("C:\" for a file at a drive root).
std::string folder_of(const std::string& path) {
    const size_t cut = path.find_last_of("\\/");
    if (cut == std::string::npos) return "";
    if (cut == 0) return path.substr(0, 1);
    if (cut == 2 && path.size() > 2 && path[1] == ':') return path.substr(0, 3);
    return path.substr(0, cut);
}

int run_launcher(Screen& s, History& history, SettingsFile& settings) {
    LauncherConfig lc;
    lc.home_dir = home_directory();
    lc.start_dir = documents_directory();
    lc.history_enabled = history.enabled();
    lc.history_file = history.file();
    lc.version = SECRAXIS_VERSION;
    lc.tip_seed = wall_s() / 3600;
    std::unique_ptr<Clipboard> clip(make_platform_clipboard(s.env.caps.clipboard_escapes, 0));
    lc.clipboard = clip.get();
    lc.startup_note = s.take_note();
    Launcher launcher(history.list(), lc);
    Pointer pointer;
    RenderResult frame;
    size_t page_rows = 0;
    KeyEvent deferred;  // a click held for the frame it can be aimed at
    bool have_deferred = false;
    RenderResult deferred_seen;  // the frame on screen when it was made
    LauncherScreen deferred_screen = LauncherScreen::Home;
    s.writer.invalidate();

    for (;;) {
        if (Terminal::hangup()) return 0;
        launcher.set_wall_clock(wall_s());
        const TermSize sz = s.size();
        frame = render_launcher(launcher.model(), s.env, sz.cols, sz.rows, &s.canvas);
        if (frame.list_rows > 0 && frame.list_rows != page_rows) {
            page_rows = frame.list_rows;
            launcher.set_page_rows(page_rows);
            frame = render_launcher(launcher.model(), s.env, sz.cols, sz.rows, &s.canvas);
        }
        s.present();
        const LauncherScreen shown = launcher.screen();
        if (have_deferred && (shown != deferred_screen ||
                              !same_click_meaning(deferred_seen, frame, deferred.x, deferred.y)))
            have_deferred = false;

        const LauncherRequest req = launcher.take_request();
        switch (req.kind) {
            case LauncherRequest::Kind::None:
                break;
            case LauncherRequest::Kind::Quit:
                return 0;
            case LauncherRequest::Kind::List: {
                // "" is the drives on Windows; everything else is normalized
                // (typed paths may be relative or contain "..").
                std::string dir = req.path;
#if defined(_WIN32)
                if (!dir.empty()) dir = absolute_path(dir);
                const bool ok = (dir.empty() && !req.path.empty()) ? false
                                                                   : true;
#else
                dir = absolute_path(dir.empty() ? std::string("/") : dir);
                const bool ok = !dir.empty();
#endif
                std::vector<DirEntry> entries;
                const bool listed = ok && list_directory(dir, &entries);
                launcher.on_listing(dir, static_cast<std::vector<DirEntry>&&>(entries), listed);
                continue;  // show the folder right away
            }
            case LauncherRequest::Kind::Forget:
                history.forget(req.path);
                break;
            case LauncherRequest::Kind::Open: {
                const std::string p = absolute_path(req.path);
                if (p.empty() || !file_exists(p) || is_directory(p)) {
                    launcher.say(MessageKind::Error, "That vault file is not there.");
                    launcher.set_recent(history.list());
                    break;
                }
                // Only a vault that was open can have changed the list. (One
                // that never opened may sit on a stalled drive: the list's
                // check of every file would wait on it too.)
                if (run_vault(s, p, KdfProfileId::Default, true, &history, &settings))
                    launcher.set_recent(history.list());
                launcher.show_home();
                s.writer.invalidate();
                continue;
            }
            case LauncherRequest::Kind::Create: {
                const std::string p = absolute_path(req.path);
                const std::string folder = folder_of(p);
                if (p.empty() || folder.empty() || !is_directory(folder)) {
                    launcher.say(MessageKind::Error, "That folder does not exist.");
                    break;
                }
                if (file_exists(p)) {
                    launcher.say(MessageKind::Error,
                                 "A file with that name is already there. Pick another name.");
                    break;
                }
                if (run_vault(s, p, req.kdf, true, &history, &settings))
                    launcher.set_recent(history.list());
                launcher.show_home();
                s.writer.invalidate();
                continue;
            }
        }

        // As in run_vault: a click acts only on what the user saw.
        KeyEvent k;
        int budget = kInputBatch;
        int handled = 0;
        bool more = have_deferred || s.term.read_key(&k, 50);
        if (have_deferred) k = deferred;
        have_deferred = false;
        while (more) {
            const uint64_t t = now_ms();
            if (is_ctrl_l(k)) {
                s.writer.invalidate();
            } else if (k.code == KeyEvent::Code::Mouse) {
                if (is_wheel(k)) {
                    if (launcher.screen() == LauncherScreen::Home ||
                        launcher.screen() == LauncherScreen::Browse)
                        for (int n = 0; n < 3; ++n) launcher.on_key(wheel_key(k), t);
                } else if (handled > 0) {
                    deferred = k;
                    deferred_seen = frame;
                    deferred_screen = shown;
                    have_deferred = true;
                    break;
                } else {
                    KeyEvent evs[2];
                    const int n = pointer.resolve(k, frame, t, evs);
                    for (int q = 0; q < n; ++q) launcher.on_key(evs[q], t);
                    break;
                }
            } else {
                launcher.on_key(k, t);
            }
            ++handled;
            // A request (open, list, create, quit) is served before more input.
            if (launcher.has_request() || --budget == 0) break;
            more = s.term.read_key(&k, 0);
        }
        launcher.on_tick(now_ms());
    }
}

}  // namespace

int run_app(const std::string& vault_path, KdfProfileId kdf_profile, const UiOptions& ui) {
    int rc = 0;
    {
        TerminalOptions topt;
        topt.force_ascii = ui.force_ascii;
        topt.no_color = ui.no_color;
        topt.theme = ui.theme;
        topt.glyphs = ui.glyphs;
        topt.mouse = !ui.no_mouse;
        topt.keep_font = ui.keep_font;
        Terminal term(topt);
        if (!term.ok()) {
            std::fprintf(stderr, "%s\n", term.error());
            return 2;
        }
        History history(!ui.no_history);
        SettingsFile settings;
        Screen s(term);
        if (!vault_path.empty()) {
            const std::string abs = absolute_path(vault_path);
            (void)run_vault(s, abs.empty() ? vault_path : abs, kdf_profile, false, &history,
                            &settings);
        } else {
            rc = run_launcher(s, history, settings);
        }
        s.wipe();
    }
    // Stopped by a signal or the console closing: the work is saved and the
    // terminal restored by now; end the way that request ends a program.
    Terminal::finish_hangup();
    // An unlock abandoned with Esc may still be running. Give it a moment to
    // finish and wipe what it holds; one still blocked (a stalled drive) ends
    // with the process, without exit-time cleanup running under its feet.
    for (int i = 0; i < 40 && UnlockWorker::running() > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (UnlockWorker::running() > 0) {
        std::fflush(nullptr);
        std::_Exit(rc);
    }
    return rc;
}

}  // namespace secraxis
