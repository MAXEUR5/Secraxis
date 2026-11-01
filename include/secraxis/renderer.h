// renderer.h — draws a RenderModel (a vault) or a LauncherModel (the start
// page) into a Canvas (agenda §14.2/§14.3).
//
// Pure functions of (model, environment, size): no IO, so every layout is
// unit-testable without a terminal. The vault screen keeps the agenda's five
// regions — title line, status line, content, input line (the search bar),
// key-hint footer — and adapts to the window:
//   * wide (>= 100 cols, >= 16 rows): entry list + details pane
//   * standard / narrow: the list, with columns chosen to fit; Enter opens
//     the details as a sheet
//   * below 40x12: a "window too small" notice (nothing secret is drawn)
// Chrome uses the probe-verified glyph set (Terminal::probe), or the agenda's
// ASCII set when the terminal could not be verified. All vault text is
// sanitized by Canvas::text(); revealed secrets are drawn straight from the
// model's views (no intermediate copies).
//
// Every clickable thing is reported as a HitZone: the app turns a click into
// the zone's event (a key, or a Pick of a list row / form field).
#ifndef SECRAXIS_RENDERER_H
#define SECRAXIS_RENDERER_H

#include <cstdint>
#include <vector>

#include "secraxis/launcher.h"
#include "secraxis/tui_canvas.h"
#include "secraxis/tui_core.h"
#include "secraxis/tui_screen.h"

namespace secraxis {

struct RenderEnv {
    TermCaps caps;
    int64_t utc_offset_s = 0;  // local time zone, for timestamps
};

struct HitZone {
    Rect r;
    KeyEvent ev;
    bool opens = false;  // a list row: a double-click also presses Enter
};

struct RenderResult {
    size_t list_rows = 0;          // list rows the layout shows (feed to the machine)
    std::vector<HitZone> zones;    // later zones lie on top
};

// The event a click at cell (x, y) stands for, if any (and whether the zone
// is a list row that a double-click opens).
bool hit_test(const RenderResult& rr, int x, int y, KeyEvent* out, bool* opens = nullptr);

// Whether a click at cell (x, y) means the same on frame `now` as on frame
// `seen`: the same event there (or nothing in both). A click read after
// other input is handled only on the next frame, and only if this holds for
// the frame the user clicked; else it is dropped (it was aimed at something
// no longer there: a dialog that opened meanwhile is never answered by it).
bool same_click_meaning(const RenderResult& seen, const RenderResult& now, int x, int y);

constexpr int MIN_COLS = 40;
constexpr int MIN_ROWS = 12;

RenderResult render(const RenderModel& m, const RenderEnv& env, int cols, int rows,
                    Canvas* out);
RenderResult render_launcher(const LauncherModel& m, const RenderEnv& env, int cols, int rows,
                             Canvas* out);

}  // namespace secraxis

#endif  // SECRAXIS_RENDERER_H
