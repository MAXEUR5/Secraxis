// app.h — entry point of the interactive TUI (src/tui/app.cpp).
#ifndef SECRAXIS_APP_H
#define SECRAXIS_APP_H

#include <string>

#include "secraxis/crypto_profile.h"

namespace secraxis {

struct UiOptions {
    bool force_ascii = false;  // ASCII chrome and ASCII-only text
    bool no_color = false;     // attributes only (NO_COLOR is honored too)
    int theme = 0;             // 0 auto, 1 dark, 2 light
    int glyphs = 0;            // 0 auto, 1 basic, 2 rich
    bool no_mouse = false;     // leave the mouse to the terminal (text selection)
    bool no_history = false;   // do not read or write the recent-vaults file
    bool keep_font = false;    // Windows console: never switch its font
};

// Opens `vault_path` (creating it when it does not exist), or the start page
// when it is empty. Returns the process exit code.
int run_app(const std::string& vault_path, KdfProfileId kdf_profile,
            const UiOptions& ui);

}  // namespace secraxis

#endif  // SECRAXIS_APP_H
