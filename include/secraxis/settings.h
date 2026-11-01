// settings.h — the user's preferences, kept by the app in a small JSON file
// in its config directory (settings.json, next to recent.json):
//
//   {
//     "version": 1,
//     "save": "manual",
//     "unattended": "save"
//   }
//
// "save": how changes reach the vault file. "manual": w / Ctrl+S, and
// locking with unsaved changes asks (save, discard, or cancel); "auto":
// every change is saved as it is made.
// "unattended": what happens to unsaved changes when nobody is there to ask,
// at the idle lock and when the terminal goes away: "save" them (to a copy
// next to the vault if it changed on disk) or "discard" them.
//
// The parser is strict like every other parser in the project: a size cap,
// known keys at most once each, the version required, values from a fixed
// set. A file it rejects means the defaults (and is replaced on the next
// change).
#ifndef SECRAXIS_SETTINGS_H
#define SECRAXIS_SETTINGS_H

#include <cstdint>
#include <string>

#include "secraxis/common.h"

namespace secraxis {

enum class SaveMode : uint8_t {
    Manual,  // w / Ctrl+S save; locking with unsaved changes asks first
    Auto,    // every change is saved as it is made
};

enum class Unattended : uint8_t {
    Save,     // the idle lock and a terminal going away save unsaved changes
    Discard,  // ... drop them: nothing is written without the user
};

struct Settings {
    SaveMode save = SaveMode::Manual;
    Unattended unattended = Unattended::Save;
    bool operator==(const Settings& o) const noexcept {
        return save == o.save && unattended == o.unattended;
    }
    bool operator!=(const Settings& o) const noexcept { return !(*this == o); }
};

constexpr size_t SETTINGS_FILE_MAX = 4096;  // bytes accepted

// Strict parse. False (and *out the defaults) on any deviation.
bool parse_settings(ByteView json, Settings* out);
std::string serialize_settings(const Settings& s);

}  // namespace secraxis

#endif  // SECRAXIS_SETTINGS_H
