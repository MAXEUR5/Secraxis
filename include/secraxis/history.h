// history.h — the start page's list of recently opened vaults, kept by the
// app in a small JSON file in its config directory (recent.json):
//
//   {
//     "version": 1,
//     "vaults": [
//       {"path": "D:\\Vaults\\personal.seis", "last_opened": 1767225600}
//     ]
//   }
//
// It records where vaults are and when they were last opened, nothing else.
// The parser is total and strict like every other parser in the project: a
// size cap, a depth of three, no unknown keys, integers only, well-formed
// UTF-8 strings without controls; anything else is rejected and the start page
// simply begins with an empty list.
#ifndef SECRAXIS_HISTORY_H
#define SECRAXIS_HISTORY_H

#include <cstdint>
#include <string>
#include <vector>

#include "secraxis/common.h"

namespace secraxis {

struct RecentVault {
    std::string path;          // absolute, UTF-8
    uint64_t last_opened = 0;  // unix seconds
    bool missing = false;      // not stored: set when the file is not found
};

constexpr size_t HISTORY_MAX = 12;               // vaults kept
constexpr size_t HISTORY_FILE_MAX = 64 * 1024;   // bytes accepted
constexpr size_t HISTORY_PATH_MAX = 4096;        // bytes per path

// Strict parse. False (and *out empty) on any deviation.
bool parse_history(ByteView json, std::vector<RecentVault>* out);
std::string serialize_history(const std::vector<RecentVault>& vaults);

// Move `path` to the front with `now` (deduplicated; case-insensitive when
// `fold_case`, as on Windows), keeping at most HISTORY_MAX entries.
void history_touch(std::vector<RecentVault>* v, const std::string& path, uint64_t now,
                   bool fold_case);
void history_forget(std::vector<RecentVault>* v, const std::string& path, bool fold_case);

}  // namespace secraxis

#endif  // SECRAXIS_HISTORY_H
