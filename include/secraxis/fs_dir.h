// fs_dir.h — directory helpers for the start page: listing, absolute paths,
// the well-known folders, and the app's config directory. All paths are UTF-8
// (like fs_atomic); Windows converts to UTF-16 internally.
#ifndef SECRAXIS_FS_DIR_H
#define SECRAXIS_FS_DIR_H

#include <string>
#include <vector>

namespace secraxis {

struct DirEntry {
    std::string name;    // UTF-8; for drives "C:\"
    bool dir = false;
    bool vault = false;  // a *.seis file
};

// Absolute, normalized form of `path` (it need not exist). "" on failure.
std::string absolute_path(const std::string& utf8_path);
bool is_directory(const std::string& utf8_path);

// Subdirectories and *.seis files of `dir` (hidden and system entries
// skipped), directories first, each group sorted case-insensitively, at most
// `cap` entries. On Windows, "" lists the drives. False if `dir` cannot be
// read.
bool list_directory(const std::string& utf8_dir, std::vector<DirEntry>* out,
                    size_t cap = 4000);

std::string home_directory();
std::string documents_directory();  // the user's Documents, else home
// Where the app keeps its own files: %APPDATA%\Secraxis,
// ~/Library/Application Support/Secraxis, or $XDG_CONFIG_HOME/secraxis
// (~/.config/secraxis). SECRAXIS_CONFIG_DIR overrides. "" if unknown.
std::string config_directory();
// mkdir -p, owner-only on POSIX. True if the directory exists afterwards.
bool make_directories(const std::string& utf8_dir);

}  // namespace secraxis

#endif  // SECRAXIS_FS_DIR_H
