#include "secraxis/fs_dir.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <cwchar>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#else
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace secraxis {

namespace {

bool ends_with_seis(const std::string& n) {
    if (n.size() < 5) return false;
    std::string t = n.substr(n.size() - 5);
    for (char& ch : t)
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    return t == ".seis";
}

std::string lower_ascii(std::string s) {
    for (char& ch : s)
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    return s;
}

void sort_entries(std::vector<DirEntry>* v) {
    std::sort(v->begin(), v->end(), [](const DirEntry& a, const DirEntry& b) {
        if (a.dir != b.dir) return a.dir;
        const std::string la = lower_ascii(a.name), lb = lower_ascii(b.name);
        return la != lb ? la < lb : a.name < b.name;
    });
}

#if defined(_WIN32)
std::wstring widen(const std::string& s) {
    if (s.empty() || s.size() > 0x7FFFFFF) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string narrow(const wchar_t* w, size_t n) {
    if (n == 0 || n > 0x7FFFFFF) return std::string();
    const int len = WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n), nullptr, 0,
                                        nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(n), &s[0], len, nullptr, nullptr);
    return s;
}

std::string narrow(const std::wstring& w) { return narrow(w.data(), w.size()); }

std::string known_folder(int csidl) {
    wchar_t buf[MAX_PATH];
    if (SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buf) != S_OK) return "";
    return narrow(buf, std::wcslen(buf));
}
#endif

}  // namespace

std::string absolute_path(const std::string& utf8_path) {
    if (utf8_path.empty()) return "";
#if defined(_WIN32)
    const std::wstring w = widen(utf8_path);
    if (w.empty()) return "";
    const DWORD n = GetFullPathNameW(w.c_str(), 0, nullptr, nullptr);
    if (n == 0 || n > 32768) return "";
    std::wstring out(n, L'\0');
    const DWORD got = GetFullPathNameW(w.c_str(), n, &out[0], nullptr);
    if (got == 0 || got >= n) return "";
    out.resize(got);
    return narrow(out);
#else
    char resolved[PATH_MAX];
    if (realpath(utf8_path.c_str(), resolved) != nullptr) return resolved;
    // Not there yet: resolve the parent and append the name.
    std::string base = utf8_path;
    if (base[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == nullptr) return "";
        base = std::string(cwd) + "/" + utf8_path;
    }
    const size_t s = base.find_last_of('/');
    const std::string dir = s == 0 ? std::string("/") : base.substr(0, s);
    const std::string name = base.substr(s + 1);
    if (realpath(dir.c_str(), resolved) == nullptr) return base;
    std::string out = resolved;
    if (out.empty() || out.back() != '/') out += '/';
    return out + name;
#endif
}

bool is_directory(const std::string& utf8_path) {
#if defined(_WIN32)
    const std::wstring w = widen(utf8_path);
    if (w.empty()) return false;
    const DWORD a = GetFileAttributesW(w.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(utf8_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

bool list_directory(const std::string& utf8_dir, std::vector<DirEntry>* out, size_t cap) {
    out->clear();
#if defined(_WIN32)
    if (utf8_dir.empty()) {  // "This PC": the drives
        const DWORD mask = GetLogicalDrives();
        for (int k = 0; k < 26; ++k) {
            if (!(mask & (1u << k))) continue;
            DirEntry e;
            e.name = std::string(1, static_cast<char>('A' + k)) + ":\\";
            e.dir = true;
            out->push_back(e);
        }
        return true;
    }
    std::wstring pattern = widen(utf8_dir);
    if (pattern.empty()) return false;
    if (pattern.back() != L'\\' && pattern.back() != L'/') pattern += L'\\';
    pattern += L'*';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    do {
        const wchar_t* n = fd.cFileName;
        if (n[0] == L'.' && (n[1] == 0 || (n[1] == L'.' && n[2] == 0))) continue;
        if (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) continue;
        DirEntry e;
        e.name = narrow(n, std::wcslen(n));
        if (e.name.empty()) continue;
        e.dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        e.vault = !e.dir && ends_with_seis(e.name);
        if (!e.dir && !e.vault) continue;
        out->push_back(e);
    } while (out->size() < cap && FindNextFileW(h, &fd));
    FindClose(h);
#else
    DIR* d = opendir(utf8_dir.c_str());
    if (d == nullptr) return false;
    while (out->size() < cap) {
        struct dirent* de = readdir(d);
        if (de == nullptr) break;
        const std::string name = de->d_name;
        if (name.empty() || name[0] == '.') continue;  // hidden, ".", ".."
        std::string full = utf8_dir;
        if (full.empty() || full.back() != '/') full += '/';
        full += name;
        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;
        DirEntry e;
        e.name = name;
        e.dir = S_ISDIR(st.st_mode);
        e.vault = S_ISREG(st.st_mode) && ends_with_seis(name);
        if (!e.dir && !e.vault) continue;
        out->push_back(e);
    }
    closedir(d);
#endif
    sort_entries(out);
    return true;
}

std::string home_directory() {
#if defined(_WIN32)
    const std::string p = known_folder(CSIDL_PROFILE);
    return p.empty() ? std::string("C:\\") : p;
#else
    const char* h = std::getenv("HOME");
    return (h != nullptr && h[0] == '/') ? std::string(h) : std::string("/");
#endif
}

std::string documents_directory() {
#if defined(_WIN32)
    const std::string p = known_folder(CSIDL_PERSONAL);
    return p.empty() ? home_directory() : p;
#else
    const std::string d = home_directory() + "/Documents";
    return is_directory(d) ? d : home_directory();
#endif
}

std::string config_directory() {
    const char* over = std::getenv("SECRAXIS_CONFIG_DIR");
    if (over != nullptr && over[0] != '\0') return over;
#if defined(_WIN32)
    const std::string p = known_folder(CSIDL_APPDATA);
    return p.empty() ? std::string() : p + "\\Secraxis";
#elif defined(__APPLE__)
    return home_directory() + "/Library/Application Support/Secraxis";
#else
    const char* x = std::getenv("XDG_CONFIG_HOME");
    if (x != nullptr && x[0] == '/') return std::string(x) + "/secraxis";
    return home_directory() + "/.config/secraxis";
#endif
}

bool make_directories(const std::string& utf8_dir) {
    if (utf8_dir.empty()) return false;
    if (is_directory(utf8_dir)) return true;
    // Create each missing ancestor in turn.
    for (size_t i = 1; i <= utf8_dir.size(); ++i) {
        if (i < utf8_dir.size() && utf8_dir[i] != '/' && utf8_dir[i] != '\\') continue;
        const std::string part = utf8_dir.substr(0, i);
        if (part.empty() || is_directory(part)) continue;
#if defined(_WIN32)
        if (part.size() == 2 && part[1] == ':') continue;  // a drive
        const std::wstring w = widen(part);
        if (w.empty() || (!CreateDirectoryW(w.c_str(), nullptr) &&
                          GetLastError() != ERROR_ALREADY_EXISTS))
            return false;
#else
        if (mkdir(part.c_str(), 0700) != 0 && !is_directory(part)) return false;
#endif
    }
    return is_directory(utf8_dir);
}

}  // namespace secraxis
