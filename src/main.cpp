// main.cpp — Secraxis Vault Manager entry point.
//
// Local-first TUI password vault. Master password is NEVER accepted via argv
// or environment (agenda §14.9) — only through the hidden in-TUI prompt.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

#include "secraxis/app.h"
#include "secraxis/crypto.h"
#include "secraxis/crypto_profile.h"
#include "secraxis/hardening.h"
#include "secraxis/version.h"

namespace secraxis {
// cli.cpp
int cli_validate(const std::string& path);
int cli_passwd(const std::string& path);
int cli_rekey(const std::string& path);
int cli_upgrade(const std::string& path, KdfProfileId profile);
int cli_import(const std::string& path, const std::string& infile, bool as_json);
int cli_export_plaintext(const std::string& path, const std::string& outfile,
                         bool as_json);
int cli_export_backup(const std::string& path, const std::string& outfile);
}

namespace {

void print_usage(const char* argv0) {
    std::printf(
        "Secraxis Vault Manager\n"
        "Usage:\n"
        "  %s [options]                                       start page (TUI)\n"
        "  %s [--kdf floor|default|strong] [options] <vault.seis>\n"
        "                                                     open/create (TUI)\n"
        "  %s validate <vault.seis>\n"
        "  %s passwd   <vault.seis>                           change master pw\n"
        "  %s rekey    <vault.seis>                           fresh VMK\n"
        "  %s upgrade  <vault.seis> --kdf floor|default|strong\n"
        "  %s import   <vault.seis> --csv|--json <infile>\n"
        "  %s backup   <vault.seis> <out.seis>                encrypted copy\n"
        "  %s export-plaintext <vault.seis> --csv|--json <outfile>   (UNSAFE)\n"
        "\n"
        "Options:\n"
        "  --ascii              ASCII-only drawing and text\n"
        "  --no-color           no colors (the NO_COLOR variable also works)\n"
        "  --theme dark|light   override the detected terminal background\n"
        "  --glyphs basic|rich  override the detected symbol set (rich needs a\n"
        "                       modern terminal font; --ascii forces plain ASCII)\n"
        "  --no-mouse           leave the mouse to the terminal (text selection)\n"
        "  --keep-font          Windows console: keep its font even when it draws\n"
        "                       symbols two cells wide (else Consolas, restored on exit)\n"
        "  --no-history         do not read or write the recent-vaults list\n"
        "  --version            print the version\n"
        "\n"
        "  The master password is only ever read from a hidden prompt,\n"
        "  never from arguments or the environment.\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

bool parse_kdf(const char* v, secraxis::KdfProfileId* out) {
    using secraxis::KdfProfileId;
    if (std::strcmp(v, "floor") == 0) { *out = KdfProfileId::Floor; return true; }
    if (std::strcmp(v, "default") == 0) { *out = KdfProfileId::Default; return true; }
    if (std::strcmp(v, "strong") == 0) { *out = KdfProfileId::Strong; return true; }
    return false;
}

#if defined(_WIN32)
// main() receives argv in the ANSI code page, which garbles (or cannot even
// represent) non-ASCII file names, while the file layer takes UTF-8
// (fs_atomic converts UTF-8 to UTF-16). Rebuild argv from the UTF-16 command
// line. Only paths and options travel here: passwords never come via argv.
std::vector<std::string> utf8_args() {
    std::vector<std::string> out;
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (w == nullptr) return out;
    for (int i = 0; i < n; ++i) {
        const int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(len > 0 ? static_cast<size_t>(len) : 1, '\0');
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, &s[0], len, nullptr, nullptr);
        s.resize(std::strlen(s.c_str()));
        out.push_back(s);
    }
    LocalFree(w);
    return out;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    using namespace secraxis;
#if defined(_WIN32)
    std::vector<std::string> args = utf8_args();
    std::vector<char*> argv8;
    if (!args.empty()) {
        for (std::string& a : args) argv8.push_back(&a[0]);
        argv8.push_back(nullptr);
        argc = static_cast<int>(args.size());
        argv = argv8.data();
    }
#endif

    if (argc >= 2 &&
        (std::strcmp(argv[1], "--help") == 0 || std::strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }
    if (argc >= 2 && std::strcmp(argv[1], "--version") == 0) {
        std::printf("secraxis %s\n", SECRAXIS_VERSION);
        return 0;
    }

    // Harden the process before any secret is read. Only the memory-probe
    // test twin (tests/CMakeLists.txt, never shipped) leaves it readable, so
    // a test can scan its memory for leftover secrets.
#if defined(SECRAXIS_TEST_NO_HARDENING)
#if !defined(SECRAXIS_MEMPROBE_TEST_BUILD)
#error "SECRAXIS_TEST_NO_HARDENING is for the secraxis_memprobe test target only"
#endif
#else
    apply_process_hardening();
#endif
    if (!crypto_init()) {
        std::fprintf(stderr, "Cryptography self-initialization failed.\n");
        return 3;
    }

    // Subcommand dispatch (first token is a known verb).
    auto is_verb = [&](const char* v) {
        return argc >= 2 && std::strcmp(argv[1], v) == 0;
    };
    auto find_flag_value = [&](const char* flag) -> const char* {
        for (int i = 2; i < argc - 1; ++i)
            if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
        return nullptr;
    };
    auto has_flag = [&](const char* flag) {
        for (int i = 2; i < argc; ++i)
            if (std::strcmp(argv[i], flag) == 0) return true;
        return false;
    };

    if (is_verb("validate")) {
        if (argc < 3) { print_usage(argv[0]); return 2; }
        return cli_validate(argv[2]);
    }
    if (is_verb("passwd")) {
        if (argc < 3) { print_usage(argv[0]); return 2; }
        return cli_passwd(argv[2]);
    }
    if (is_verb("rekey")) {
        if (argc < 3) { print_usage(argv[0]); return 2; }
        return cli_rekey(argv[2]);
    }
    if (is_verb("upgrade")) {
        const char* kv = find_flag_value("--kdf");
        KdfProfileId prof;
        if (argc < 3 || kv == nullptr || !parse_kdf(kv, &prof)) {
            print_usage(argv[0]);
            return 2;
        }
        return cli_upgrade(argv[2], prof);
    }
    if (is_verb("import")) {
        bool json = has_flag("--json");
        bool csv = has_flag("--csv");
        const char* infile = find_flag_value(json ? "--json" : "--csv");
        if (argc < 3 || (json == csv) || infile == nullptr) {
            print_usage(argv[0]);
            return 2;
        }
        return cli_import(argv[2], infile, json);
    }
    if (is_verb("backup")) {
        if (argc < 4) { print_usage(argv[0]); return 2; }
        return cli_export_backup(argv[2], argv[3]);
    }
    if (is_verb("export-plaintext")) {
        bool json = has_flag("--json");
        bool csv = has_flag("--csv");
        const char* outfile = find_flag_value(json ? "--json" : "--csv");
        if (argc < 3 || (json == csv) || outfile == nullptr) {
            print_usage(argv[0]);
            return 2;
        }
        return cli_export_plaintext(argv[2], outfile, json);
    }

    // Default: interactive TUI (open/create).
    std::string vault_path;
    KdfProfileId kdf = KdfProfileId::Default;
    UiOptions ui;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--kdf") == 0 && i + 1 < argc) {
            if (!parse_kdf(argv[++i], &kdf)) {
                std::fprintf(stderr, "Unknown KDF profile: %s\n", argv[i]);
                return 2;
            }
            continue;
        }
        if (std::strcmp(a, "--ascii") == 0) {
            ui.force_ascii = true;
            continue;
        }
        if (std::strcmp(a, "--no-color") == 0) {
            ui.no_color = true;
            continue;
        }
        if (std::strcmp(a, "--no-mouse") == 0) {
            ui.no_mouse = true;
            continue;
        }
        if (std::strcmp(a, "--no-history") == 0) {
            ui.no_history = true;
            continue;
        }
        if (std::strcmp(a, "--keep-font") == 0) {
            ui.keep_font = true;
            continue;
        }
        if (std::strcmp(a, "--glyphs") == 0 && i + 1 < argc) {
            const char* g = argv[++i];
            if (std::strcmp(g, "basic") == 0) {
                ui.glyphs = 1;
            } else if (std::strcmp(g, "rich") == 0) {
                ui.glyphs = 2;
            } else {
                std::fprintf(stderr, "Unknown glyph set: %s (use basic or rich)\n", g);
                return 2;
            }
            continue;
        }
        if (std::strcmp(a, "--theme") == 0 && i + 1 < argc) {
            const char* t = argv[++i];
            if (std::strcmp(t, "dark") == 0) {
                ui.theme = 1;
            } else if (std::strcmp(t, "light") == 0) {
                ui.theme = 2;
            } else {
                std::fprintf(stderr, "Unknown theme: %s (use dark or light)\n", t);
                return 2;
            }
            continue;
        }
        if (a[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", a);
            return 2;
        }
        if (vault_path.empty()) vault_path = a;
        else { std::fprintf(stderr, "Only one vault path may be given.\n"); return 2; }
    }
    // Without a vault path the start page opens (recent vaults, browse, new).
    return run_app(vault_path, kdf, ui);
}
