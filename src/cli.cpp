// cli.cpp — non-interactive subcommands (validate/passwd/rekey/upgrade/
// export/import). Master passwords come only from the hidden prompt, never
// argv/env. Import ADDS to the vault (fresh entry ids); export of plaintext
// requires an explicit typed confirmation.
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "secraxis/canonical_codec.h"
#include "secraxis/crypto.h"
#include "secraxis/export_import.h"
#include "secraxis/fs_atomic.h"
#include "secraxis/prompt.h"
#include "secraxis/seis_container.h"
#include "secraxis/tui_core.h"
#include "secraxis/vault_session.h"

namespace secraxis {

namespace {

uint64_t now_s() { return static_cast<uint64_t>(time(nullptr)); }

// The TUI accepts only printable ASCII in master passwords (Unicode text can
// encode differently across input methods; see tui_core.h). Enforce the same
// rule for new passwords here, so every master password can be typed in the
// TUI. Current passwords are accepted as typed, so nobody is locked out.
bool printable_ascii(const SecureBuffer& b) {
    for (size_t i = 0; i < b.size(); ++i)
        if (b.data()[i] < 0x20 || b.data()[i] > 0x7E) return false;
    return true;
}

int require_tty() {
    if (!stdin_is_tty()) {
        std::fprintf(stderr,
                     "This command needs an interactive terminal for the "
                     "hidden password prompt.\n");
        return 2;
    }
    return 0;
}

// Why a command that unlocked the vault could not write it. Only reachable
// with the right password, so this tells an attacker nothing; anything else
// stays the one generic unlock failure.
const char* failure_text(Err e) {
    if (e == Err::VaultChanged)
        return "The vault file changed while this ran (another window or a sync tool saved "
               "it). Nothing was written; run the command again.";
    if (e == Err::VaultRekeyed)
        return "The vault's master password or keys were changed while this ran. Nothing "
               "was written (that would bring the old ones back); run the command again.";
    if (e == Err::IoWrite) return "Could not write the vault file (disk full or no permission?). It is unchanged.";
    // Refused before the password was tried: no random numbers (RDSEED).
    if (e == Err::RngFailed) return entropy_state_text(entropy_state());
    return "Failed: wrong password or corrupted vault.";
}

}  // namespace

int cli_validate(const std::string& path) {
    if (int r = require_tty()) return r;
    SecureBuffer pw = read_hidden_line("Master password: ");
    Status s = seis_validate(path, pw.view());
    pw.reset();
    if (s.ok()) {
        std::printf("OK: vault is valid and openable.\n");
        return 0;
    }
    std::printf("FAILED: wrong password or corrupted vault.\n");
    return 1;
}

int cli_passwd(const std::string& path) {
    if (int r = require_tty()) return r;
    SecureBuffer oldp = read_hidden_line("Current master password: ");
    SecureBuffer new1 = read_hidden_line("New master password: ");
    SecureBuffer new2 = read_hidden_line("Confirm new master password: ");
    if (!new1.ct_equals(new2)) {
        std::fprintf(stderr, "New passwords do not match.\n");
        return 1;
    }
    // The same rules as the vault screen: never empty (anyone could open
    // the vault), and no longer than its password field takes.
    if (new1.size() == 0) {
        std::fprintf(stderr, "The new master password must not be empty.\n");
        return 1;
    }
    if (new1.size() > SecretLineEdit::MAX_LEN) {
        std::fprintf(stderr,
                     "The new master password is longer than %zu characters, more than the "
                     "vault screen accepts.\n",
                     SecretLineEdit::MAX_LEN);
        return 1;
    }
    if (!printable_ascii(new1)) {
        std::fprintf(stderr,
                     "Master passwords use printable ASCII characters only "
                     "(letters, digits, punctuation, space).\n");
        return 1;
    }
    Status s = change_master_password(path, oldp.view(), new1.view(), now_s());
    oldp.reset(); new1.reset(); new2.reset();
    if (s.ok()) { std::printf("Master password changed.\n"); return 0; }
    std::printf("%s\n", failure_text(s.err));
    return 1;
}

int cli_rekey(const std::string& path) {
    if (int r = require_tty()) return r;
    SecureBuffer pw = read_hidden_line("Master password: ");
    Status s = rekey_vault(path, pw.view(), now_s());
    pw.reset();
    if (s.ok()) { std::printf("Vault rekeyed (fresh VMK).\n"); return 0; }
    std::printf("%s\n", failure_text(s.err));
    return 1;
}

int cli_upgrade(const std::string& path, KdfProfileId profile) {
    if (int r = require_tty()) return r;
    SecureBuffer pw = read_hidden_line("Master password: ");
    Status s = upgrade_kdf_profile(path, pw.view(), profile, now_s());
    pw.reset();
    if (s.ok()) { std::printf("KDF profile upgraded.\n"); return 0; }
    if (s.err == Err::InvalidArgument) {
        std::printf("Refused: that is not an upgrade (no downgrade allowed).\n");
        return 1;
    }
    std::printf("%s\n", failure_text(s.err));
    return 1;
}

int cli_import(const std::string& path, const std::string& infile,
               bool as_json) {
    if (int r = require_tty()) return r;
    Result<Bytes> data = read_file(infile);
    if (!data.ok()) { std::fprintf(stderr, "Cannot read %s\n", infile.c_str()); return 2; }
    Result<std::vector<EntryRecord>> parsed =
        as_json ? import_json(ByteView(data.value))
                : import_csv(ByteView(data.value));
    secure_wipe(data.value.data(), data.value.size());
    if (!parsed.ok()) {
        std::fprintf(stderr, parsed.err == Err::AllocationFailed
                                 ? "Out of secure memory while reading the import file. "
                                   "Nothing was imported.\n"
                                 : "Import file is malformed or unsupported.\n");
        return 1;
    }
    std::printf("Parsed %zu entries. WARNING: source file is plaintext; "
                "delete it securely afterwards.\n", parsed.value.size());
    SecureBuffer pw = read_hidden_line("Master password: ");
    Result<VaultSession> vs = VaultSession::unlock(path, pw.view());
    pw.reset();
    if (!vs.ok()) { std::printf("%s\n", failure_text(vs.err)); return 1; }
    size_t added = 0;
    for (EntryRecord& e : parsed.value) {
        if (vs.value.add_entry(static_cast<EntryRecord&&>(e), now_s()).ok()) ++added;
    }
    Status s = vs.value.save(now_s());
    if (!s.ok()) {
        std::printf("Import parsed but not saved: %s\n",
                    s.err == Err::VaultChanged || s.err == Err::VaultRekeyed ||
                            s.err == Err::IoWrite || s.err == Err::RngFailed
                        ? failure_text(s.err)
                        : "the vault is unchanged.");
        return 1;
    }
    std::printf("Imported %zu entries.\n", added);
    return 0;
}

int cli_export_plaintext(const std::string& path, const std::string& outfile,
                         bool as_json) {
    if (int r = require_tty()) return r;
    std::fprintf(stderr,
                 "!! UNSAFE PLAINTEXT EXPORT !!\n"
                 "This writes every password in CLEARTEXT to:\n  %s\n"
                 "It cannot be un-exported. Anyone who reads that file sees "
                 "all secrets.\n"
                 "Type exactly  I UNDERSTAND  to proceed: ",
                 outfile.c_str());
    char line[64] = {0};
    if (std::fgets(line, sizeof(line), stdin) == nullptr) return 1;
    size_t n = std::strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
    if (std::strcmp(line, "I UNDERSTAND") != 0) {
        std::printf("Aborted.\n");
        return 1;
    }
    SecureBuffer pw = read_hidden_line("Master password: ");
    Result<VaultSession> vs = VaultSession::unlock(path, pw.view());
    pw.reset();
    if (!vs.ok()) { std::printf("%s\n", failure_text(vs.err)); return 1; }
    // Reassemble records from the runtime store.
    Result<SecureBuffer> canon = vs.value.export_canonical();
    if (!canon.ok()) { std::printf("Failed to assemble export.\n"); return 1; }
    Result<std::vector<EntryRecord>> recs = canonical_decode(canon.value.view());
    canon.value.reset();
    if (!recs.ok()) { std::printf("Failed to assemble export.\n"); return 1; }
    Status s = export_plaintext_file(outfile, recs.value, as_json,
                                     UnsafeExportConsent::grant());
    if (s.ok()) {
        std::printf("Exported %zu entries in PLAINTEXT to %s.\n"
                    "Delete that file securely when done.\n",
                    recs.value.size(), outfile.c_str());
        return 0;
    }
    if (s.err == Err::Exists) {
        std::printf("%s already exists. Choose a new file name: an export never replaces a "
                    "file.\n",
                    outfile.c_str());
        return 1;
    }
    std::printf("Export failed (permission or IO).\n");
    return 1;
}

int cli_export_backup(const std::string& path, const std::string& outfile) {
    if (int r = require_tty()) return r;
    SecureBuffer pw = read_hidden_line("Master password: ");
    // Encrypted backup = the vault file's bytes (already a full
    // authenticated container), read once: the bytes checked against the
    // password are the bytes written.
    Status s = backup_vault_file(path, pw.view(), outfile);
    pw.reset();
    if (s.ok()) { std::printf("Encrypted backup written to %s.\n", outfile.c_str()); return 0; }
    if (s.err == Err::Exists) {
        std::printf("%s already exists. Choose a new file name: a backup never replaces a "
                    "file.\n",
                    outfile.c_str());
        return 1;
    }
    if (s.err == Err::IoWrite) { std::printf("Backup write failed.\n"); return 1; }
    std::printf("%s\n", failure_text(s.err));
    return 1;
}

}  // namespace secraxis
