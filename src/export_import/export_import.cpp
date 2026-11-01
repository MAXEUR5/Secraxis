#include "secraxis/export_import.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "secraxis/crypto.h"
#include "secraxis/fs_atomic.h"
#include "secraxis/kdf.h"
#include "secraxis/key_hierarchy.h"

namespace secraxis {

namespace {

constexpr size_t IMPORT_MAX_INPUT = 16u << 20;  // 16 MiB
constexpr size_t IMPORT_MAX_ROWS = CANONICAL_MAX_ENTRIES;
constexpr size_t CSV_MAX_FIELDS = 64;  // per row; a row with more fails the import

// A UTF-8 byte-order mark (Excel and many exporters write one) is not text
// of the file: left in, it hid the first CSV column's name ("name", most
// often), and those values were dropped without a word.
ByteView skip_utf8_bom(ByteView d) {
    if (d.len >= 3 && d.ptr[0] == 0xEF && d.ptr[1] == 0xBB && d.ptr[2] == 0xBF)
        return ByteView(d.ptr + 3, d.len - 3);
    return d;
}

// Assign a string field to the right EntryRecord slot by column role.
enum class Col { Ignore, Name, Remark, Username, Url, Tags, Password, Totp };

Col classify_header(const std::string& h) {
    // Spaces and quotes trimmed by index (a long run of them must not cost
    // quadratic time); no name below is longer than 10 characters.
    size_t b = 0, e = h.size();
    while (b < e && (h[b] == ' ' || h[b] == '"')) ++b;
    while (e > b && (h[e - 1] == ' ' || h[e - 1] == '"')) --e;
    if (e - b > 16) return Col::Ignore;
    std::string k;
    for (size_t j = b; j < e; ++j) {
        const char c = h[j];
        k.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
    }
    if (k == "name" || k == "title" || k == "account") return Col::Name;
    if (k == "remark" || k == "notes" || k == "note" || k == "comment") return Col::Remark;
    if (k == "username" || k == "user" || k == "login" || k == "email") return Col::Username;
    if (k == "url" || k == "website" || k == "uri" || k == "site") return Col::Url;
    if (k == "tags" || k == "group" || k == "folder") return Col::Tags;
    if (k == "password" || k == "pass" || k == "pwd") return Col::Password;
    if (k == "totp" || k == "otp_secret" || k == "otpauth" || k == "2fa") return Col::Totp;
    return Col::Ignore;
}

// False when a secret could not be stored (no secure memory left): the
// import then fails as a whole, never goes on without it.
bool assign(EntryRecord& e, Col c, const std::string& v) {
    if (v.empty()) return true;
    auto secret = [&](SecureBuffer& dst) {
        SecureBuffer s = SecureBuffer::alloc(v.size());
        if (!s.valid()) return false;
        std::memcpy(s.data(), v.data(), v.size());
        dst = static_cast<SecureBuffer&&>(s);
        return true;
    };
    switch (c) {
        case Col::Name: e.name.assign(v.begin(), v.end()); break;
        case Col::Remark: e.remark.assign(v.begin(), v.end()); break;
        case Col::Username: e.username.assign(v.begin(), v.end()); break;
        case Col::Url: e.url.assign(v.begin(), v.end()); break;
        case Col::Tags: e.tags.assign(v.begin(), v.end()); break;
        case Col::Password: return secret(e.password);
        case Col::Totp: return secret(e.totp_seed);
        case Col::Ignore: break;
    }
    return true;
}

// Zeroes a row's fields (a password among them) before they are freed.
void wipe_fields(std::vector<std::string>& fields) {
    for (std::string& f : fields)
        if (!f.empty()) secure_wipe(&f[0], f.size());
}

// Enforce field caps; oversized -> reject the whole import (caller sees error).
bool within_caps(const EntryRecord& e) {
    return e.name.size() <= field_max_len((uint16_t)FieldId::Name) &&
           e.remark.size() <= field_max_len((uint16_t)FieldId::Remark) &&
           e.username.size() <= field_max_len((uint16_t)FieldId::Username) &&
           e.url.size() <= field_max_len((uint16_t)FieldId::Url) &&
           e.tags.size() <= field_max_len((uint16_t)FieldId::Tags) &&
           e.password.size() <= field_max_len((uint16_t)FieldId::Password) &&
           e.totp_seed.size() <= field_max_len((uint16_t)FieldId::TotpSeed);
}

bool entry_nonempty(const EntryRecord& e) {
    return !e.name.empty() || !e.username.empty() || e.password.size() > 0 ||
           !e.url.empty();
}

// ---- CSV (RFC 4180-ish): comma sep, "" escapes inside quotes, CRLF/LF ----
struct CsvReader {
    const uint8_t* p;
    size_t n;
    size_t i = 0;
    bool bad = false;  // malformed: a quote never closed, or too many fields

    bool at_end() const { return i >= n; }
    // One field from i on (i < n): its text appended to *out, or only
    // counted when out is null. Returns the length; sets *last_in_row when
    // the terminator was newline/EOF.
    size_t scan(std::string* out, bool* last_in_row) {
        size_t len = 0;
        auto put = [&](uint8_t c) {
            if (out != nullptr) out->push_back(static_cast<char>(c));
            ++len;
        };
        *last_in_row = false;
        bool quoted = (p[i] == '"');
        if (quoted) ++i;
        while (i < n) {
            uint8_t c = p[i];
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < n && p[i + 1] == '"') { put('"'); i += 2; continue; }
                    ++i; quoted = false; continue;
                }
                put(c);
                ++i;
            } else {
                if (c == ',') { ++i; return len; }
                if (c == '\n') { ++i; *last_in_row = true; return len; }
                if (c == '\r') { ++i; if (i < n && p[i] == '\n') ++i; *last_in_row = true; return len; }
                put(c);
                ++i;
            }
        }
        if (quoted) bad = true;  // the input ended inside quotes: cut short
        *last_in_row = true;
        return len;
    }
    // Read one field; sets *last_in_row when the terminator was newline/EOF.
    bool field(std::string* out, bool* last_in_row) {
        out->clear();
        *last_in_row = false;
        if (i >= n) { *last_in_row = true; return false; }
        // Sized first: the text (it may be a password) is never copied by a
        // growing buffer, which would leave copies behind in freed memory.
        const size_t start = i;
        out->reserve(scan(nullptr, last_in_row));
        i = start;
        scan(out, last_in_row);
        return true;
    }
    std::vector<std::string> row(bool* ok) {
        std::vector<std::string> r;
        r.reserve(CSV_MAX_FIELDS);  // never regrown, for the same reason
        bool last = false;
        *ok = false;
        for (;;) {
            if (r.size() == CSV_MAX_FIELDS) {
                bad = true;  // the rest would be taken for the next row
                return r;
            }
            r.emplace_back();
            bool got = field(&r.back(), &last);
            if (!got && r.size() == 1 && last) {  // EOF, empty
                r.pop_back();
                return r;
            }
            *ok = true;
            if (last) break;
        }
        return r;
    }
};

}  // namespace

Result<std::vector<EntryRecord>> import_csv(ByteView data) {
    using R = Result<std::vector<EntryRecord>>;
    if (data.len > IMPORT_MAX_INPUT) return R::failure(Err::InvalidArgument);
    const ByteView in = skip_utf8_bom(data);
    CsvReader rd{in.ptr, in.len};
    bool ok = false;
    std::vector<std::string> header = rd.row(&ok);
    if (rd.bad || !ok || header.empty()) return R::failure(Err::InvalidArgument);
    std::vector<Col> cols;
    cols.reserve(header.size());
    bool any_known = false;
    for (const std::string& h : header) {
        Col c = classify_header(h);
        cols.push_back(c);
        if (c != Col::Ignore) any_known = true;
    }
    if (!any_known) return R::failure(Err::InvalidArgument);

    std::vector<EntryRecord> out;
    while (!rd.at_end()) {
        if (out.size() >= IMPORT_MAX_ROWS) return R::failure(Err::InvalidArgument);
        std::vector<std::string> fields = rd.row(&ok);
        if (rd.bad) {
            wipe_fields(fields);
            return R::failure(Err::InvalidArgument);
        }
        if (!ok) break;
        // Skip fully-empty trailing rows.
        bool empty_row = true;
        for (const std::string& f : fields) if (!f.empty()) { empty_row = false; break; }
        if (empty_row) continue;
        EntryRecord e;
        bool stored = true;
        for (size_t c = 0; stored && c < fields.size() && c < cols.size(); ++c)
            stored = assign(e, cols[c], fields[c]);
        wipe_fields(fields);
        if (!stored) return R::failure(Err::AllocationFailed);
        if (!within_caps(e)) return R::failure(Err::InvalidArgument);
        if (entry_nonempty(e)) {
            e.pw_bucket = password_length_bucket(e.password.size());
            out.push_back(static_cast<EntryRecord&&>(e));
        }
    }
    return R::success(static_cast<std::vector<EntryRecord>&&>(out));
}

// ---- Minimal, bounded JSON: array of flat objects with string values ------
namespace {

struct JsonReader {
    const uint8_t* p;
    size_t n;
    size_t i = 0;
    int depth = 0;
    bool alloc_failed = false;  // a secret could not be stored
    static constexpr int MAX_DEPTH = 32;

    void ws() {
        while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r')) ++i;
    }
    // A string's text appended to *out, or only counted (*len) when out is
    // null.
    bool str_scan(std::string* out, size_t* len) {
        *len = 0;
        auto put = [&](char ch) {
            if (out != nullptr) out->push_back(ch);
            ++*len;
        };
        if (i >= n || p[i] != '"') return false;
        ++i;
        while (i < n) {
            uint8_t c = p[i++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i >= n) return false;
                uint8_t e = p[i++];
                switch (e) {
                    case '"': put('"'); break;
                    case '\\': put('\\'); break;
                    case '/': put('/'); break;
                    case 'n': put('\n'); break;
                    case 't': put('\t'); break;
                    case 'r': put('\r'); break;
                    case 'b': put('\b'); break;
                    case 'f': put('\f'); break;
                    case 'u': {
                        if (i + 4 > n) return false;
                        // Decode BMP code point; emit UTF-8 (non-ASCII becomes
                        // multibyte — display layer sanitizes later).
                        unsigned v = 0;
                        for (int k = 0; k < 4; ++k) {
                            uint8_t h = p[i++];
                            v <<= 4;
                            if (h >= '0' && h <= '9') v |= h - '0';
                            else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
                            else return false;
                        }
                        if (v < 0x80) put(static_cast<char>(v));
                        else if (v < 0x800) {
                            put(static_cast<char>(0xC0 | (v >> 6)));
                            put(static_cast<char>(0x80 | (v & 0x3F)));
                        } else {
                            put(static_cast<char>(0xE0 | (v >> 12)));
                            put(static_cast<char>(0x80 | ((v >> 6) & 0x3F)));
                            put(static_cast<char>(0x80 | (v & 0x3F)));
                        }
                        break;
                    }
                    default: return false;
                }
            } else {
                if (*len > (8u << 20)) return false;  // string cap
                put(static_cast<char>(c));
            }
        }
        return false;
    }
    // Sized first, like a CSV field: a value (it may be a password) is never
    // copied by a growing buffer.
    bool str(std::string* out) {
        out->clear();
        const size_t start = i;
        size_t len = 0;
        if (!str_scan(nullptr, &len)) return false;
        i = start;
        out->reserve(len);
        return str_scan(out, &len);
    }
    // Skip a JSON value we don't store (number/bool/null/nested).
    bool skip_value() {
        if (++depth > MAX_DEPTH) return false;
        ws();
        if (i >= n) { --depth; return false; }
        bool r = false;
        uint8_t c = p[i];
        if (c == '"') {
            std::string tmp;
            r = str(&tmp);
            if (!tmp.empty()) secure_wipe(&tmp[0], tmp.size());
        }
        else if (c == '{') r = skip_object();
        else if (c == '[') r = skip_array();
        else {
            // number/true/false/null: consume until , } ] or ws
            size_t start = i;
            while (i < n && p[i] != ',' && p[i] != '}' && p[i] != ']' &&
                   p[i] != ' ' && p[i] != '\n' && p[i] != '\t' && p[i] != '\r')
                ++i;
            r = (i > start);
        }
        --depth;
        return r;
    }
    bool skip_object() {
        if (p[i] != '{') return false;
        ++i; ws();
        if (i < n && p[i] == '}') { ++i; return true; }
        while (i < n) {
            std::string k;
            ws();
            if (!str(&k)) return false;
            ws();
            if (i >= n || p[i] != ':') return false;
            ++i;
            if (!skip_value()) return false;
            ws();
            if (i >= n) return false;
            if (p[i] == ',') { ++i; continue; }
            if (p[i] == '}') { ++i; return true; }
            return false;
        }
        return false;
    }
    bool skip_array() {
        if (p[i] != '[') return false;
        ++i; ws();
        if (i < n && p[i] == ']') { ++i; return true; }
        while (i < n) {
            if (!skip_value()) return false;
            ws();
            if (i >= n) return false;
            if (p[i] == ',') { ++i; continue; }
            if (p[i] == ']') { ++i; return true; }
            return false;
        }
        return false;
    }
    // Parse one flat object into an EntryRecord.
    bool object(EntryRecord* e, bool* ok) {
        *ok = false;
        if (++depth > MAX_DEPTH) { --depth; return false; }
        ws();
        if (i >= n || p[i] != '{') { --depth; return false; }
        ++i; ws();
        if (i < n && p[i] == '}') { ++i; --depth; *ok = true; return true; }
        while (i < n) {
            std::string key;
            ws();
            if (!str(&key)) { --depth; return false; }
            ws();
            if (i >= n || p[i] != ':') { --depth; return false; }
            ++i; ws();
            if (i < n && p[i] == '"') {
                std::string val;
                if (!str(&val)) { --depth; return false; }
                const bool stored = assign(*e, classify_header(key), val);
                if (!val.empty()) secure_wipe(&val[0], val.size());
                if (!stored) {
                    alloc_failed = true;
                    --depth;
                    return false;
                }
            } else {
                if (!skip_value()) { --depth; return false; }  // non-string
            }
            ws();
            if (i >= n) { --depth; return false; }
            if (p[i] == ',') { ++i; continue; }
            if (p[i] == '}') { ++i; --depth; *ok = true; return true; }
            --depth; return false;
        }
        --depth;
        return false;
    }
};

}  // namespace

Result<std::vector<EntryRecord>> import_json(ByteView data) {
    using R = Result<std::vector<EntryRecord>>;
    if (data.len > IMPORT_MAX_INPUT) return R::failure(Err::InvalidArgument);
    const ByteView in = skip_utf8_bom(data);
    JsonReader rd{in.ptr, in.len};
    rd.ws();
    if (rd.i >= rd.n || rd.p[rd.i] != '[') return R::failure(Err::InvalidArgument);
    ++rd.i;
    rd.ws();
    std::vector<EntryRecord> out;
    bool closed = false;
    if (rd.i < rd.n && rd.p[rd.i] == ']') {
        ++rd.i;
        closed = true;
    }
    while (!closed && rd.i < rd.n) {
        if (out.size() >= IMPORT_MAX_ROWS) return R::failure(Err::InvalidArgument);
        EntryRecord e;
        bool ok = false;
        if (!rd.object(&e, &ok) || !ok)
            return R::failure(rd.alloc_failed ? Err::AllocationFailed : Err::InvalidArgument);
        if (!within_caps(e)) return R::failure(Err::InvalidArgument);
        if (entry_nonempty(e)) {
            e.pw_bucket = password_length_bucket(e.password.size());
            out.push_back(static_cast<EntryRecord&&>(e));
        }
        rd.ws();
        if (rd.i >= rd.n) return R::failure(Err::InvalidArgument);
        if (rd.p[rd.i] == ',') { ++rd.i; rd.ws(); continue; }
        if (rd.p[rd.i] == ']') { ++rd.i; closed = true; break; }
        return R::failure(Err::InvalidArgument);
    }
    // Truncated arrays are rejected; only whitespace may follow the ']'.
    if (!closed) return R::failure(Err::InvalidArgument);
    rd.ws();
    if (rd.i != rd.n) return R::failure(Err::InvalidArgument);
    return R::success(static_cast<std::vector<EntryRecord>&&>(out));
}

// ---- plaintext export bodies ----------------------------------------------
namespace {
// Where an export body goes: counted first, then written into secure memory
// of exactly that size (a growing buffer would leave copies of the plaintext
// behind in freed memory).
struct Sink {
    uint8_t* out = nullptr;  // null: count only
    size_t n = 0;
    void put(uint8_t c) {
        if (out != nullptr) out[n] = c;
        ++n;
    }
    void put(const char* s) {
        for (; *s != '\0'; ++s) put(static_cast<uint8_t>(*s));
    }
};

void csv_field(Sink& out, ByteView v) {
    bool need_quote = false;
    for (size_t k = 0; k < v.len; ++k) {
        uint8_t c = v.ptr[k];
        if (c == ',' || c == '"' || c == '\n' || c == '\r') { need_quote = true; break; }
    }
    if (need_quote) out.put('"');
    for (size_t k = 0; k < v.len; ++k) {
        uint8_t c = v.ptr[k];
        if (c == '"' && need_quote) out.put('"');
        out.put(c);
    }
    if (need_quote) out.put('"');
}
void json_string(Sink& out, ByteView v) {
    static const char kHex[] = "0123456789abcdef";
    out.put('"');
    for (size_t k = 0; k < v.len; ++k) {
        uint8_t c = v.ptr[k];
        switch (c) {
            case '"': out.put("\\\""); break;
            case '\\': out.put("\\\\"); break;
            case '\n': out.put("\\n"); break;
            case '\r': out.put("\\r"); break;
            case '\t': out.put("\\t"); break;
            default:
                if (c < 0x20) {
                    out.put("\\u00");
                    out.put(static_cast<uint8_t>(kHex[c >> 4]));
                    out.put(static_cast<uint8_t>(kHex[c & 15]));
                } else {
                    out.put(c);
                }
        }
    }
    out.put('"');
}

void csv_body(Sink& out, const std::vector<EntryRecord>& entries) {
    out.put("name,remark,username,url,tags,password,totp\r\n");
    for (const EntryRecord& e : entries) {
        csv_field(out, ByteView(e.name)); out.put(',');
        csv_field(out, ByteView(e.remark)); out.put(',');
        csv_field(out, ByteView(e.username)); out.put(',');
        csv_field(out, ByteView(e.url)); out.put(',');
        csv_field(out, ByteView(e.tags)); out.put(',');
        csv_field(out, e.password.view()); out.put(',');
        csv_field(out, e.totp_seed.view());
        out.put("\r\n");
    }
}

void json_body(Sink& out, const std::vector<EntryRecord>& entries) {
    out.put('[');
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        const EntryRecord& e = entries[idx];
        if (idx > 0) out.put(',');
        out.put('{');
        auto kv = [&](const char* k, ByteView v, bool last) {
            json_string(out, label(k));
            out.put(':');
            json_string(out, v);
            if (!last) out.put(',');
        };
        kv("name", ByteView(e.name), false);
        kv("remark", ByteView(e.remark), false);
        kv("username", ByteView(e.username), false);
        kv("url", ByteView(e.url), false);
        kv("tags", ByteView(e.tags), false);
        kv("password", e.password.view(), false);
        kv("totp", e.totp_seed.view(), true);
        out.put('}');
    }
    out.put(']');
}

SecureBuffer build_body(void (*body)(Sink&, const std::vector<EntryRecord>&),
                        const std::vector<EntryRecord>& entries) {
    Sink count;
    body(count, entries);
    SecureBuffer buf = SecureBuffer::alloc(count.n);
    if (!buf.valid()) return buf;
    Sink fill;
    fill.out = buf.data();
    body(fill, entries);
    return buf;
}
}  // namespace

SecureBuffer export_csv_plaintext(const std::vector<EntryRecord>& entries) {
    return build_body(csv_body, entries);
}

SecureBuffer export_json_plaintext(const std::vector<EntryRecord>& entries) {
    return build_body(json_body, entries);
}

Status export_plaintext_file(const std::string& out_path,
                             const std::vector<EntryRecord>& entries,
                             bool as_json, UnsafeExportConsent consent) {
    if (!consent.acknowledged) return status_fail(Err::ExportPermission);
    SecureBuffer body = as_json ? export_json_plaintext(entries)
                                : export_csv_plaintext(entries);
    if (!body.valid()) return status_fail(Err::AllocationFailed);
    // A new file only the user can read (never an existing one, nor through
    // a link); nothing of it stays behind if the write fails.
    return write_file_private(out_path, body.view());
}

Status backup_vault_file(const std::string& path, ByteView master_password,
                         const std::string& backup_path) {
    // Writing the copy needs random numbers (its temporary file's name):
    // refused before the password is tried, as everything without RDSEED.
    if (entropy_state() != EntropyState::Ready) return status_fail(Err::RngFailed);
    Result<Bytes> cur = read_file(path);
    if (!cur.ok()) return status_fail(cur.err);
    Result<UnlockedVault> v = seis_unlock_bytes(ByteView(cur.value), master_password);
    if (!v.ok()) return status_fail(v.err);
    // Its entries must decode too, as when the vault screen opens it.
    Result<std::vector<EntryRecord>> entries = canonical_decode(v.value.canonical.view());
    if (!entries.ok()) return status_fail(entries.err);
    return write_file_new(backup_path, ByteView(cur.value));
}

// ---- key management --------------------------------------------------------
namespace {
// Sealing a new VMK envelope failed: for want of random numbers (its nonce),
// or for another reason.
Err seal_failure() {
    return entropy_state() == EntropyState::Ready ? Err::Internal : Err::RngFailed;
}
}  // namespace

Status change_master_password(const std::string& path, ByteView old_password,
                              ByteView new_password, uint64_t now_unix) {
    // An empty master password would let anyone open the vault (and skip
    // the save's unlock-from-password check).
    if (new_password.empty()) return status_fail(Err::InvalidArgument);
    if (entropy_state() != EntropyState::Ready) return status_fail(Err::RngFailed);
    Result<UnlockedVault> vr = seis_unlock(path, old_password);
    if (!vr.ok()) return status_fail(vr.err);
    UnlockedVault& v = vr.value;
    const AeadProfile* ap = aead_profile_by_id(v.header.aead_profile_id);
    const KdfProfile* kp = kdf_profile_by_id(v.header.kdf_profile_id);
    if (ap == nullptr || kp == nullptr) return status_fail(Err::Internal);

    // New salt + KEK; rewrap the SAME VMK.
    SeisHeader h = v.header;
    if (!random_bytes(h.kdf_salt, KDF_SALT_LEN)) return status_fail(Err::RngFailed);
    KdfOutcome kek = derive_kek_material(new_password,
                                         ByteView(h.kdf_salt, KDF_SALT_LEN), *kp);
    if (!kek.ok()) return status_fail(kek.err);
    Bytes new_env = vmk_envelope_seal(h, *ap, kek.kek_material.view(), v.vmk,
                                      /*vmk_version=*/1, now_unix);
    kek.kek_material.reset();
    if (new_env.empty()) return status_fail(seal_failure());

    std::memcpy(v.header.kdf_salt, h.kdf_salt, KDF_SALT_LEN);
    v.vmk_envelope = new_env;
    return seis_save(path, v, v.canonical.view(), now_unix, new_password);
}

Status rekey_vault(const std::string& path, ByteView master_password,
                   uint64_t now_unix) {
    if (entropy_state() != EntropyState::Ready) return status_fail(Err::RngFailed);
    Result<UnlockedVault> vr = seis_unlock(path, master_password);
    if (!vr.ok()) return status_fail(vr.err);
    UnlockedVault& v = vr.value;
    const AeadProfile* ap = aead_profile_by_id(v.header.aead_profile_id);
    const KdfProfile* kp = kdf_profile_by_id(v.header.kdf_profile_id);
    if (ap == nullptr || kp == nullptr) return status_fail(Err::Internal);

    // Fresh VMK; KEK from the SAME password + a fresh salt.
    SeisHeader h = v.header;
    if (!random_bytes(h.kdf_salt, KDF_SALT_LEN)) return status_fail(Err::RngFailed);
    KdfOutcome kek = derive_kek_material(master_password,
                                         ByteView(h.kdf_salt, KDF_SALT_LEN), *kp);
    if (!kek.ok()) return status_fail(kek.err);
    Result<SecureBuffer> fresh_vmk = random_secret(VMK_LEN);
    if (!fresh_vmk.ok()) return status_fail(fresh_vmk.err);
    SecureBuffer new_vmk = static_cast<SecureBuffer&&>(fresh_vmk.value);
    Bytes new_env = vmk_envelope_seal(h, *ap, kek.kek_material.view(), new_vmk,
                                      /*vmk_version=*/2, now_unix);
    kek.kek_material.reset();
    if (new_env.empty()) return status_fail(seal_failure());

    std::memcpy(v.header.kdf_salt, h.kdf_salt, KDF_SALT_LEN);
    v.vmk = static_cast<SecureBuffer&&>(new_vmk);
    SecureBuffer new_prk = vmk_prk(v.vmk, v.header);
    if (!new_prk.valid()) return status_fail(Err::AllocationFailed);
    v.prk = static_cast<SecureBuffer&&>(new_prk);
    v.vmk_envelope = new_env;
    // The old VMK is gone once this lands: prove first that the new image
    // opens from the password (a full unlock of it, before the rename).
    return seis_save(path, v, v.canonical.view(), now_unix, master_password);
}

namespace {
// Strength rank for the no-downgrade rule: Floor(1) < Default(2) < Strong(3).
// The TEST-ONLY weak profile (999) ranks BELOW Floor — upgrading away from it
// is allowed; downgrading to it never is.
uint32_t kdf_profile_rank(uint32_t id) {
    if (id == 999) return 0;
    return id;  // registered ids are already strength-ordered
}
}  // namespace

Status upgrade_kdf_profile(const std::string& path, ByteView master_password,
                           KdfProfileId new_profile, uint64_t now_unix) {
    if (entropy_state() != EntropyState::Ready) return status_fail(Err::RngFailed);
    Result<UnlockedVault> vr = seis_unlock(path, master_password);
    if (!vr.ok()) return status_fail(vr.err);
    UnlockedVault& v = vr.value;
    const AeadProfile* ap = aead_profile_by_id(v.header.aead_profile_id);
    const KdfProfile* np = kdf_profile_by_id(static_cast<uint32_t>(new_profile));
    if (ap == nullptr || np == nullptr) return status_fail(Err::InvalidArgument);
    // No downgrade, by strength rank (never by raw id).
    if (kdf_profile_rank(static_cast<uint32_t>(new_profile)) <
        kdf_profile_rank(v.header.kdf_profile_id))
        return status_fail(Err::InvalidArgument);

    SeisHeader h = v.header;
    h.kdf_profile_id = static_cast<uint32_t>(np->id);
    h.kdf_memory_mib = np->memory_mib;
    h.kdf_iterations = np->iterations;
    h.kdf_lanes = np->lanes;
    if (!random_bytes(h.kdf_salt, KDF_SALT_LEN)) return status_fail(Err::RngFailed);
    KdfOutcome kek = derive_kek_material(master_password,
                                         ByteView(h.kdf_salt, KDF_SALT_LEN), *np);
    if (!kek.ok()) return status_fail(kek.err);
    Bytes new_env = vmk_envelope_seal(h, *ap, kek.kek_material.view(), v.vmk,
                                      /*vmk_version=*/1, now_unix);
    kek.kek_material.reset();
    if (new_env.empty()) return status_fail(seal_failure());

    // Adopt the new KDF header fields + salt; body keys (VMK/PRK) unchanged.
    v.header.kdf_profile_id = h.kdf_profile_id;
    v.header.kdf_memory_mib = h.kdf_memory_mib;
    v.header.kdf_iterations = h.kdf_iterations;
    v.header.kdf_lanes = h.kdf_lanes;
    std::memcpy(v.header.kdf_salt, h.kdf_salt, KDF_SALT_LEN);
    v.vmk_envelope = new_env;
    return seis_save(path, v, v.canonical.view(), now_unix, master_password);
}

}  // namespace secraxis
