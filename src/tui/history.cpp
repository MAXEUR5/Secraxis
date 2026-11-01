#include "secraxis/history.h"

#include <cstdio>

#include "secraxis/tui_text.h"

namespace secraxis {

namespace {

// A path the history may hold: well-formed UTF-8, bounded, and only code
// points the TUI draws as text (no controls, bidi overrides, BOM, ...).
bool storable(const std::string& s) {
    if (s.empty() || s.size() > HISTORY_PATH_MAX) return false;
    size_t i = 0;
    while (i < s.size()) {
        char32_t cp = 0;
        if (!utf8_decode(s.data(), s.size(), &i, &cp) || !is_text_cp(cp)) return false;
    }
    return true;
}

// Recursive-descent reader for exactly the history shape. Every helper
// returns false on the first deviation; nothing is allocated from lengths
// found in the input.
class Reader {
  public:
    Reader(const char* p, size_t n) : p_(p), n_(n) {}

    bool document(std::vector<RecentVault>* out) {
        ws();
        if (!eat('{')) return false;
        bool have_version = false, have_vaults = false;
        ws();
        if (peek() == '}') return false;  // both keys are required
        for (;;) {
            std::string key;
            ws();
            if (!string(&key, 16)) return false;
            ws();
            if (!eat(':')) return false;
            ws();
            if (key == "version" && !have_version) {
                uint64_t v = 0;
                if (!integer(&v) || v != 1) return false;
                have_version = true;
            } else if (key == "vaults" && !have_vaults) {
                if (!vaults(out)) return false;
                have_vaults = true;
            } else {
                return false;  // unknown or duplicate key
            }
            ws();
            if (eat(',')) continue;
            if (eat('}')) break;
            return false;
        }
        ws();
        return have_version && have_vaults && i_ == n_;
    }

  private:
    char peek() const { return i_ < n_ ? p_[i_] : '\0'; }
    bool eat(char c) {
        if (peek() != c) return false;
        ++i_;
        return true;
    }
    void ws() {
        while (i_ < n_ && (p_[i_] == ' ' || p_[i_] == '\t' || p_[i_] == '\n' || p_[i_] == '\r'))
            ++i_;
    }

    bool vaults(std::vector<RecentVault>* out) {
        if (!eat('[')) return false;
        ws();
        if (eat(']')) return true;
        size_t count = 0;
        for (;;) {
            if (++count > 4 * HISTORY_MAX) return false;
            RecentVault v;
            ws();
            if (!vault(&v)) return false;
            if (out->size() < HISTORY_MAX) out->push_back(v);
            ws();
            if (eat(',')) continue;
            if (eat(']')) return true;
            return false;
        }
    }

    bool vault(RecentVault* v) {
        if (!eat('{')) return false;
        bool have_path = false, have_time = false;
        for (;;) {
            std::string key;
            ws();
            if (!string(&key, 16)) return false;
            ws();
            if (!eat(':')) return false;
            ws();
            if (key == "path" && !have_path) {
                if (!string(&v->path, HISTORY_PATH_MAX) || v->path.empty()) return false;
                have_path = true;
            } else if (key == "last_opened" && !have_time) {
                if (!integer(&v->last_opened)) return false;
                have_time = true;
            } else {
                return false;
            }
            ws();
            if (eat(',')) continue;
            if (eat('}')) break;
            return false;
        }
        return have_path && have_time;
    }

    // Non-negative integer, no sign/fraction/exponent, no leading zeros,
    // at most 2^53.
    bool integer(uint64_t* out) {
        const size_t start = i_;
        uint64_t v = 0;
        while (i_ < n_ && p_[i_] >= '0' && p_[i_] <= '9') {
            if (i_ - start >= 16) return false;
            v = v * 10 + static_cast<uint64_t>(p_[i_] - '0');
            ++i_;
        }
        if (i_ == start) return false;
        if (p_[start] == '0' && i_ - start > 1) return false;
        if (v > (1ULL << 53)) return false;
        *out = v;
        return true;
    }

    int hex4() {
        if (i_ + 4 > n_) return -1;
        int v = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = p_[i_ + static_cast<size_t>(k)];
            int d = -1;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            if (d < 0) return -1;
            v = v * 16 + d;
        }
        i_ += 4;
        return v;
    }

    void put(std::string* s, char32_t cp) {
        char b[4];
        s->append(b, utf8_encode(cp, b));
    }

    // String with JSON escapes; the result must be well-formed UTF-8 and
    // free of control characters.
    bool string(std::string* out, size_t max_bytes) {
        out->clear();
        if (!eat('"')) return false;
        for (;;) {
            if (i_ >= n_) return false;
            const char c = p_[i_];
            if (c == '"') {
                ++i_;
                break;
            }
            if (static_cast<uint8_t>(c) < 0x20) return false;
            if (c != '\\') {
                size_t j = i_;
                char32_t cp = 0;
                if (!utf8_decode(p_, n_, &j, &cp)) return false;
                out->append(p_ + i_, j - i_);
                i_ = j;
            } else {
                ++i_;
                const char e = peek();
                ++i_;
                switch (e) {
                    case '"': out->push_back('"'); break;
                    case '\\': out->push_back('\\'); break;
                    case '/': out->push_back('/'); break;
                    case 'u': {
                        const int u = hex4();
                        if (u < 0) return false;
                        char32_t cp = static_cast<char32_t>(u);
                        if (u >= 0xD800 && u <= 0xDBFF) {
                            if (!eat('\\') || !eat('u')) return false;
                            const int lo = hex4();
                            if (lo < 0xDC00 || lo > 0xDFFF) return false;
                            cp = 0x10000 + ((static_cast<char32_t>(u) - 0xD800) << 10) +
                                 (static_cast<char32_t>(lo) - 0xDC00);
                        } else if (u >= 0xDC00 && u <= 0xDFFF) {
                            return false;
                        }
                        if (cp < 0x20) return false;
                        put(out, cp);
                        break;
                    }
                    default:
                        return false;  // \b \f \n \r \t: controls are not allowed
                }
            }
            if (out->size() > max_bytes) return false;
        }
        return storable(*out);
    }

    const char* p_;
    size_t n_;
    size_t i_ = 0;
};

bool same_path(const std::string& a, const std::string& b, bool fold_case) {
    if (a.size() != b.size()) return false;
    for (size_t k = 0; k < a.size(); ++k) {
        char x = a[k], y = b[k];
        if (fold_case) {
            if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
            if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        }
        if (x != y) return false;
    }
    return true;
}

}  // namespace

bool parse_history(ByteView json, std::vector<RecentVault>* out) {
    out->clear();
    if (json.len == 0 || json.len > HISTORY_FILE_MAX) return false;
    Reader r(reinterpret_cast<const char*>(json.ptr), json.len);
    if (!r.document(out)) {
        out->clear();
        return false;
    }
    return true;
}

std::string serialize_history(const std::vector<RecentVault>& vaults) {
    std::string s = "{\n  \"version\": 1,\n  \"vaults\": [";
    for (size_t k = 0; k < vaults.size() && k < HISTORY_MAX; ++k) {
        s += k == 0 ? "\n" : ",\n";
        s += "    {\"path\": \"";
        for (const char c : vaults[k].path) {
            if (c == '"') s += "\\\"";
            else if (c == '\\') s += "\\\\";
            else if (static_cast<uint8_t>(c) < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c));
                s += b;
            } else {
                s += c;
            }
        }
        s += "\", \"last_opened\": ";
        s += std::to_string(vaults[k].last_opened);
        s += "}";
    }
    s += vaults.empty() ? "]\n}\n" : "\n  ]\n}\n";
    return s;
}

void history_touch(std::vector<RecentVault>* v, const std::string& path, uint64_t now,
                   bool fold_case) {
    if (!storable(path)) return;  // could not be read back: do not record it
    history_forget(v, path, fold_case);
    RecentVault r;
    r.path = path;
    r.last_opened = now;
    v->insert(v->begin(), r);
    if (v->size() > HISTORY_MAX) v->resize(HISTORY_MAX);
}

void history_forget(std::vector<RecentVault>* v, const std::string& path, bool fold_case) {
    for (size_t k = 0; k < v->size();) {
        if (same_path((*v)[k].path, path, fold_case)) v->erase(v->begin() + static_cast<long>(k));
        else ++k;
    }
}

}  // namespace secraxis
