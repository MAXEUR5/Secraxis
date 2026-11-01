#include "secraxis/settings.h"

namespace secraxis {

namespace {

// Reader for exactly the settings shape: one object of known keys, each at
// most once, the version required. Keys and values are short words of
// lowercase letters, so strings with escapes are simply rejected.
class Reader {
  public:
    Reader(const char* p, size_t n) : p_(p), n_(n) {}

    bool document(Settings* out) {
        ws();
        if (!eat('{')) return false;
        bool have_version = false, have_save = false, have_unattended = false;
        for (;;) {
            std::string key, value;
            ws();
            if (!word(&key)) return false;
            ws();
            if (!eat(':')) return false;
            ws();
            if (key == "version" && !have_version) {
                if (!eat('1') || digit()) return false;  // the only version
                have_version = true;
            } else if (key == "save" && !have_save) {
                if (!word(&value)) return false;
                if (value == "manual") out->save = SaveMode::Manual;
                else if (value == "auto") out->save = SaveMode::Auto;
                else return false;
                have_save = true;
            } else if (key == "unattended" && !have_unattended) {
                if (!word(&value)) return false;
                if (value == "save") out->unattended = Unattended::Save;
                else if (value == "discard") out->unattended = Unattended::Discard;
                else return false;
                have_unattended = true;
            } else {
                return false;  // unknown or duplicate key
            }
            ws();
            if (eat(',')) continue;
            if (eat('}')) break;
            return false;
        }
        ws();
        return have_version && i_ == n_;
    }

  private:
    char peek() const { return i_ < n_ ? p_[i_] : '\0'; }
    bool digit() const { return peek() >= '0' && peek() <= '9'; }
    bool eat(char c) {
        if (peek() != c) return false;
        ++i_;
        return true;
    }
    void ws() {
        while (i_ < n_ && (p_[i_] == ' ' || p_[i_] == '\t' || p_[i_] == '\n' || p_[i_] == '\r'))
            ++i_;
    }
    // "word": 1 to 16 of a-z and '_'.
    bool word(std::string* out) {
        out->clear();
        if (!eat('"')) return false;
        while (i_ < n_ && p_[i_] != '"') {
            const char c = p_[i_++];
            if (!((c >= 'a' && c <= 'z') || c == '_') || out->size() >= 16) return false;
            out->push_back(c);
        }
        return !out->empty() && eat('"');
    }

    const char* p_;
    size_t n_;
    size_t i_ = 0;
};

}  // namespace

bool parse_settings(ByteView json, Settings* out) {
    *out = Settings();
    if (json.len == 0 || json.len > SETTINGS_FILE_MAX) return false;
    Reader r(reinterpret_cast<const char*>(json.ptr), json.len);
    if (!r.document(out)) {
        *out = Settings();
        return false;
    }
    return true;
}

std::string serialize_settings(const Settings& s) {
    std::string out = "{\n  \"version\": 1,\n  \"save\": \"";
    out += s.save == SaveMode::Auto ? "auto" : "manual";
    out += "\",\n  \"unattended\": \"";
    out += s.unattended == Unattended::Discard ? "discard" : "save";
    out += "\"\n}\n";
    return out;
}

}  // namespace secraxis
