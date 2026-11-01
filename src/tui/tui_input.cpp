#include "secraxis/tui_input.h"

#include <cstring>
#include <initializer_list>
#include <string>

#include "secraxis/secure_buffer.h"
#include "secraxis/tui_text.h"

namespace secraxis {

namespace {

using C = KeyEvent::Code;

constexpr size_t MAX_CSI = 64;      // longer "CSI" input is garbage: drop ESC
constexpr size_t MAX_STRING = 512;  // OSC/DCS/APC/PM/SOS payload cap

// Length of the UTF-8 sequence a lead byte announces (0 = not a lead byte).
size_t utf8_len(uint8_t b) {
    if (b < 0x80) return 1;
    if (b >= 0xC2 && b <= 0xDF) return 2;
    if (b >= 0xE0 && b <= 0xEF) return 3;
    if (b >= 0xF0 && b <= 0xF4) return 4;
    return 0;
}

// True if buf[0..n) is a proper prefix of a UTF-8 sequence that may still
// complete (so the decoder should wait for more bytes).
bool utf8_incomplete(const char* buf, size_t n) {
    const size_t need = utf8_len(static_cast<uint8_t>(buf[0]));
    if (need <= 1 || n >= need) return false;
    for (size_t k = 1; k < n; ++k)
        if ((static_cast<uint8_t>(buf[k]) & 0xC0) != 0x80) return false;
    return true;
}

// First numeric CSI parameter (default 1).
unsigned first_param(const char* p, size_t n) {
    unsigned v = 0;
    bool any = false;
    for (size_t k = 0; k < n; ++k) {
        const char c = p[k];
        if (c < '0' || c > '9') break;
        if (v < 100000) v = v * 10 + static_cast<unsigned>(c - '0');
        any = true;
    }
    return any ? v : 1;
}

bool key_from_csi(char final, unsigned p1, KeyEvent* out) {
    switch (final) {
        case 'A': *out = KeyEvent::key(C::Up); return true;
        case 'B': *out = KeyEvent::key(C::Down); return true;
        case 'C': *out = KeyEvent::key(C::Right); return true;
        case 'D': *out = KeyEvent::key(C::Left); return true;
        case 'H': *out = KeyEvent::key(C::Home); return true;
        case 'F': *out = KeyEvent::key(C::End); return true;
        case 'Z': *out = KeyEvent::key(C::BackTab); return true;
        case '~':
            switch (p1) {
                case 1: case 7: *out = KeyEvent::key(C::Home); return true;
                case 4: case 8: *out = KeyEvent::key(C::End); return true;
                case 3: *out = KeyEvent::key(C::Del); return true;
                case 5: *out = KeyEvent::key(C::PageUp); return true;
                case 6: *out = KeyEvent::key(C::PageDown); return true;
                default: return false;
            }
        default:
            return false;
    }
}

}  // namespace

void InputDecoder::clear() noexcept {
    secure_wipe(buf_, sizeof(buf_));
    len_ = 0;
    paste_ = false;
}

void InputDecoder::consume(size_t n) noexcept {
    if (n > len_) n = len_;
    std::memmove(buf_, buf_ + n, len_ - n);
    secure_wipe(buf_ + len_ - n, n);
    len_ -= n;
}

size_t InputDecoder::feed(const char* p, size_t n) {
    const size_t room = CAPACITY - len_;
    const size_t take = n < room ? n : room;
    std::memcpy(buf_ + len_, p, take);
    len_ += take;
    return take;
}

bool InputDecoder::next(KeyEvent* out, bool flush) {
    while (len_ > 0) {
        bool have = false;
        const size_t used = parse(out, &have, flush);
        if (used == 0) return false;  // need more bytes
        consume(used);
        if (have) return true;
    }
    return false;
}

size_t InputDecoder::parse(KeyEvent* out, bool* have, bool flush) {
    const uint8_t b = static_cast<uint8_t>(buf_[0]);
    static const char kPasteEnd[] = "\x1b[201~";
    constexpr size_t kPasteEndLen = sizeof(kPasteEnd) - 1;

    if (paste_) {
        if (b == 0x1b) {
            const size_t m = len_ < kPasteEndLen ? len_ : kPasteEndLen;
            if (std::memcmp(buf_, kPasteEnd, m) == 0) {
                if (m == kPasteEndLen) {
                    paste_ = false;
                    return kPasteEndLen;
                }
                return 0;  // maybe the end marker: wait (never flushed)
            }
            return 1;  // a stray ESC inside the paste: drop it
        }
        if (utf8_incomplete(buf_, len_)) return 0;
        size_t i = 0;
        char32_t cp = 0;
        if (!utf8_decode(buf_, len_, &i, &cp)) return i;
        if (cp >= 0x20 && cp != 0x7F && is_text_cp(cp)) {
            *out = KeyEvent::chr(cp, KEYMOD_PASTE);
            *have = true;
        }
        return i;  // CR, LF, TAB and other controls are dropped
    }

    if (b == 0x1b) {
        if (len_ == 1) {
            if (!flush) return 0;
            *out = KeyEvent::key(C::Esc);
            *have = true;
            return 1;
        }
        const char b1 = buf_[1];
        if (b1 == '[') {
            size_t k = 2;
            while (k < len_ && k < MAX_CSI) {
                const uint8_t c = static_cast<uint8_t>(buf_[k]);
                if (c >= 0x40 && c <= 0x7E) break;      // final byte
                if (c < 0x20 || c > 0x3F) return 1;    // not a CSI: drop ESC
                ++k;
            }
            if (k >= MAX_CSI) return 1;
            // Incomplete: wait, however long, for the rest. A timeout would
            // turn its tail into typed keys (a split "ESC[200~" would run a
            // paste as commands). Any byte that cannot continue a CSI ends it.
            if (k >= len_) return 0;
            const char final = buf_[k];
            if (k == 2 && final == 'M') {
                // Old-style mouse report (terminals without SGR mode 1006):
                // CSI M, then button, column and row as raw bytes + 32. Its
                // three bytes must never be read as keys.
                if (len_ < 6) return 0;
                const unsigned cb = static_cast<uint8_t>(buf_[3]);
                const unsigned cx = static_cast<uint8_t>(buf_[4]);
                const unsigned cy = static_cast<uint8_t>(buf_[5]);
                if (cb < 32 || cx < 33 || cy < 33) return 6;  // malformed: drop
                const unsigned v = cb - 32;
                if (v & 32) return 6;  // motion: not used
                KeyEvent::Pointer kind = KeyEvent::Pointer::Press;
                uint8_t button = static_cast<uint8_t>(v & 3u);
                if (v & 64) {
                    kind = (v & 1u) ? KeyEvent::Pointer::WheelDown : KeyEvent::Pointer::WheelUp;
                    button = 0;
                } else if (button == 3) {
                    kind = KeyEvent::Pointer::Release;  // this encoding does not say which
                    button = 0;
                }
                *out = KeyEvent::mouse(kind, button, static_cast<int16_t>(cx - 33),
                                       static_cast<int16_t>(cy - 33));
                *have = true;
                return 6;
            }
            if (buf_[2] == '<' && (final == 'M' || final == 'm')) {
                // SGR mouse report: CSI < button ; column ; row M|m (1-based).
                unsigned v[3] = {0, 0, 0};
                int idx = 0;
                for (size_t q = 3; q < k && idx < 3; ++q) {
                    const char c = buf_[q];
                    if (c == ';') {
                        ++idx;
                    } else if (c >= '0' && c <= '9') {
                        if (v[idx] < 100000) v[idx] = v[idx] * 10 + static_cast<unsigned>(c - '0');
                    } else {
                        return k + 1;  // malformed: drop it
                    }
                }
                if (idx != 2 || v[1] == 0 || v[2] == 0 || v[1] > 10000 || v[2] > 10000)
                    return k + 1;
                if (v[0] & 32) return k + 1;  // motion: not used
                const int16_t px = static_cast<int16_t>(v[1] - 1);
                const int16_t py = static_cast<int16_t>(v[2] - 1);
                KeyEvent::Pointer kind = final == 'M' ? KeyEvent::Pointer::Press
                                                      : KeyEvent::Pointer::Release;
                uint8_t button = static_cast<uint8_t>(v[0] & 3u);
                if (v[0] & 64) {
                    kind = (v[0] & 1u) ? KeyEvent::Pointer::WheelDown : KeyEvent::Pointer::WheelUp;
                    button = 0;
                }
                *out = KeyEvent::mouse(kind, button, px, py);
                *have = true;
                return k + 1;
            }
            const unsigned p1 = first_param(buf_ + 2, k - 2);
            if (final == '~' && p1 == 200) {
                paste_ = true;
                return k + 1;
            }
            KeyEvent ev;
            if (key_from_csi(final, p1, &ev)) {
                *out = ev;
                *have = true;
            }
            return k + 1;  // unknown sequences (incl. late probe replies) vanish
        }
        if (b1 == 'O') {
            if (len_ < 3) return 0;
            KeyEvent ev;
            if (key_from_csi(buf_[2], 1, &ev)) {
                *out = ev;
                *have = true;
            }
            return 3;
        }
        if (b1 == ']' || b1 == 'P' || b1 == '_' || b1 == '^' || b1 == 'X') {
            // String sequence (e.g. a color-query reply): skip to BEL or ST.
            for (size_t k = 2; k < len_ && k < MAX_STRING; ++k) {
                if (buf_[k] == '\x07') return k + 1;
                if (buf_[k] == '\x1b' && k + 1 < len_ && buf_[k + 1] == '\\')
                    return k + 2;
            }
            if (len_ >= MAX_STRING) return MAX_STRING;
            return flush ? len_ : 0;
        }
        // ESC + anything else: a plain Esc; the next byte is its own key.
        *out = KeyEvent::key(C::Esc);
        *have = true;
        return 1;
    }

    if (b == '\r' || b == '\n') {
        *out = KeyEvent::key(C::Enter);
        *have = true;
        return 1;
    }
    if (b == '\t') {
        *out = KeyEvent::key(C::Tab);
        *have = true;
        return 1;
    }
    if (b == 0x7F || b == 0x08) {
        *out = KeyEvent::key(C::Backspace);
        *have = true;
        return 1;
    }
    if (b >= 0x01 && b <= 0x1A) {
        *out = KeyEvent::chr(static_cast<char32_t>(U'a' + (b - 1)), KEYMOD_CTRL);
        *have = true;
        return 1;
    }
    if (b < 0x20) return 1;  // NUL, FS..US: ignored

    // A character split across reads waits for its rest (a byte that cannot
    // continue it ends it: the lead byte is then dropped as ill-formed).
    if (utf8_incomplete(buf_, len_)) return 0;
    size_t i = 0;
    char32_t cp = 0;
    if (!utf8_decode(buf_, len_, &i, &cp)) return i;  // ill-formed: drop
    if (is_text_cp(cp)) {
        *out = KeyEvent::chr(cp);
        *have = true;
    }
    return i;
}

int InputDecoder::partial_wait_ms() const noexcept {
    if (!paste_ && len_ >= 2 && buf_[0] == '\x1b' &&
        (buf_[1] == ']' || buf_[1] == 'P' || buf_[1] == '_' || buf_[1] == '^' || buf_[1] == 'X'))
        return 1000;
    return 25;
}

bool Utf16Assembler::push(uint16_t unit, char32_t* cp) noexcept {
    if (unit >= 0xD800 && unit <= 0xDBFF) {
        high_ = unit;
        return false;
    }
    if (unit >= 0xDC00 && unit <= 0xDFFF) {
        if (high_ == 0) return false;  // lone low surrogate
        *cp = 0x10000 + ((static_cast<char32_t>(high_) - 0xD800) << 10) +
              (static_cast<char32_t>(unit) - 0xDC00);
        high_ = 0;
        return true;
    }
    high_ = 0;  // a lone high surrogate followed by a BMP unit is dropped
    *cp = unit;
    return true;
}

// ---------------------------------------------------------------------------
// Terminal identification
// ---------------------------------------------------------------------------
void scan_term_ident(const char* buf, size_t n, TermIdent* id) {
    for (size_t i = 0; i + 3 < n; ++i) {
        if (buf[i] != '\x1b') continue;
        if (buf[i + 1] == 'P' && buf[i + 2] == '>' && buf[i + 3] == '|') {
            std::string v;
            for (size_t k = i + 4; k < n && buf[k] != '\x1b' && buf[k] != '\x07' && v.size() < 64;
                 ++k)
                if (buf[k] >= 0x20 && buf[k] < 0x7f) v += buf[k];
            id->version = v;
        } else if (buf[i + 1] == '[' && buf[i + 2] == '>') {
            int vals[3] = {-1, -1, -1};
            int at = 0, v = -1;
            size_t k = i + 3;
            for (; k < n && at < 3; ++k) {
                const char ch = buf[k];
                if (ch >= '0' && ch <= '9') {
                    v = (v < 0 ? 0 : v) * 10 + (ch - '0');
                    if (v > 1000000) v = 1000000;
                } else if (ch == ';') {
                    vals[at++] = v;
                    v = -1;
                } else {
                    break;
                }
            }
            if (k < n && buf[k] == 'c') {
                if (at < 3) vals[at] = v;
                for (int q = 0; q < 3; ++q) id->da2[q] = vals[q];
            }
        }
    }
}

namespace {
bool named(const TermIdent& id, std::initializer_list<const char*> names) {
    for (const char* n : names)
        if (id.version.find(n) != std::string::npos) return true;
    return false;
}
}  // namespace

TermTraits term_traits(const TermIdent& id) {
    TermTraits t;
    // VTE: XTVERSION "VTE(7600)"; before it answered that, DA2 65, or 61
    // with its version. The Microsoft consoles: no XTVERSION, DA2 0;10;1.
    t.vte = named(id, {"VTE"}) || id.da2[0] == 65 || (id.da2[0] == 61 && id.da2[1] >= 4000);
    t.microsoft = id.da2[0] == 0 && id.da2[1] == 10 && id.da2[2] == 1;
    const bool modern = named(id, {"kitty", "WezTerm", "iTerm2", "foot", "Konsole", "ghostty",
                                   "Ghostty", "contour", "rio"});
    t.truecolor = t.vte || t.microsoft || modern || named(id, {"Alacritty"});
    t.color256 = t.truecolor || named(id, {"XTerm"}) || id.da2[0] == 41;
    t.emoji = t.vte || t.microsoft || modern;
    // PuTTY draws only what its one font has.
    t.plain = id.da2[0] == 0 && id.da2[1] == 136 && id.da2[2] == 0;
    // OSC 52: VTE never takes it; xterm only when its user allows it.
    if (t.vte || named(id, {"XTerm"}) || id.da2[0] == 41)
        t.clipboard_escapes = 0;
    else if (t.microsoft || modern || named(id, {"Alacritty"}))
        t.clipboard_escapes = 1;
    return t;
}

}  // namespace secraxis
