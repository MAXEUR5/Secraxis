#include "secraxis/tui_text.h"

namespace secraxis {

namespace {

struct CpRange {
    char32_t lo, hi;
};

#include "unicode_tables.inc"

template <size_t N>
bool in_table(const CpRange (&t)[N], char32_t cp) noexcept {
    size_t lo = 0, hi = N;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (cp < t[mid].lo) {
            hi = mid;
        } else if (cp > t[mid].hi) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

bool is_variation_selector(char32_t cp) noexcept {
    return cp == 0xFE0E || cp == 0xFE0F;
}

}  // namespace

CpClass classify_cp(char32_t cp) noexcept {
    if (cp > 0x10FFFF) return CpClass::Unsafe;
    if (cp >= 0x20 && cp < 0x7F) return CpClass::Narrow;  // ASCII fast path
    if (in_table(kUnsafe, cp)) return CpClass::Unsafe;
    if (in_table(kZeroWidth, cp)) return CpClass::Zero;
    if (in_table(kWide, cp)) return CpClass::Wide;
    if (in_table(kAmbiguous, cp)) return CpClass::Ambiguous;
    return CpClass::Narrow;
}

bool utf8_decode(const char* s, size_t n, size_t* i, char32_t* cp) noexcept {
    const auto at = [&](size_t k) { return static_cast<uint8_t>(s[k]); };
    const size_t p = *i;
    const uint8_t b0 = at(p);
    if (b0 < 0x80) {
        *cp = b0;
        *i = p + 1;
        return true;
    }
    // Table 3-7 (well-formed UTF-8): lead byte decides length and the legal
    // range of the second byte; further bytes are 80..BF.
    size_t len = 0;
    uint8_t lo2 = 0x80, hi2 = 0xBF;
    char32_t v = 0;
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        len = 2; v = b0 & 0x1Fu;
    } else if (b0 >= 0xE0 && b0 <= 0xEF) {
        len = 3; v = b0 & 0x0Fu;
        if (b0 == 0xE0) lo2 = 0xA0;   // no overlongs
        if (b0 == 0xED) hi2 = 0x9F;   // no surrogates
    } else if (b0 >= 0xF0 && b0 <= 0xF4) {
        len = 4; v = b0 & 0x07u;
        if (b0 == 0xF0) lo2 = 0x90;   // no overlongs
        if (b0 == 0xF4) hi2 = 0x8F;   // <= U+10FFFF
    } else {
        *i = p + 1;                   // C0, C1, F5..FF, stray continuation
        return false;
    }
    for (size_t k = 1; k < len; ++k) {
        if (p + k >= n) {
            *i = p + k;               // truncated: consume the valid prefix
            return false;
        }
        const uint8_t b = at(p + k);
        const uint8_t lo = (k == 1) ? lo2 : 0x80;
        const uint8_t hi = (k == 1) ? hi2 : 0xBF;
        if (b < lo || b > hi) {
            *i = p + k;               // maximal subpart ends before b
            return false;
        }
        v = (v << 6) | (b & 0x3Fu);
    }
    *cp = v;
    *i = p + len;
    return true;
}

size_t utf8_encode(char32_t cp, char out[4]) noexcept {
    if (cp < 0x80) {
        out[0] = static_cast<char>(cp);
        return 1;
    }
    if (cp < 0x800) {
        out[0] = static_cast<char>(0xC0 | (cp >> 6));
        out[1] = static_cast<char>(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = static_cast<char>(0xE0 | (cp >> 12));
        out[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out[2] = static_cast<char>(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = static_cast<char>(0xF0 | (cp >> 18));
    out[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out[3] = static_cast<char>(0x80 | (cp & 0x3F));
    return 4;
}

bool is_text_cp(char32_t cp) noexcept {
    return classify_cp(cp) != CpClass::Unsafe;
}

bool next_cluster(const char* s, size_t n, size_t* i, const WidthPolicy& p,
                  Cluster* out) noexcept {
    while (*i < n) {
        Cluster c;
        char32_t cp = 0;
        if (!utf8_decode(s, n, i, &cp)) {
            c.placeholder = true;
            *out = c;
            return true;
        }
        if (is_variation_selector(cp)) continue;  // presentation hint: drop
        const CpClass cls = classify_cp(cp);
        if (cls == CpClass::Unsafe || (!p.utf8 && cp >= 0x80)) {
            c.placeholder = true;
            *out = c;
            // Swallow marks that would otherwise attach to the placeholder.
            while (*i < n) {
                size_t j = *i;
                char32_t nx = 0;
                if (!utf8_decode(s, n, &j, &nx)) break;
                if (classify_cp(nx) != CpClass::Zero && !is_variation_selector(nx))
                    break;
                *i = j;
            }
            return true;
        }
        if (cls == CpClass::Zero) {
            // A mark with no base must not combine with whatever the terminal
            // drew before it (a border, another field): give it a space base.
            c.cp[0] = U' ';
            c.cp[1] = cp;
            c.ncp = 2;
        } else {
            c.cp[0] = cp;
            c.ncp = 1;
            if (cls == CpClass::Wide) {
                if (!p.wide_ok) {
                    c.placeholder = true;
                    c.ncp = 0;
                } else {
                    c.width = 2;
                }
            } else if (cls == CpClass::Ambiguous && p.ambiguous_wide && !p.is_narrow(cp)) {
                c.width = 2;
            }
        }
        // Absorb following zero-width code points (marks, ZWJ/ZWNJ).
        while (*i < n) {
            size_t j = *i;
            char32_t nx = 0;
            if (!utf8_decode(s, n, &j, &nx)) break;
            if (is_variation_selector(nx)) {
                *i = j;
                continue;
            }
            if (classify_cp(nx) != CpClass::Zero) break;
            *i = j;
            // ASCII-only terminals get the base letter alone.
            if (!c.placeholder && p.utf8 && c.ncp < 1 + Cluster::MAX_COMBINING)
                c.cp[c.ncp++] = nx;
        }
        *out = c;
        return true;
    }
    return false;
}

size_t display_width(std::string_view s, const WidthPolicy& p) noexcept {
    size_t i = 0, w = 0;
    Cluster c;
    while (next_cluster(s.data(), s.size(), &i, p, &c)) w += c.width;
    return w;
}

const char* unicode_tables_version() noexcept { return kUnicodeVersion; }

}  // namespace secraxis
