#include "secraxis/tui_screen.h"

#include <cstdio>
#include <cstring>

#include "secraxis/secure_buffer.h"

namespace secraxis {

// ---------------------------------------------------------------------------
// WipeBuffer
// ---------------------------------------------------------------------------
void WipeBuffer::append(const char* p, size_t n) {
    if (n == 0) return;
    if (len_ + n > buf_.size()) {
        size_t cap = buf_.size() < 4096 ? 4096 : buf_.size() * 2;
        while (cap < len_ + n) cap *= 2;
        std::vector<char> bigger(cap);
        if (len_ > 0) std::memcpy(bigger.data(), buf_.data(), len_);
        if (!buf_.empty()) secure_wipe(buf_.data(), buf_.size());
        buf_.swap(bigger);
    }
    std::memcpy(buf_.data() + len_, p, n);
    len_ += n;
}

void WipeBuffer::truncate(size_t n) noexcept {
    if (n >= len_) return;
    secure_wipe(buf_.data() + n, len_ - n);
    len_ = n;
}

void WipeBuffer::clear() noexcept { truncate(0); }

void WipeBuffer::release() noexcept {
    if (!buf_.empty()) secure_wipe(buf_.data(), buf_.size());
    std::vector<char>().swap(buf_);
    len_ = 0;
}

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------
namespace {

constexpr uint8_t kCube[6] = {0, 95, 135, 175, 215, 255};

uint32_t sq(int v) { return static_cast<uint32_t>(v * v); }

int nearest_cube(int v) {
    int best = 0;
    for (int k = 1; k < 6; ++k)
        if (sq(v - kCube[k]) < sq(v - kCube[best])) best = k;
    return best;
}

void append_num(unsigned v, WipeBuffer* out) {
    char b[12];
    const int n = std::snprintf(b, sizeof(b), "%u", v);
    if (n > 0) out->append(b, static_cast<size_t>(n));
}

void append_color(Color c, bool bg, ColorDepth depth, WipeBuffer* out) {
    if (c == 0 || depth == ColorDepth::None) return;
    const unsigned r = (c >> 16) & 0xFFu, g = (c >> 8) & 0xFFu, b = c & 0xFFu;
    switch (depth) {
        case ColorDepth::TrueColor:
            out->append(bg ? ";48;2;" : ";38;2;");
            append_num(r, out);
            out->push(';');
            append_num(g, out);
            out->push(';');
            append_num(b, out);
            return;
        case ColorDepth::Ansi256:
            out->append(bg ? ";48;5;" : ";38;5;");
            append_num(rgb_to_xterm256(c & 0xFFFFFFu), out);
            return;
        case ColorDepth::Ansi16: {
            const unsigned idx = (c >> 24) & 15u;
            const unsigned base = idx < 8 ? (bg ? 40u : 30u) : (bg ? 100u : 90u);
            out->push(';');
            append_num(base + (idx & 7u), out);
            return;
        }
        case ColorDepth::None:
            return;
    }
}

void append_cup(int x, int y, WipeBuffer* out) {
    out->append("\x1b[");
    append_num(static_cast<unsigned>(y + 1), out);
    out->push(';');
    append_num(static_cast<unsigned>(x + 1), out);
    out->push('H');
}

void append_cell_text(const Cell& c, WipeBuffer* out) {
    for (uint8_t k = 0; k < c.ncp; ++k) {
        char b[4];
        out->append(b, utf8_encode(c.cp[k], b));
        secure_wipe(b, sizeof(b));
    }
}

bool blank_default(const Cell& c) {
    return c.width == 1 && c.ncp == 1 && c.cp[0] == U' ' && c.style == Style();
}

}  // namespace

uint8_t rgb_to_xterm256(uint32_t rgb) noexcept {
    const int r = static_cast<int>((rgb >> 16) & 0xFF);
    const int g = static_cast<int>((rgb >> 8) & 0xFF);
    const int b = static_cast<int>(rgb & 0xFF);
    const int cr = nearest_cube(r), cg = nearest_cube(g), cb = nearest_cube(b);
    const uint32_t cube_d =
        sq(r - kCube[cr]) + sq(g - kCube[cg]) + sq(b - kCube[cb]);
    // Grayscale ramp 232..255 = 8, 18, ..., 238.
    const int avg = (r + g + b) / 3;
    int gi = (avg - 8 + 5) / 10;
    if (gi < 0) gi = 0;
    if (gi > 23) gi = 23;
    const int gv = 8 + 10 * gi;
    const uint32_t gray_d = sq(r - gv) + sq(g - gv) + sq(b - gv);
    if (gray_d < cube_d) return static_cast<uint8_t>(232 + gi);
    return static_cast<uint8_t>(16 + 36 * cr + 6 * cg + cb);
}

void append_sgr(const Style& st, ColorDepth depth, WipeBuffer* out) {
    out->append("\x1b[0");
    if (st.attrs & ATTR_BOLD) out->append(";1");
    if (st.attrs & ATTR_DIM) out->append(";2");
    if (st.attrs & ATTR_UNDERLINE) out->append(";4");
    if (st.attrs & ATTR_REVERSE) out->append(";7");
    append_color(st.fg, false, depth, out);
    append_color(st.bg, true, depth, out);
    out->push('m');
}

// ---------------------------------------------------------------------------
// ScreenWriter
// ---------------------------------------------------------------------------
void ScreenWriter::clear() noexcept {
    prev_.clear();
    valid_ = false;
}

void ScreenWriter::diff(const Canvas& next, ColorDepth depth, bool sync,
                        WipeBuffer* out) {
    const int cols = next.cols(), rows = next.rows();
    const bool full = !valid_ || prev_.cols() != cols || prev_.rows() != rows;
    const size_t start_len = out->size();
    if (sync) out->append("\x1b[?2026h");
    if (full) out->append("\x1b[0m\x1b[2J");

    bool style_known = false;
    Style cur_style;
    bool pos_known = false;
    int px = 0, py = 0;
    size_t cell_bytes = 0;

    dirty_.assign(static_cast<size_t>(cols), 0);
    for (int y = 0; y < rows; ++y) {
        // 1. Which cells differ from what the terminal shows?
        for (int x = 0; x < cols; ++x)
            dirty_[static_cast<size_t>(x)] =
                full ? !blank_default(next.at(x, y))
                     : !same_cell(prev_.at(x, y), next.at(x, y));
        if (!full) {
            // Writing over either half of an old wide pair erases the whole
            // pair on the terminal, so its partner must be redrawn too.
            for (int x = 0; x < cols; ++x) {
                if (!dirty_[static_cast<size_t>(x)]) continue;
                const Cell& o = prev_.at(x, y);
                if (o.width == 2 && x + 1 < cols) dirty_[static_cast<size_t>(x + 1)] = 1;
                if (o.width == 0 && x > 0) dirty_[static_cast<size_t>(x - 1)] = 1;
            }
        }
        // A changed continuation is redrawn through its lead.
        for (int x = cols - 1; x > 0; --x)
            if (dirty_[static_cast<size_t>(x)] && next.at(x, y).width == 0)
                dirty_[static_cast<size_t>(x - 1)] = 1;
        // A glyph the terminal might draw wider than we measured can spill
        // into its right neighbor; repaint the neighbor after it (left to
        // right, so the neighbor wins and the spill is clipped).
        for (int x = 0; x + 1 < cols; ++x) {
            if (!dirty_[static_cast<size_t>(x)]) continue;
            const Cell& c = next.at(x, y);
            if (c.width == 1 && !(c.flags & CELL_TRUSTED)) dirty_[static_cast<size_t>(x + 1)] = 1;
        }

        // 2. Emit.
        for (int x = 0; x < cols; ++x) {
            if (!dirty_[static_cast<size_t>(x)]) continue;
            const Cell& c = next.at(x, y);
            if (c.width == 0) continue;
            if (!style_known || c.style != cur_style) {
                append_sgr(c.style, depth, out);
                cur_style = c.style;
                style_known = true;
            }
            const size_t before = out->size();
            if (c.width == 2) {
                // Blank the right half first: a terminal that thinks this
                // character is narrow then shows a space there, not stale text.
                append_cup(x + 1, y, out);
                out->push(' ');
                append_cup(x, y, out);
                append_cell_text(c, out);
                pos_known = false;
            } else {
                if (!pos_known || px != x || py != y) append_cup(x, y, out);
                append_cell_text(c, out);
                const bool trusted = (c.flags & CELL_TRUSTED) != 0;
                px = x + 1;
                py = y;
                pos_known = trusted && px < cols;
            }
            cell_bytes += out->size() - before;
        }
    }

    const bool cursor_changed =
        full || next.cursor_visible() != prev_.cursor_visible() ||
        (next.cursor_visible() &&
         (next.cursor_x() != prev_.cursor_x() || next.cursor_y() != prev_.cursor_y()));
    if (cell_bytes == 0 && !full && !cursor_changed) {
        out->truncate(start_len);  // nothing changed: emit nothing at all
        return;
    }
    out->append("\x1b[0m");
    if (next.cursor_visible()) {
        append_cup(next.cursor_x(), next.cursor_y(), out);
        out->append("\x1b[?25h");
    } else {
        out->append("\x1b[?25l");
    }
    if (sync) out->append("\x1b[?2026l");
    prev_.copy_from(next);
    valid_ = true;
}

}  // namespace secraxis
