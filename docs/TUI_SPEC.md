# TUI Specification

This is the technical specification of the terminal interface; how to use
the program is described in `MANUAL.md` at the repository root. Version
0.9.2 is built and tested on Windows 11 and Linux. The macOS code paths
mentioned below (the config folder, `pbcopy`/`pbpaste`) exist but are
neither built nor tested.

The TUI is split into pure logic and IO, so the whole interface is
headless-testable (`test_tui_machine`, `test_renderer`, `test_tui_text`,
`test_launcher`) and fuzzable end to end (`fuzz_tui`, `fuzz_history`):

```
keys ─▶ TuiMachine ─▶ RenderModel ─▶ render() ─▶ Canvas ─▶ ScreenWriter ─▶ terminal
        (tui_core)                    (renderer)  (cells)   (changed cells only)
mouse ─▶ hit_test(zones of the last frame) ─▶ the same key events
```

| Module | Role |
|---|---|
| `tui_core` | `TuiMachine`: every state transition and secret-exposure rule; no IO, threads or clock of its own |
| `launcher` | `Launcher`: the start page (recent vaults, folder browser, new-vault form); pure, like the machine |
| `tui_text` | strict UTF-8, display-width classes (generated tables), cell clustering, **the sanitizer** |
| `tui_input` | terminal input decoding (keys, UTF-8, bracketed paste, SGR mouse reports; UTF-16 assembly for Win32) |
| `canvas` | the cell grid, styles, glyph tiers, probe decisions |
| `ui_kit` | the theme and shared components: dialogs, buttons, key hints, toasts, entry badges, hit zones |
| `renderer`, `launcher_view` | `render()` / `render_launcher()`: layout and drawing, pure; each frame also returns its hit zones |
| `screen` | `ScreenWriter`: diffs frames into terminal bytes; `WipeBuffer` |
| `terminal` | raw mode, alternate screen, input (keys and mouse), resize, the startup probe |
| `clipboard` | `PlatformClipboard`: copy, clear-if-ours, and the clipboard read behind `Ctrl+V` (see Clipboard) |
| `history`, `settings`, `fs_dir` | the recent-vaults and settings files (strict parsers and writers); directory listing and the config folder |
| `app` | the loops (start page, vault): render → diff → write → input → tick; KDF worker thread |

Mouse input never reaches the machine as coordinates. `render()` records a
zone for everything clickable (list rows, form fields, buttons, key hints, the
search bar), and a click becomes the event that zone stands for: a key
(`Ctrl+R`, `y`, `/`, …) or a *pick* of a row or field. A click therefore can do
nothing a key cannot, and every rule below applies to it unchanged.

## Visual design

Quiet by default, with one accent color: the terminal's own background
everywhere, hairline frames only where a frame carries meaning (dialogs,
inputs), and a three-step text hierarchy (text, muted, subtle). Typography uses
weight, not decoration: bold for names and titles, small uppercase labels for
sections, muted color for secondary text. The terminal chooses the font; the
glyph tiers (below) keep every symbol inside what common console fonts carry.

Themes: dark and light palettes, each color 24-bit with an explicit ANSI-16
fallback (256-color terminals get the nearest xterm color). Monochrome
terminals (`NO_COLOR`, `--no-color`) get every distinction through attributes
(bold, underline, reverse). Light/dark comes from `--theme`, else the
terminal's reported background (OSC 11, POSIX), else `COLORFGBG`, else dark.

### Layout

```
 ◆ Secraxis  personal.seis              Argon2id Default · AES-256-GCM-SIV · 42 entries · ■ unsaved

   › Search                                       /  │  GW  GitHub Work
                                                     │      github.com
         NAME               USERNAME        UPDATED  │
  ┃  GW  GitHub Work        alex@example…    2d ago  │ USERNAME
     BA  Bank               alex             3w ago  │ alex@example.com                u copy
     工  工作邮箱           zhang.wei@ex…     today  │
                                                     │ PASSWORD
                                                     │ ••••••••••••             s show  p copy
                                                     │ ...
  ✓ Entry added.
  ↑↓ move · / search · a add · s show · p copy · m edit · d delete · w save · q lock · ? help
```

**Entry badges.** A four-cell tile before each name, in the list and the
details pane. Where the terminal draws emoji (Rich tier, and only if the probe
measured a two-cell advance), it is a kind icon guessed from the URL scheme,
tags and name, in English and Chinese: 💻 server/SSH, 📧 mail, 🏦 bank,
💳 payment, 📶 Wi-Fi, 💾 database, 🔧 code hosting, 💬 chat, 🛒 shopping,
🎮 games, ⛅ cloud, 🌐 other websites, 🔑 everything else. Elsewhere it is a
tinted tile with two initials (`GitHub Work` → `GW`, `GitHub` → `GH`,
`Bank` → `BA`) or one CJK character, its color fixed by the name. The guess
reads only metadata the overview already holds; no icon is fetched or
stored.

The agenda's five regions (§14.3) map to: title line, toast/status line,
content, the search bar as the input line, and the key-hint footer. The
content adapts to the window:

| Window | Layout |
|---|---|
| ≥ 100×16 | list + details pane (hairline divider) |
| ≥ 40×12, but under 100 columns or 16 rows | list; columns join while they fit (name, username, updated, monogram); Enter opens the details as a sheet |
| < 40×12 | "Window too small" with the required size; nothing from the vault is drawn |

The list scrolls with the selection (the machine is told how many rows the
layout shows), with a thumb when it overflows. Modal dialogs (add/edit, delete,
help, reveal, details sheet) sit on a faded copy of the screen, inside a clear
margin; a word the card cuts is wiped whole, so no stray letter touches its
border. The lock screen is a centered wordmark, the vault name, and a framed
password field with step dots when creating a vault. The field ends in a
`show`/`hide` pill (the entry form's); while the password is shown, the
label line says when it hides again, right-aligned with the field, where it
fits.

### Start page

`secraxis` without a vault path opens the start page (`Launcher`,
`launcher_view.cpp`):

```
              ███████╗███████╗ ██████╗██████╗  █████╗ ██╗  ██╗██╗███████╗
              ██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗██╔╝██║██╔════╝
              ...                                        (logo widget, 66×10)
                  =[ secraxis v0.9.2 - local password vault                 ]
           + -- --=[ AES-256-GCM-SIV - XChaCha20-Poly1305 - Argon2id        ]
           + -- --=[ 4 recent vaults - no cloud - no telemetry              ]

           RECENT VAULTS                                                    4

           ┃ 🔐 personal.seis          D:\Vaults                      2h ago
             🔐 team-shared.seis       C:\Users…lex\Documents\Work    3d ago
              ✗ archive-2023.seis      D:\Old                        missing

                            n  New vault    o  Open a vault

           tip  Esc always steps back one level.
  ↑↓ move · enter open · n new · o browse · x forget · ? help · q quit
```

- **The logo is a fixed-size widget.** The block-letter logo (59×6, drawn
  with the probe-verified block glyphs, or a figlet ASCII form on terminals
  without them) and the info block are always 66×10 cells. The home screen is
  one fixed-height composition (logo, an eight-row list region, the buttons)
  centered as a block, so neither the window size nor the number of recent
  vaults moves or resizes anything; the list scrolls past eight. In windows
  narrower than 70 columns or shorter than 23 rows a two-row wordmark
  replaces the logo; below 13 rows neither is drawn, and the title line
  alone names the program.
- **Recent vaults**: file name, folder (shortened in the middle), last opened.
  A vault whose file is gone shows `missing` and stays until forgotten (`x`;
  forgetting never touches the file). Enter or a double-click opens one.
- **Open a vault** (`o`): a folder browser listing folders and `.seis` files
  (hidden entries skipped; on Windows the root lists the drives). Typing
  filters the listing; a typed path (`~`, absolute, or containing a
  separator) is followed on Enter; Backspace on an empty filter goes up.
- **New vault** (`n`): name, folder (`Ctrl+O` browses, in a pick-a-folder
  mode) and the KDF profile (Floor, Default, Strong). `Ctrl+S` continues to
  the master-password screen in create mode. The name is a file name only
  (no separators, characters Windows forbids or Windows device names such as
  `CON` or `NUL`), and an existing file is never overwritten.
- `Esc` on the lock screen of a vault opened from the start page goes back to
  the start page, before unlocking or after locking.

The recent-vaults list lives in `recent.json` in the config folder
(Windows: `%APPDATA%\Secraxis`; Linux: `$XDG_CONFIG_HOME/secraxis` or
`~/.config/secraxis`; the macOS code:
`~/Library/Application Support/Secraxis`; `SECRAXIS_CONFIG_DIR`
overrides). It holds absolute vault paths and last-opened times only, at
most 12 entries, written atomically. The reader is strict like every other parser
(64 KiB file, 4096-byte paths, exact schema `{"version":1,"vaults":[{"path",
"last_opened"}]}`, paths with control or bidi characters rejected); a file it
rejects is treated as empty and replaced on the next write. A vault is
recorded once it unlocks, whether it was opened from the start page or the
command line. `--no-history` neither reads nor writes the file.

### Glyph tiers and the terminal probe

Agenda §14.2 permits Unicode drawing only if the renderer verifies terminal
support and width calculations. At startup `Terminal::probe` measures, on the
live terminal, the advance of **every** glyph it intends to draw (Win32: the
console's cursor position; POSIX: cursor-position reports, sent as one burst),
plus a CJK character and two East Asian Ambiguous letters:

- A glyph that is not exactly one cell falls back to its plainer (Basic,
  WGL4) form if that measured one cell, else to ASCII: a diamond the font
  lacks becomes a lozenge before it becomes `*`. The six frame glyphs fall
  back together (rounded, then square corners, then `+-|`).
- Ambiguous symbols measured at one cell are recorded, so text drawing agrees
  with the measurement (`WidthPolicy::narrow`).
- If ambiguous letters measure two cells (consoles with CJK fonts, terminals
  set to "ambiguous: wide"), ambiguous text is laid out as two cells, and the
  first screen says how to get the full set (one line, gone on the first key).
- No cursor reports (or `--ascii`): the agenda's ASCII set (`+-|`, `...`).

**Which tier is tried, and who is drawing.**

- *POSIX:* the probe also asks the terminal what it is (XTVERSION `CSI > 0
  q`, DA2 `CSI > c`, bounded by a cursor report; a DA2 answer that arrives
  after that report, as from Windows Terminal and the classic console over
  SSH, is waited for up to 250 ms). This matters most over SSH, where no
  environment variable crosses. Every UTF-8 terminal tries **Rich**; the
  Linux text console (`TERM=linux`) and PuTTY (DA2 `0;136;0`, one font, no
  fallback) try **Basic**. A C/POSIX locale (common on SSH logins) does not force ASCII:
  if the terminal draws the three bytes of `─` in one cell, it decodes UTF-8.
  The answers also set what the environment may not say
  (`scan_term_ident`/`term_traits` in `tui_input`, unit-tested on recorded
  answers): **24-bit color** for VTE (GNOME Terminal and kin), Windows
  Terminal, the classic console, kitty, WezTerm, iTerm2, foot, Konsole,
  Ghostty, Alacritty, **256 colors** for xterm (which says `TERM=xterm`),
  **emoji** for the same terminals but Alacritty, and whether the terminal
  takes **OSC 52** copies (see Clipboard).
  Answers are matched to questions safely: each step asks on a row of its
  own (the `─` gate on row 1, the CJK character on 2, the identification's
  closing report on 3, the glyph burst on 4) and sets aside a report from
  another row, which is a late answer to an earlier step; within the burst,
  after one answer fails to come in time the rest are left unknown (drawn
  plainly) rather than matched. Over SSH, where every answer is a round
  trip, the first may take 2 s and each later one three times as long as
  the first took (at most 2 s); the burst gets 5 s in all. Before, a late
  answer was taken for the next question's (over SSH to a busy host: the
  program started in ASCII, or drew CJK names as `?`).
- *Windows:* Windows Terminal and every other ConPTY host (recognized by its
  `PseudoConsoleWindow`, also when reached through the Windows 11
  default-terminal handoff, which sets no `WT_SESSION`) try **Rich**. The
  classic console tries Rich too once its font is right: the default font of
  Chinese, Japanese and Korean systems (新宋体/NSimSun, MS Gothic, ...) and
  the raster fonts draw accented letters and most symbols two cells wide,
  which forced ASCII stand-ins and spread out accented text. When an accented
  letter or `●` measures two cells, the console switches to Consolas for the
  session (Windows links CJK glyphs in from the system fonts) and restores
  its own font on exit; `--keep-font` keeps it.

Two optional sets ride on the same probe:

- **Emoji** (entry badges, vault and folder icons): Rich tier only, on
  terminals known to draw them (above), and kept only if the probe measures
  exactly two cells; otherwise letter tiles and plain glyphs.
- **Block glyphs** (`█ ═ ║ ╔ ╗ ╚ ╝`, the start-page logo): Rich and Basic,
  kept only if every one measures one cell; otherwise the logo is drawn in
  ASCII.

The probe measures widths, not whether the font has the glyph: a terminal
that advances two cells for an emoji it cannot draw shows a box there.
`--glyphs basic` turns emoji off.

### Wide characters and other scripts

- All text is UTF-8; widths come from tables generated from the Unicode
  database (`scripts/gen_unicode_tables.py`, Unicode 15.0): CJK/emoji two
  cells, combining marks zero (attached to their base, at most two per cell),
  ambiguous per the probe.
- Truncation and wrapping are width-aware and never split a character;
  truncation ends in `…` (or `...`).
- Input accepts any text code point (IME commits, surrogate pairs); editing
  moves by character and never stops inside a combining sequence.
- Edits keep other fields' bytes verbatim, including ill-formed bytes from an
  import.
- Search matches are highlighted (case-insensitive ASCII, as
  `VaultSession::query`).
- Right-to-left scripts are sent in logical order; the TUI applies no bidi
  reordering of its own. Some terminals (Konsole, and VTE-based ones such as
  GNOME Terminal) can reorder right-to-left text themselves; others show it
  in logical order.
- The clipboard carries UTF-16 on Windows (`CF_UNICODETEXT`; ill-formed bytes
  fall back to the raw `CF_TEXT` bytes).

## States (19: agenda §14.4, plus three)

`Locked, Unlocking, Overview, Query, AddEntry, EditEntry, DeleteConfirm,
RevealSecret, CopySecret, ExportEntry, ExportVault, Import, SaveInProgress,
RekeyInProgress, Error, Help, SaveConflict, CloseConfirm, Settings`. Default
unlocked state is `Overview`. The details sheet is a flag on `Overview`, not
a state. `SaveConflict` asks what to do when a save finds the vault file
changed on disk, `CloseConfirm` what to do with unsaved changes when the
vault is locked (`q`), and `Settings` holds how changes are saved (below).

## Keys

Command letters act in either case: `command_letter()` folds `A`–`Z` to
`a`–`z` wherever a key is a command (the list, the dialogs, Settings, the
start page, `Ctrl` combinations), so Caps Lock or Shift never silences one.
Text and password fields keep the case typed. (Until 0.9.2 an uppercase
letter did nothing outside the three confirmation dialogs.)

| Where | Keys |
|---|---|
| List | `↑↓`/`j k` move, `PgUp PgDn` page (by the visible rows), `Home End`, `Enter` details, `/` search, `a` add, `m` edit, `d` delete, `s` show, `p` copy password, `u` copy username, `w`/`Ctrl+S` save, `r` re-seal, `q` lock (asks first if there are unsaved changes), `o` settings, `?` help, `Esc` back out one level (sheet, then filter) |
| Unsaved changes (after `q`) | `s` or `Enter` save and lock, `d` discard and lock, `Esc`/`c` cancel (back to the vault); another `q` and pastes do nothing |
| Settings | `↑↓`/`j k`/`Tab` choose, `←→`/`Space` change (a click on an item changes it), `Esc`/`Enter`/`o` done |
| Search | type to filter, `↑↓` pick, `Enter` keep, `Esc` restore the previous list, `Ctrl+U` clear |
| Forms | `Tab`/`Shift+Tab`, `↑↓`, `←→ Home End Del` editing (`Ctrl+A`/`Ctrl+E` start/end, in every text field), `Ctrl+U` clear field, `Ctrl+V` paste, `Ctrl+R` show/hide the password being typed, `Enter` next/save on the last field, `Ctrl+S` save, `Esc` cancel |
| Password prompt | `Enter`, `Esc` (back one step when confirming, else back to the start page, or quit when the vault came from the command line), `Ctrl+R` show/hide the password being typed, `Ctrl+U`, `Ctrl+V` paste; while unlocking, `Esc` stops waiting (back to the prompt) |
| Paste | `Ctrl+V` in any text field (the search, the forms, the password prompt, the start page's path and name fields); the terminal's own paste (`Ctrl+Shift+V`, right-click, `Shift+Insert`; `Ctrl+V` in Windows Terminal and the classic console) works everywhere a field is focused |
| Changed on disk | `c` or `Enter` save a copy next to the vault (the window goes on in it), `o` overwrite what the other side saved, `Esc`/`n` back, still unsaved |
| Start page | `↑↓`/`j k`, `PgUp PgDn Home End` move, `Enter` open, `n` new vault, `o` open (browser), `x`/`Del` forget, `?` help, `q`/`Esc` quit |
| Browser | type to filter or enter a path, `↑↓` move, `Enter` open or enter a folder, `Backspace` up (on an empty filter), `Esc` back |
| New vault | `Tab`/`Shift+Tab`, `←→` or `Space` security profile (on its field), `Ctrl+O` choose a folder (also `Ctrl+B` in the folder field), `Ctrl+S` create, `Esc` cancel |
| Mouse | click selects a row or focuses a field; double-click opens a list row (in a form it only focuses); the wheel scrolls lists; key hints, buttons and the show/hide pill are clickable (`--no-mouse` turns this off) |
| Anywhere | `Ctrl+L` repaint |

With mouse reporting on, most terminals select text with `Shift` held.

## Security-relevant behaviors (enforced in the machine, tested)

- **Hidden input**: master password and entry passwords are edited only in
  `SecretLineEdit` (SecureBuffer-backed, wiped on cancel/commit/state-exit).
  Create mode requires double entry with a constant-time confirm compare; the
  form shows a live match indicator computed by the same compare.
- **Master password is printable ASCII** (a notice explains when another
  character is typed): Unicode text can encode differently across input
  methods and platforms (NFC/NFD), which would lock the user out. `passwd`
  enforces the same rule for new passwords. Entry passwords accept any text.
- **Async KDF**: `Locked`→`Unlocking` hands the password to the worker
  thread; input is ignored meanwhile, except `Esc`: it stops waiting (a
  vault on a stalled network drive can block the read for minutes) and
  returns to the prompt without touching the file system. The abandoned run
  gives up before the KDF and before writing anything (also after writing
  the temporary file of a new vault: nothing is put in place), and wipes its
  result; quitting waits at most 2 s for it. One key derivation runs at a
  time, so retrying after Esc never stacks a second Argon2 arena (up to
  1 GiB) on one still running. An Esc read while the screen said
  "unlocking" always cancels, even if the run finished meanwhile. Going back
  to the start page from a vault that never opened does not re-check the
  recent vaults' files (the stalled drive would hold that up too). The UI
  shows only non-secret progress.
  Tested end to end on Linux with a shim that makes opening the vault block
  (`stall_open.c`).
- **Reveal**: entry-scoped, TTL (10 s), countdown shown; hides on timeout,
  any key (navigation keys then move), selection or mode change; fires the
  exposure reseal; lives in one machine-owned SecureBuffer.
- **Copy**: explicit; TTL (20 s) with a live countdown; clear-if-still-ours on
  TTL/lock/exit; the entry is resealed.
- **Delete**: only `DeleteConfirm` calls `delete_entry(idx, confirmed=true)`.
- **Paste never commands**: bracketed-paste input arrives as `KEYMOD_PASTE`
  characters with every control (CR, LF, Tab, Esc) removed; it reaches text
  fields only, never a list command or the delete confirmation. On Windows
  the console runs in VT input mode. Paste detection works in Windows
  Terminal on Windows 11 and in the classic console from Windows 11 24H2,
  which mark their pastes the same way. The classic console's paste is
  tested on Windows 11 25H2 (build 26200, which shares 24H2's code base): a
  pasted `dy` in the list deletes nothing (with raw key records, as before,
  it deleted the selected entry). Windows Terminal's own paste cannot be
  triggered from outside, so the drivers do not exercise it; its support is
  Windows Terminal's bracketed paste. The classic console of earlier Windows
  releases cannot mark pastes (it gained bracketed paste in April 2023,
  microsoft/terminal #15155): there its paste arrives as typing and acts as
  keys, escape sequences included. A `Ctrl+V` that reaches Secraxis (the
  console usually takes it for its own paste) is marked everywhere. Consoles
  without VT input still get raw records, where a paste cannot be told from
  typing.
- **Ctrl+V** reads the clipboard itself where it can (Win32 clipboard;
  `wl-paste`, `xclip` or `xsel` on a local Linux display; `pbpaste` on
  macOS) and feeds the text through the same filter, as pasted characters:
  it lands in the focused field only, newlines and tabs dropped. The text (often a
  password) is read straight into a SecureBuffer, at most 64 KiB. Where the
  program cannot reach the user's clipboard (over SSH, no clipboard tool) the
  status line says how to paste with the terminal instead. In the list,
  `Ctrl+V` only says where a paste can go.
- **Search is explicit** (agenda §14.4): only `/` opens it, never typing in the
  list. While open, the list filters as you type (vaults up to 5,000 entries;
  larger ones apply on Enter). It searches metadata only; a needle present
  only in a password matches nothing.
- **Saving: by hand or automatically** (Settings, `o`; kept in
  `settings.json` in the config folder, next to `recent.json`, under the
  same strict-parser rules; `SECRAXIS_CONFIG_DIR` applies). "Save changes:
  when I press w" (the default): `w`/`Ctrl+S` save, the header marks
  unsaved changes. "Automatically": every entry added, edited or deleted is
  saved at once (choosing it saves what was pending), the header says
  `autosave`, and `w` still works (after a failed save, say). A vault
  changed on disk asks first either way (below). Keys change the focused
  setting, so no window may hide one: a short window drops the
  explanations (but the focused item's, where it fits), never an item's
  label or value.
- **Locking with unsaved changes asks** (`q`, `CloseConfirm`): save and lock
  (`s`, or `Enter`: the choice that loses nothing), discard and lock (`d`;
  the vault file stays as last saved), or cancel (`Esc`, `c`). A paste
  chooses nothing, and neither does a second `q` (before, `q` `q` locked
  without saving), nor anything typed ahead: keys read together with the
  `q` are dropped, since they were pressed before the question could be
  seen (tested: `q` and `d` in one write leave the question open). Saving
  into a vault that changed on disk opens the conflict dialog first; it
  locks only once a choice has saved, and backing out of it keeps the vault
  open.
- **Idle auto-lock (300 s), periodic reseal (60 s)**, with the reason shown
  after an idle lock. Nobody is there to ask about unsaved changes, so the
  setting "At an idle lock, or when the terminal closes" decides: save them
  (the default; to a copy beside the vault, see below, if it changed on
  disk or cannot take the save in place, e.g. another save of it is stuck)
  or discard them; the lock screen says which. If even a copy cannot be
  written it says that, and locks anyway: an unattended screen must not stay
  open. Such a copy is added to the start page's recent vaults, so it is
  found also after a hangup nobody saw.
- **A vault changed on disk is never overwritten silently.** Every save
  first checks that the file is still the save this window loaded or last
  wrote (vault id, epoch, per-save salt). If another window or a sync tool
  saved over it, nothing is written and `SaveConflict` asks: save a copy
  next to it (`<name>-conflict.seis`, then `-conflict-2`...; the window goes
  on in the copy, also after locking and unlocking again, and both versions
  survive), overwrite (an explicit choice), or back. A paste chooses
  nothing. A vault file that is gone is simply written again. The check and
  the rename hold a replace lock other Secraxis windows honor, so two
  windows saving at the same moment cannot both overwrite the same state.
- **The terminal going away.** When the window is closed, the SSH
  connection drops (SIGHUP), the program is asked to stop (SIGTERM, an
  outside SIGINT), or on Windows the console closes, logs off, shuts down or
  gets Ctrl+Break, nobody can be asked: unsaved changes are saved (to a copy
  if the vault changed on disk) or, if the setting says so, discarded; the
  clipboard is cleared if it still holds our copy, and the terminal is
  restored. That gets 5 s, then the program ends anyway; repeated signals
  do not cut it short. Log-off and shut-down reach a Windows program that
  loads user32 (this one does) only as window messages, not as console
  events: a hidden window on a thread of its own takes `WM_ENDSESSION` down
  the same path (tested with `console_drive`'s `end-session`). Measured
  exception: VTE terminals (GNOME Terminal, Tilix, the Xfce Terminal and
  others) send SIGKILL 0.07 ms after SIGHUP
  when their window is closed (VTE 0.76), so nothing can save then (the
  clipboard is still cleared: see Clipboard). There, "save changes
  automatically" keeps everything (tested: the window closed right after an
  added entry, which was there on the next start); otherwise save before
  closing such a window (the header's "unsaved" marker shows when).
- **Show while typing**: in the add/edit form, `Ctrl+R` (or a click on the
  `show` pill) shows the password and confirm fields as typed. It hides
  after the reveal TTL (10 s, renewed by each keystroke in a password field),
  and on leaving the form. Only what was typed is shown: an edit never loads
  the stored password into the form. There is no password generator (the
  project stores secrets the user chose and does not claim to improve them).
- **Show the master password while typing** (0.9.2): on the password
  prompt, `Ctrl+R` (or a click on the `show` pill) shows the master password
  being typed, in the unlock prompt and both create prompts. Every prompt
  opens hidden; it hides after the reveal TTL without typing (renewed by each
  keystroke), on `Enter`, on `Esc`, at the confirm step and on any state
  change, so nothing is shown while the key is derived. A paste cannot turn
  it on. It reaches the renderer only as `RenderModel::pw_reveal`.
- **No secret in the render model** outside `reveal_text` and, while shown,
  `FormField::reveal` (the form's passwords) and `pw_reveal` (the master
  password being typed): views into the machine's SecureBuffers, valid until
  the next machine call, never copies. The canvas cells, the screen mirror
  and the output buffer that carry a shown secret to the terminal are wiped
  when reused or released.
  Masks show the length bucket, never the length; hidden form secrets expose
  only character counts.
- **Timestamps** use the injected wall clock (`set_wall_clock`), never uptime.

## Terminal safety (renderer, writer, terminal)

- **Sanitizer choke point**: every byte of vault text reaches a cell only
  through `next_cluster()`. Ill-formed UTF-8, C0/C1 controls, DEL, bidi
  overrides/isolates, BOM, zero-width space, line/paragraph separators and
  noncharacters become a reverse-video `?`; variation selectors are dropped.
  An imported entry named `ESC ] 52 ; …` (clipboard write) or carrying `CSI 2 J`
  is drawn, never executed. `test_renderer` replays every frame through a
  strict emulated terminal that rejects any sequence the writer does not
  emit itself.
- **Frame writer**: only changed cells are written, each run positioned
  absolutely. Text whose width the terminal might disagree with is
  re-positioned, wide characters' right halves are blanked first, and a
  possibly wider glyph's right neighbor is repainted after it. A width
  disagreement can lose one glyph but never move a border or ASCII text
  (`width_disagreement_never_moves_chrome_or_ascii`). Auto-wrap is off, so
  nothing can scroll. Frames are wrapped in synchronized-update mode.
- **Alternate screen + panic restore**; nothing reaches scrollback.
- **QuickEdit off on Windows**: a mouse selection would otherwise freeze
  output (and the reveal timeout) until a key is pressed.
- **Memory**: the canvas, the writer's mirror, the output buffer and the
  input decoder are wiped when reused or released (a reveal passes through
  them).
- **Split input never turns into keys.** A read timeout resolves only a lone
  ESC (the Esc key, after 25 ms) and drops a stalled string reply (after
  1 s). A split CSI or SS3 sequence, mouse report, paste marker or UTF-8
  character waits for its rest, however long. Before, `ESC[20`, a timeout,
  then `0~dy` ran a paste as commands, and a timeout inside the end marker
  left input stuck in paste mode. Tested for every split point, with
  timeouts in between, against the same input read whole.
- **Old-style mouse reports** (`CSI M` and three raw bytes, from terminals
  without SGR mode 1006) are decoded as clicks. Before, their bytes were
  read as keys: a click at column 67, row 56 was ` dY`, delete, confirmed.
- **A click acts on the frame the user saw.** A click read together with
  other input waits for the next frame (that input may have opened a dialog
  the click would otherwise answer unseen), and acts there only if it means
  the same as on the frame it was made on: the same screen, and the same
  event at that cell (`same_click_meaning`). Otherwise it is dropped: `d`
  and a click where the dialog's Delete button then appears delete nothing,
  and after a scroll a click never picks the entry that moved under it.
  (Until 0.9.1 the held click acted on whatever the next frame showed.) A
  double-click adds `Enter` only on a list row, never in a form, where it
  would commit.
- **The form's editors hold what the vault allows** for each field (remark
  and URL 1024 bytes, tags 512): editing an imported entry no longer cuts
  them at 256 bytes, possibly inside a character.
- **Editing changes only what the form shows.** A new password replaces the
  password alone: an entry's other secrets (a TOTP seed from an import,
  recovery codes, a secret note), which the form does not show, are kept.
  (Until 0.9.1 a new password dropped them.)
- **Out of secure memory** (a very large vault where the system limits
  memory maps; `THREAT_MODEL.md`), taking a typed password from its field,
  opening a vault or storing an entry fails with "Not enough secure memory
  for this vault..." and changes nothing: the typed text stays in the form,
  a vault is never created or unlocked with an empty password, and an entry
  is never stored without its password. It is never shown as "wrong
  password": the core reports it only after the password has opened the
  vault.

## Options

`--ascii`, `--no-color` (or `NO_COLOR`), `--theme dark|light`,
`--glyphs basic|rich`, `--no-mouse`, `--no-history` (the start page neither
reads nor writes `recent.json`), `--keep-font` (the classic console keeps its
font even when it draws symbols two cells wide), `--version`, `--help`. None
of them affects what is stored in a vault. One option does:
`--kdf floor|default|strong` sets the KDF profile of a vault created from
the command line (a path to a file that does not exist yet; the start
page's form has its own choice). Without a vault path, `secraxis` opens the
start page.

How changes are saved is a setting, not an option: `o` in a vault opens
Settings, and the choice is kept in `settings.json` in the config folder
(`{"version":1,"save":"manual"|"auto","unattended":"save"|"discard"}`).
A file the strict parser rejects means the defaults (manual, save) and is
replaced on the next change; if it cannot be written, the settings last
until the program quits and the status line says so.

## Clipboard

`PlatformClipboard` (`src/tui/clipboard.cpp`):

- **Windows:** `CF_UNICODETEXT` with `ExcludeClipboardContentFromMonitorProcessing`,
  `CanIncludeInClipboardHistory=0` and `CanUploadToCloudClipboard=0`: kept out
  of the clipboard history (Win+V) and the cloud clipboard. Another program
  may hold the clipboard open for a moment; opening it is tried for about
  100 ms. A copy Windows does not take reports "busy", never "copied". A
  clear that still finds the clipboard busy keeps the fingerprint and
  returns "not yet" (`clear_if_ours()` is false): the machine says "Could
  not clear the clipboard yet: another program has it open. Trying again."
  and tries every second, also after the vault locks, until it can; only
  then "Clipboard cleared.".
- **Local POSIX display:** the first clipboard tool that reaches it
  (`wl-copy`/`wl-paste` on Wayland, `xclip` or `xsel` on X11, `pbcopy` on
  macOS). These tools serve a copy from a process of their own. Where
  `timeout` exists it is kept in the foreground under it (`timeout
  --foreground 25 xclip -quiet ...`): that process ends when someone else
  copies, ends with the terminal (it stays in the program's process group),
  and ends 25 s after the copy at the latest. So the copy cannot outlive the
  20 s timeout by more than 5 s even if the program is killed or crashes
  (tested: SIGKILL, then the copy is gone within 25 s). The clear stops that
  process; a clipboard manager that took the copy over is then checked with
  a keyed BLAKE2b fingerprint (clear-if-ours, so a later user copy is never
  clobbered and no plaintext is retained). Reading the clipboard (that
  check, and `Ctrl+V`) runs the tool directly, with no shell, and gives up
  after 2 s: if the clipboard's owner never answers (a hung program, a stuck
  VM bridge), xclip, xsel or wl-paste would wait forever, and the screen,
  the clear and the idle lock with it.
- **Over SSH** (no X11 forwarding), **or with no clipboard tool:** the
  terminal's own clipboard, through OSC 52 (`ESC ] 52 ; c ; base64 BEL`,
  built in a SecureBuffer; inside tmux also through its passthrough). The
  status line says "sent to your terminal's clipboard": the program cannot
  read it back, so the timeout clears it unconditionally (an empty OSC 52).
  Terminals known to ignore OSC 52 (VTE, i.e. GNOME Terminal and kin; xterm's
  default settings) get a clear "cannot copy here" with what would help
  instead of a false success. Windows Terminal and the classic console
  take it (verified over SSH: the password reached the Windows
  clipboard). Inside tmux the note says it needs tmux's `set-clipboard on`.
  With it, tmux keeps every OSC 52 copy as one of its paste buffers and
  ignores an empty one: there the clear sends a blank instead (which also
  reaches the outer terminal) and deletes the automatic buffers (`bufferN`)
  that hold the copy or the blank. Before, tmux 3.4 kept the password after
  the timeout and after the program exited.

## Deviations from agenda §14 (owner direction, 2026-10-30)

- Unicode drawing and the `…` ellipsis are used when, and only for the
  glyphs that, the probe verifies (§14.2's condition); ASCII remains the
  fallback.
- The overview example's password column is dropped from the list; the
  length-bucket mask is shown in the details pane.
- Search filters live inside the explicitly opened search (§14.4's "not a
  default live search field" is kept: list typing never searches).

## Responsiveness

The loop handles everything already typed or pasted before it draws (a
paste costs one frame, not one per character; a click ends the batch so the
next click hits the layout it was aimed at). Only changed cells are written;
an idle screen sends nothing. Live search narrows as the needle grows
(searching only the last hits), opens metadata with one reused pair of
secure buffers instead of two fresh ones per entry, and on vaults above
1,000 entries runs after the keystroke's own frame, so typing never waits
for it. `bench_tui` (a 5,000-entry vault, 120×34): about 0.6 ms from key to
frame for scrolling and paging (2.7 KB per keystroke), under 1 ms to show a
typed search character, 20 ms to the search results (88 ms before);
1.5 ms / 21 ms on the Linux host. Idle CPU in the real consoles: 0.3 to 1 %.

## Dev tools

These live in the development tree, not in the public source.

- `frame_dump [cols rows] [--ascii|--basic] [--light] [--ansi|--html]
  [--only TEXT [--hold MS]]` prints a scripted session's frames, start page
  included (`--html`: colored HTML; `--only`/`--hold`: one real frame held on
  screen, to look at or photograph it in a real terminal).
- `console_drive <script> <out-dir> [NAME=value...]` (Windows) plays a
  script against a real console window: the classic console, Windows
  Terminal, a hidden classic console, or what a double-click opens. It types
  and clicks through that console's input queue only (never global
  keystrokes), triggers the classic console's own paste (Windows Terminal's
  cannot be triggered from outside), sets and checks the clipboard (and
  gives the user's back), measures waits and CPU, and saves window
  screenshots.
- `linux_drive <script> <out-dir> [NAME=value...]` (Linux; C, GTK 3 + VTE +
  XTest) plays the same script language in a VTE terminal (GNOME Terminal's
  engine) or an embedded xterm, on the display or a private Xvfb: real X key
  and mouse events, the terminal's own paste, screen read-back (VTE), window
  screenshots.
- Scenarios in `tests/interop/scenarios/`: `win_vault`, `win_launcher`,
  `win_ssh` (Windows OpenSSH to a Linux host), `win_memory`, `win_hangup`,
  `win_conflict`, `win_save`, `win_prompt` (the subcommands' hidden prompt
  gives the console its echo back after Ctrl+Break), `linux_vault`,
  `linux_tmux`, `linux_xterm`, `linux_memory`, `linux_hangup`,
  `linux_conflict`, `linux_save` (with `stall_open.c`, an `LD_PRELOAD` shim
  that makes opening the vault block like a stalled network drive).
- `bench_tui [entries] [cols rows]`: key-to-frame time and bytes per frame on
  a large vault.
