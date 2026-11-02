# Testing and Fuzzing

The test suites, fuzz targets and corpora, test drivers and scripts named
here belong to the development tree, and the experiment, red-team and
release-checklist reports it cites are internal: neither is part of the
public source. This document records what they checked and found.

## 0.9.3

0.9.3 replaces the entry icons with colored letter tiles, adds a per-entry
color, and stores it in a new revision of the encrypted contents
(SEIS-CANON-v2, `SEIS_FORMAT.md` §8); a vault written by a later version is
reported as such, only after authentication. The cryptography, key
derivation and container are unchanged, so the 0.9.1 results below still
stand for them. Run for 0.9.3, on the final code:

- ctest 21 of 21 on Windows (MinGW GCC 14.2) and Linux (GCC 11.5), 0
  warnings. `tui_machine`, `renderer`, `launcher`, `phase3`, `seis_phase2`
  and `vault_session` (43, 27, 15, 9, 17 and 20 cases on Linux) also under
  ASan+UBSan, TSan and MSan (clang 18): no report.
- New tests: `canonical_revisions_and_entry_color` (`phase3`),
  `validate_vault_api` rewritten on real contents with a newer manifest
  and contents revision (`seis_phase2`),
  `vaults_from_0_9_2_open_whole_and_upgrade_on_save`,
  `a_0_9_2_vault_saved_unchanged_is_upgraded_and_its_backup_is_not`,
  `key_changes_keep_a_0_9_2_vaults_contents_as_they_are`,
  `a_newer_format_says_so_but_only_with_the_right_password` and new cases
  in `add_contract` and `modify_contract_preserves_identity`
  (`vault_session`), `entry_color_field` and
  `format_upgrade_and_newer_format_messages` (`tui_machine`),
  `entry_badges_are_colored_initial_tiles`, `start_page_draws_no_emoji`,
  `form_color_field_names_the_color_and_its_arrows_click` and
  `form_focus_is_always_drawn` (`renderer`). The compatibility fixtures in
  `tests/vectors/compat` are vaults the 0.9.2 code wrote (both AEAD
  profiles), made before any 0.9.3 change. Each guarded fault was put back
  once and its test failed (15 of 15): Color accepted in v1 contents, Color
  0 accepted, v1 written with a color, a newer contents magic or manifest
  reported as the generic error, `seis_validate` hiding a newer manifest,
  no upgrade notice, no wrap-around of the colors, emoji in a badge or on
  the start page, the color dropped on commit or not loaded on edit, the
  form not scrolling to its focus, and add or edit taking a color the
  format does not define.
- End to end, Windows (hidden consoles): the test build's `win_memory` 39;
  the release `.exe`'s `win_vault` 29, `win_launcher` 21, `win_hangup` 32,
  `win_save` 59, `win_conflict` 43 and `win_prompt` 4. New `win_compat`
  (the released 0.9.2 and 0.9.1 programs against 0.9.3: an earlier release
  makes a vault, 0.9.3 opens and converts it, the earlier one refuses it
  and leaves the file unchanged, a copy from before still opens there, the
  color survives): 40 of 40 against each, on the release `.exe`, and 40 of
  40 in Windows Terminal (test build, against 0.9.2). Linux:
  `linux_memory` 25, `linux_vault` 28,
  `linux_save` 47, `linux_conflict` 44, `linux_hangup` 55, `linux_xterm`
  by its screenshots; the release binary's `linux_vault` 28 and
  `linux_hangup` 55. Every scenario now tabs through the Color field;
  `win_vault` and `linux_vault` pick a color.
- libFuzzer (ASan+UBSan, coverage on all code), 15 minutes per target, 4
  workers, from the committed corpora and the targets' seeds: `canonical`
  184,689,958 executions, `unlock` 515,103,617, `tui` 628,607; no crash,
  leak or timeout. The corpora of the three were replaced by this
  campaign's minimized ones (`canonical` 66 to 74 files, 11 of them in the
  new revision; `unlock` 14 to 14; `tui` 1,695 to 2,179).
- Release binaries: 0 warnings, no `SECRAXIS-WEAK-KDF`, no test hook; the
  Windows `.exe` imports only Windows DLLs, the same as 0.9.2's (ASLR, DEP,
  high-entropy VA); the Linux binary is PIE with full RELRO and a
  non-executable stack, and two builds in different folders are identical.
- Static analysis was not re-run for 0.9.3.

## 0.9.2

0.9.2 changes the terminal interface only: the master password can be shown
while typed (`Ctrl+R` or the `show` pill), and command letters act in either
case. The cryptography, the file format and saving are unchanged, so the
0.9.1 results below still stand for them. Run for 0.9.2, on the final code
(the Windows `memory`, `vault` and `launcher` sessions one step earlier, on
the same code before the version number changed to 0.9.2):

- ctest 21 of 21 on Windows (MinGW GCC 14.2) and Linux (GCC 11.5), 0
  warnings. `tui_machine`, `renderer` and `launcher` (41, 24 and 15 cases on
  Linux) also under ASan+UBSan, TSan and MSan (clang 18): no report.
- New tests: `master_password_show_toggle`,
  `uppercase_command_letters_act_like_lowercase` (`tui_machine`),
  `master_password_appears_only_while_shown` (`renderer`) and
  `uppercase_letters_command_the_start_page` (`launcher`). Each guarded
  fault was put back once and its test failed (7 of 7): no hiding after the
  idle timeout, a confirm step that opened shown, a paste turning it on, the
  renderer drawing the password whenever a view existed, a pill that was not
  a click target, and no case folding on the vault screen or the start page.
- End to end: `win_memory` 39 of 39, `win_vault` 28 of 28, `win_launcher` 21
  of 21; the release `.exe` `win_vault` 28 of 28 and `win_hangup` 32 of 32;
  `linux_memory` 25 of 25 and `linux_vault` 27 of 27. Both memory sessions
  now show the master password while creating the vault (`win_memory` also
  while unlocking it again), check it is on screen, and then find it
  nowhere in the program's memory, as UTF-8 or UTF-16, once the key is
  derived.
- libFuzzer `tui` (ASan+UBSan, coverage on all code) for 10 minutes from the
  committed corpus: 153,432 executions, no crash, leak or timeout.
- Release binaries: 0 warnings, no `SECRAXIS-WEAK-KDF`, no test hook; the
  Windows `.exe` imports only Windows DLLs (ASLR, DEP, high-entropy VA); the
  Linux binary is PIE with full RELRO and a non-executable stack, and two
  builds in different folders are identical.
- Static analysis was not re-run for 0.9.2.

## Test suites (ctest)

Every operation has tests. ctest runs the suites below and also replays the
committed fuzz corpora (`tests/fuzz/corpus/<target>`) through the
standalone driver as `fuzz_replay_<target>`: 13 suites + 8 replays = 21
tests. For 0.9.1 all 21 pass on Windows (MinGW GCC 14.2) and on Linux (dot8,
the experiment host described in `EXPERIMENT_REPORT.md`; GCC 11.5), and on
Linux also under ASan+UBSan, ThreadSanitizer and MemorySanitizer, with no
report.

| Suite | Covers |
|---|---|
| `crypto_selftest` | SecureBuffer lifecycle/wipe/ct-eq, RNG, Argon2id/HKDF/XChaCha/GCM-SIV KATs, KDF profile registry, A2ONT production link + roundtrip, process hardening, AEAD profile registry + backend availability |
| `seis_phase2` | header codec + strict rejection (downgrade/confusion/bad-region), **reserved bytes rejected even with a valid CRC**, key hierarchy distinctness grid, VMK envelope roundtrip/tamper, container create/unlock/save roundtrip, **wrong-password ≡ tamper-oracle equivalence** (13 classes + reorder/delete/truncate/rollback), **header timestamps bound to the ciphertext** (changed with a consistent CRC: parses, does not open), atomic writer, `seis_validate`, no-plaintext-on-disk probe, `seis_validate` decodes the contents too: **a newer manifest or contents revision is `NewerFormat` with the right password and the generic failure with a wrong one (0.9.3)** |
| `phase3` | canonical codec roundtrip + strictness (disorder/dup/oversize/truncation/unknown-field/bucket-range), **an entry count the bytes cannot hold is refused before anything is allocated** (the binary counts its own allocations; skipped under sanitizers, whose runtimes own `operator new`), runtime sealed store lifecycle + moving-target reseal, metadata-only query, full-stack entries→.seis→runtime; **contents revisions (0.9.3)**: v1 and v2 each have one valid encoding, Color is refused in v1 and outside 1..8, `SXC3`..`SXC9` are `NewerFormat`, any other magic generic |
| `vault_session` | CRUD lifecycle contract: add/modify/delete, confirmation-gated delete, dirty-state, consume-and-wipe, identity preservation, reseal triggers, idle autolock, lock inertness; **two sessions on one vault** (the second save is refused, then saved as a copy or overwritten on purpose), a vault file replaced or deleted underneath, creation never replacing a file, leftovers of interrupted saves removed (and look-alike names kept); **four windows saving the same state at the same moment, 12 rounds: exactly one save written each time**; the replace lock (a second holder waits then gives up, a save waits for it, a file of the lock's name that is not ours is never deleted or changed, a leftover of ours is removed, a folder of that name does not stop saving); **a create canceled from another thread, at 40 moments from before the KDF to after the write: either created and there, or canceled and nothing left, not even a temporary file**; **a window never writes back keys changed on disk** (after `passwd`, `rekey` or `upgrade` elsewhere: save, overwrite and save-a-copy all refused, nothing written); **vaults written by 0.9.2** (`tests/vectors/compat`, both AEAD profiles) open whole and are upgraded by their first save, a chosen color survives saves, a password change and a rekey, key changes alone keep the old revision, a backup is the unchanged file, **a newer format is told only with the right password** (manifest and contents); **add and edit refuse a color or field size the format cannot hold** (0.9.3) |
| `tui_machine` | headless state machine: create/unlock/wrong-password, reveal TTL + exposure reseal, clipboard TTL clear-if-ours, delete-confirm gating, query scope, **render-model secret-leak probe**, **locking with unsaved changes asks** (save and lock, discard and lock, cancel; every pasted character and a second `q` choose nothing; into a vault changed on disk the conflict dialog decides, locking only once something saved), idle autolock, Unicode round trips (edits keep other fields' bytes verbatim, even ill-formed ones), ASCII-only master password, **paste never triggers commands**, paging/scrolling, live search keeping the pick, details sheet, wall-clock timestamps, countdowns, clicks picking rows and fields, show-while-typing (TTL, renewed by typing, hidden on leaving the form), **no pasted character acts in any state** (every state × every key a paste can carry), editing keeps imported fields whole, **the idle lock saves first** (to a copy when the vault changed on disk), **the save-conflict dialog** (a paste chooses nothing; back, overwrite, copy), **hangup saves and clears the clipboard**, the Settings dialog (keys, clicks, pastes change nothing, each change reported once), **save automatically** (add, edit and delete each saved at once; choosing it saves what was pending; a changed vault asks), **"discard" when nobody can be asked** (idle lock and hangup write nothing), **Esc stops an unlock** (told once, also before the shell took the password; a late result ignored; the session layer gives up before the KDF and creation before writing), creating over a vault that appeared meanwhile says so and unlocks it, **the idle lock and a hangup while the unsaved-changes dialog, Settings or a "save and lock" conflict dialog is open**, **an unattended save that cannot go in place goes to a copy** (another save holding the lock); **editing the password keeps the entry's other secrets** (TOTP seed, recovery codes, secret note); **a busy clipboard is cleared once it is free** (retried each second, also after a lock; "cleared" only then); **keys changed elsewhere are never written back** (`w`, the idle lock's save, no conflict copy); **no secure memory never means an empty password** (create, add and unlock with the n-th allocation failing; never "wrong password"); the core never creates a vault with an empty master password; on Linux, **a clipboard tool that never answers is given up after 2 s** (a fake `xclip` that sleeps); **the master password shown while typed (0.9.2)**: hidden whenever a prompt opens, after the idle timeout, on Enter, Esc and at the confirm step, never by a paste, and only in `pw_reveal`; **uppercase command letters act like lowercase (0.9.2)**, in the list, the dialogs and Settings, while fields keep the case; **the entry form's Color field (0.9.3)**: arrows, Space and clicks step and wrap, typing and pastes change nothing, an edit loads and keeps the color; the upgrade notice once after a 0.9.2 vault's first save, the newer-format message |
| `renderer` | every state × 10 sizes × 4 terminal profiles fills the canvas exactly (no ragged rows, no split wide characters, ASCII-only when required); **frames replayed through a strict emulated terminal** (`tests/unit/vt_emulator.h`) match the canvas and contain no foreign sequence; **hostile metadata** (OSC 52, CSI, C1, bidi, BOM, ill-formed UTF-8, zalgo) never reaches the terminal; secret only while revealed, form passwords only while shown; masks show the bucket; columns align under CJK; scrollbar/capacity; local-time and relative timestamps; 300 random frames replay exactly; width-disagreeing terminal never moves chrome or ASCII; start-page layouts replay at every size; **the logo is the same fixed-size widget at every window size**; clicks resolve to the right events (the unsaved-changes buttons at every width, narrow ones stacked; Settings items pick themselves, never "open"); **Settings never hides an item** (keys change the focused one: both values on screen and clickable at 7 sizes down to 40x12, × 4 terminal profiles, either item focused); **a held click acts only if its meaning is unchanged** (never on a dialog that opened meanwhile, never after a scroll); **the master password appears on the lock screen only while shown, once, and its show/hide pill means Ctrl+R (0.9.2)**; **entry tiles (0.9.3)**: initials in every glyph tier, eight distinct colors, Auto stable, no emoji anywhere (also the start page); the Color field's name, arrows and hint; **the focused form field drawn and clickable at every height from 12 rows** |
| `launcher` | recent-vaults file: round trip, **strict rejection of every deviation**, touch/forget (case-folded on Windows); settings file: round trip, defaults, strict rejection (24 deviations, size cap); start page: list and requests, folder browser and typed paths (Windows and POSIX), new-vault form (profiles, folder pick, names Windows maps to devices), every tip fits its line, **uppercase letters command the start page while typed names and filters keep their case (0.9.2)** |
| `tui_text` | UTF-8 maximal-subpart substitution (the standard's own example), width classes, clusters and sanitizing, input decoder (CSI/SS3 keys, UTF-8 split across reads, bracketed paste, SGR mouse reports, bounds), **nothing inside a paste escapes as a key** (every byte value and sequence, every chunking), **every split point of every sequence means the same after timeouts**, **every old-style mouse report** (256 button bytes × coordinates × split points) yields no key, UTF-16 assembly, line editors, glyph-probe decisions |
| `phase5` | CSV/JSON import roundtrip + rejection (depth bomb, truncation, malformed, **more than 64 fields in a row, a quote never closed**), **an import that cannot store a secret fails as a whole**, **header trimming in linear time** (1 MiB of spaces), **byte-exact export bodies** (both formats, pinned before they moved into secure memory), plaintext-export consent gating, **the export is a new file only the user can read** (never over a file or through a link; 0600, or a protected one-entry DACL checked with `GetNamedSecurityInfo`), **nothing left behind when an export write fails** (Linux: a file-size limit in a child), **the backup is the checked bytes and never replaces a file**, change-master-password (**the same VMK, rewrapped; an empty new password refused**), full rekey (**a fresh VMK**), KDF upgrade + no-downgrade, **a fresh KDF salt for every vault and every key change (one password in two vaults derives two keys)**, **saves and key changes through a symbolic link change the real vault** (where links can be made) |
| `a2ont_*` | the built-in A2ONT component's own suites against our build: 21 cross-language vectors, roundtrip, deterministic decode/header fuzz over every profile id, C++ wrapper |

## Sanitizers

- **ASan+UBSan**: all 21 tests pass on dot8 (`remote/run_sanitizers.sh`),
  and so do the GCM-SIV suites with the OpenSSL backend
  (`remote/run_openssl_gcmsiv_sanitize.sh`).
- **LSan**: enabled via `ASAN_OPTIONS=detect_leaks=1` in the campaign; no
  leaks.
- **ThreadSanitizer** (clang 18, `-DSECRAXIS_TSAN=ON`): all 21 tests, and
  the Linux end-to-end scenarios run with the TSan build of the program
  (vault, hangup, conflict, save including the stalled-drive unlock that is
  abandoned with Esc): no report. 0.9.1, final code: 173 of 173 checks.
- **The program under ASan+UBSan in real terminals** (0.9.1, final code):
  `linux_vault`, `linux_tmux`, `linux_save`, `linux_hangup`,
  `linux_conflict` and `linux_xterm` with the ASan+UBSan build: 192 of 192
  checks, no report. This covers the terminal, clipboard and signal code
  and the unlock worker, which the unit tests do not reach.
  - Only the `wait` limits were scaled (Argon2 is slower under the
    sanitizers); sleeps stay as they are.
  - `linux_memory` is left out: its memory scans mean nothing under ASan's
    allocator.
  - The GCC ASan build needs its runtime first in the preload list. The
    stalled-drive step therefore runs with
    `STALL=/lib/x86_64-linux-gnu/libasan.so.6:stall_open.so`; preloading the
    shim alone makes ASan refuse to start.
  - Each log setting (`log_path`) was first shown to catch a planted bug: a
    heap overflow under ASan and a data race under TSan.
- **MemorySanitizer** (clang 18, `-fsanitize=memory` with origins): built
  against an instrumented libc++ (LLVM 18.1.3 runtimes), libsodium
  (`--disable-asm`) and OpenSSL (`no-asm`), all in `~/secraxis-deps/msan`
  on the Linux host; all 21 tests, no report.
- **Platform note**: the local MinGW toolchain ships **no** ASan/UBSan
  runtime (`libclang_rt.asan*` absent), so sanitizers are Linux-only. All
  sanitizer evidence is from dot8.

## Fuzzing

Targets (`src/fuzz_targets/fuzz_targets.cpp`, one per `-DSX_FUZZ_<NAME>`):
`header`, `canonical`, `csv`, `json`, `a2ont`, `tui`, `unlock`, `history`.
The `tui` target runs the whole pipeline: raw terminal bytes (mouse reports
included) → `InputDecoder` → `TuiMachine` → `render()` → `ScreenWriter`, over
a vault seeded with hostile metadata, at a size and terminal profile chosen by
the input; when the input's second byte is odd it drives the start page
(`Launcher` → `render_launcher()`) instead, answering every folder-listing
request. It also feeds every input to the terminal-identification parser
(`scan_term_ident`), which reads the terminal's answers at startup.
`history` feeds the recent-vaults and settings parsers and checks that
whatever they accept survives a write/read round trip unchanged. Two
drivers:

- **Standalone mutational** (`SECRAXIS_FUZZ_STANDALONE=ON`): portable, no
  clang runtime; seed corpus + xorshift mutation; `FUZZ_ITERS`/`FUZZ_SEED`
  env; replays files given on argv (crash reproduction / CI).
- **libFuzzer** (`SECRAXIS_FUZZ=ON`, clang): coverage-guided, links
  `-fsanitize=fuzzer,address,undefined`; all code is compiled with
  `-fsanitize=fuzzer-no-link`, so coverage guides the fuzzer through the
  libraries under test. (Until 2026-10-31 only the target file carried
  coverage counters: 881 of them, against 21,212 after the change.) A
  standalone build's `--dump-seeds DIR` writes a target's built-in seeds as
  its starting corpus.

The rounds below are listed oldest first; the last one, 0.9.1, is the
release's result.

First campaign (0.1.0, 2026-07; dot8, ASan+UBSan, seed 20260706): **~2.52 M
executions, 0 crashes, 0 sanitizer findings** (500k each for
header/canonical/csv/json/a2ont, 20k for the heavier TUI target). Details in
`EXPERIMENT_REPORT.md §3`.

Start page and mouse round (2026-10-30, dot8, ASan+UBSan, seeds
20261030/20261031): `history` 500k executions and `tui` (now also driving the
start page and mouse reports) 2 × 60k, **0 crashes, 0 sanitizer findings**;
all 13 suites pass under ASan+UBSan and in a GCC 11 `-Werror` release build.
Locally (MinGW, standalone driver, no sanitizer): `history` 300k, `tui`
2 × 150k, no crash.

Deep-testing round (2026-10-31, dot8, clang 18 / GCC 11, ASan+UBSan), after
this round's changes:

| Target | libFuzzer, 15 min × 8 workers | Coverage (edges) | Corpus | Standalone |
|---|---|---|---|---|
| `header` | 757.6 M execs | 327 | 31 | 2 × 1 M |
| `canonical` | 122.6 M | 773 | 85 | 2 × 1 M |
| `csv` | 41.4 M | 1,352 | 452 | 2 × 1 M |
| `json` | 80.5 M | 1,971 | 646 | 2 × 1 M |
| `a2ont` | 190.1 M | 228 | 27 | 2 × 1 M |
| `history` | 157.1 M | 1,422 | 354 | 2 × 1 M |
| `tui` | 0.67 M | 15,314 | 1,715 | 16 × 200 k |
| `unlock` | 657.8 M | 160 | 14 | 8 × 4 k |

About 2.0 billion libFuzzer executions and 15.2 M standalone ones: **0
crashes, 0 sanitizer findings, 0 timeouts, 0 out-of-memory**. The `unlock`
target's coverage is small by design: a mutated vault fails its header
checksum or authentication before any parser behind the AEAD runs
(verify-before-parse). The first run of this round did abort, in the `tui`
target's own set-up: sixteen fuzzers sharing a folder raced to create one
vault file, and creation no longer replaces a file. Each now uses a name of
its own; the saved inputs replay cleanly.

Round 5 (2026-10-31): one hour per target, 4 workers each, all eight side
by side, then each corpus minimized (`-merge=1`):

| Target | Executions | Coverage (edges) | Corpus, minimized |
|---|---|---|---|
| `header` | 2.65 billion | 329 | 36 |
| `canonical` | 538 M | 496 | 71 |
| `csv` | 104 M | 509 | 526 |
| `json` | 244 M | 683 | 743 |
| `a2ont` | 640 M | 210 | 27 |
| `history` (now also `settings.json`) | 604 M | 975 | 356 |
| `tui` (now also the close prompt and Settings) | 3.1 M | 17,196 | 1,527 |
| `unlock` | 2.37 billion | 160 | 14 |

About 7.1 billion executions: **0 crashes, 0 sanitizer findings, 0
timeouts, 0 out-of-memory**. (The edge counts are not comparable with the
table above: the builds differ.) The `tui` target reported three "slow
units": 62-byte inputs holding about 17 Ctrl+S each. Replayed alone they
finish in 24 to 48 s; one save takes 2.8 s in that build (ASan, UBSan and
coverage on every byte loop of the save pipeline; 0.7 s with ASan alone, 40
to 50 ms in a release build), and the disk syncs of all 17 saves took 12 ms
in all (strace). Not a hang. The minimized corpora (about 3,300 inputs, 272 KB
compressed) were kept outside the repository then. After the review fixes of
this round, the standalone ASan+UBSan drivers ran again on this round's
final code: 12 M executions over the six parser targets, 800 k `tui`, 16 k
`unlock`, no crash.

0.9.1 (2026-10-31): 2.5 hours, all eight targets side by side with 4
workers each (`-timeout=30`, `-rss_limit_mb=4096`), seeded with round 5's
minimized corpora and the built-in seeds. The campaign ran on the code as it
stood when it started, before the release's last parser fixes; the same eight
targets then ran 20 minutes on the final code, seeded with the campaign's
minimized corpora, and the result was minimized again (`-merge=1`):

| Target | Campaign, 2.5 h (earlier code) | Coverage (edges) | Final code, 20 min | Corpus committed |
|---|---|---|---|---|
| `header` | 6.62 billion | 334 | 903 million | 38 |
| `canonical` | 1.13 billion | 1,088 | 170 million | 66 |
| `csv` | 207 million | 2,310 | 28.0 million | 505 |
| `json` | 535 million | 3,074 | 65.7 million | 768 |
| `a2ont` | 1.60 billion | 318 | 215 million | 26 |
| `tui` | 7.5 million | 30,995 | 660,760 | 1,695 |
| `unlock` | 5.89 billion | 175 | 800 million | 14 |
| `history` | 1.52 billion | 2,459 | 194 million | 354 |

17.51 billion executions in the campaign and 2.38 billion on the final
code (about 19.9 billion in all): **0 crashes, 0 sanitizer findings, 0
out-of-memory**. The only events were five `tui` inputs over the 30-second
limit (four in the campaign, one on the final code): inputs that save 25 to
46 times in a row (counted with
`strace`: one rename per save). Under ASan, UBSan and coverage each save
takes about 3.5 s on the loaded host; replayed, all five finish (27 to 89 s
there, 1.0 to 2.2 s in a plain build). Slow, not stuck. The final minimized
corpora (3,466 inputs, 768 KB) are committed in `tests/fuzz/corpus/` and
replayed by every ctest run (`fuzz_replay_*`), also under ASan, TSan and
MSan on Linux.

The release review's last round changed two parsers (CSV and JSON skip a
UTF-8 byte-order mark) and the `canonical` target, which now aborts unless
every accepted input re-encodes to exactly the same bytes: the codec's
one-encoding rule, which until then the target only claimed in a comment.
The committed corpora replay cleanly under the new check, and libFuzzer ran
each of the three targets for 15 minutes on the final code (4 workers,
seeded with the committed corpora): `canonical` 152.8 million executions,
`csv` 18.0 million, `json` 52.6 million, 0 crashes, 0 timeouts, 0
out-of-memory.

The parsers are written to be total: bounded input sizes, strict field caps,
no allocation from attacker-controlled length fields, explicit depth limits
(JSON: 32), and no partial-accept (canonical/manifest/header reject any
deviation). The manifest and page-table parsers run only on AEAD-authenticated
plaintext, so an external attacker cannot feed them arbitrary bytes; they are
nonetheless written defensively and are reachable from the whole-file unlock
fuzzer (run on the Linux hosts with the weak-KDF test build, where per-exec
Argon2 cost is affordable).

## Crash safety

`exp_crashsave` (tests/experiments) creates a vault, then again and again
starts a child that unlocks it and adds and saves entries as fast as it can,
reporting each save that returned. The parent kills it (SIGKILL /
TerminateProcess) at a random moment within four save times, often mid-save,
and checks: the vault unlocks; entry *i* is exactly `entry-i`/`secret-i`;
every reported save is on disk; how many temporary files are left; and,
after every kill, that the save's lock file (Windows) is gone with it.

| Where | Kills | Saves reported | Kills between rename and report | Lost or torn | Temp files left |
|---|---|---|---|---|---|
| Windows 11 (NTFS, one save 36-40 ms) | 400 | 307 | 96 | 0 | 0 |
| Linux (ext4, one save 70 ms under load) | 1,000 | 302 | 304 | 0 | 0 |
| Windows 11, final round-5 code (replace lock; one save 40 ms) | 400 | 291 | 108 | 0 | 0, and no lock file after any kill |
| Linux, final round-5 code (one save 48 ms) | 1,000 | 320 | 350 | 0 | 0 |
| Windows 11, 0.9.1 (one save 40.5 ms) | 400 | 321 | 96 | 0 | 0, and no lock file after any kill |
| Linux, 0.9.1 (one save 48.5 ms) | 1,000 | 282 | 314 | 0 | 0 |
| Windows 11, 0.9.1 review code (one save 42.9 ms) | 400 | 319 | 110 | 0 | 0, and no lock file after any kill |
| Linux, 0.9.1 review code (one save 50.1 ms) | 1,000 | 293 | 337 | 0 | 0 |
| Windows 11, 0.9.1 final code (one save 40.9 ms) | 400 | 289 | 117 | 0 | 0, and no lock file after any kill |
| Linux, 0.9.1 final code (one save 43.3 ms) | 1,000 | 263 | 341 | 0 | 0 |

The replace lock costs under a millisecond per save (Windows release, five
runs each: about 39 ms with it and without it).

Before the fix, 200 kills on Windows left 5 temporary files (whole vault
copies, openable with the password they had then); now each successful save
removes them.

## Memory residency

`memscan`, `memscan-none` and `memscan-some` in the drivers search the
running program's memory (Windows `ReadProcessMemory`, every committed
region; Linux `/proc/PID/mem`) for a secret as UTF-8 and UTF-16, with
positive controls where a secret must be (while typed, while shown). Linux
runs a test-only twin, `secraxis_memprobe` (built only with tests), because
the real program makes itself non-dumpable and even its parent cannot read
it (itself evidence of that hardening). Scenarios `win_memory` and
`linux_memory` pass (0.9.1: 35 and 22 checks): the master password is gone
once the key is derived; an entry password is gone after it is added,
hidden again after being shown, copied and cleared, pasted (Ctrl+V; on
Linux also the terminal's own paste), and after locking. They found two
leaks, both fixed: on Windows, the UTF-16 copies of a copied or pasted
password left in freed clipboard memory; on Linux, stdio's buffers in the
pipes to the clipboard tool.

**Locked memory and memory maps** (0.9.1 final code):

- **Windows locking.** A scratch probe allocating secure buffers the way
  `SecureBuffer` does, then asking `QueryWorkingSetEx` which pages are
  locked, found 44 locked out of 400 (and out of 4,000) with Windows'
  default minimum working set (200 KB). With it raised to 16 MiB, 400 of
  400; with 64 MiB, 4,000 of 4,000. The program now raises it to 64 MiB at
  startup. `secure_memory_is_locked_beyond_the_default_quota` checks 600 of
  600 locked, and the running release program reports the 64 MiB minimum.
- **Memory maps (Linux).** A probe sampling `/proc/self/maps` from a second
  thread measured 8.01 maps per entry in an open vault, and a save peak of
  11.78 per entry (15.35 with a TOTP secret on every entry): a save holds
  every entry decrypted at once. That is what limits large vaults with the
  default `vm.max_map_count` (`THREAT_MODEL.md`, `MANUAL.md` "Limits").

## Property and mutation checks

Beyond examples, the input paths are checked exhaustively: every byte value
and sequence inside a paste in every chunking; every split point of every
escape sequence with up to three timeouts in between, compared with the same
input read whole; every old-style mouse report; every state against every
key a paste can carry. To show the tests catch what they claim, six input
bugs found in the deep-testing round were put back one at a time
(`mutate.py`, a throwaway script outside the repository): each made its
test suite fail.

The same for the save fixes of round 5. With the replace lock taken out of
`seis_save`, `simultaneous_saves_never_lose_a_reported_save` failed in 12 of
12 rounds on Windows (2 to 4 of 4 simultaneous saves reported as written,
all but one of them lost) and in 6 of 12 on Linux; with it, none. With the
unlock worker given the path the window started with instead of the one it
is on, `win_conflict` failed (after "save a copy", locking and unlocking
again showed the copy's name but opened the original); with the fix, 41/41.

An independent AI review of round 5's code (a separate agent, given the
code but not the author's conclusions) found ten more issues; all are fixed
(`CHANGELOG.md`). Each fix was taken out one at a time, and a test caught
the bug it had fixed: the Settings dialog hiding its second item in short
windows (112 failed checks), an unattended save
not falling back to a copy, the "vault exists now" message, a canceled
write of a new file, the deletion of a leftover lock file of ours (unit
tests); and, end to end on Windows, keys typed ahead answering the
unsaved-changes question (`q` and `d` arriving together discarded the
changes: 33 failed checks) and a copy missing from the start page's list.

For 0.9.1, three independent AI code reviews (crypto and format; parsers
and CLI; terminal, clipboard and platform) and the release work itself
found the issues listed in the changelog. Every fix was taken back out
once (`mutate091.py` on Windows, `mutate091_linux.py` on Linux, throwaway
scripts outside the repository) and its test failed each time: 26
unit-test mutations on Windows, 5 Linux-only ones (symbolic-link saves, the
clipboard reads' deadline, the export's mode, its refusal of links and its
cleanup after a failed write), and 3 end to end: without the hidden window,
`win_hangup`'s session end left the program running, the password on the
clipboard and the entry unsaved (3 failed checks); without the prompt's
console handler, `win_prompt` found echo still off after Ctrl+Break; and
without the POSIX signal handlers, a `script` pty showed `-echo` after a
SIGINT at the prompt. 34 of 34 caught.

The review's last rounds, a check of every document against the code by
independent AI agents and a final review of the security design, found
six more defects; each fix was taken back out the same way and its new test
failed:

- Windows' default lock quota left the minimum working set unraised:
  `secure_memory_is_locked_beyond_the_default_quota` found far fewer than
  600 of 600 buffers locked.
- Without the check under the replace lock,
  `an_overwrite_never_writes_back_keys_changed_meanwhile` saw an overwrite
  rewrite the vault with the old keys after `passwd`, `rekey` or `upgrade`:
  the old password opened it again, the new one no longer did.
- Without skipping the byte-order mark,
  `a_byte_order_mark_does_not_hide_the_first_column` lost the names.
- Without the save message, `a_save_out_of_secure_memory_says_so` saw only
  "Save failed".
- With the clipboard fingerprint's key fixed again,
  `clipboard_fingerprint_key_differs_per_instance` saw two clipboards give
  the same fingerprint for the same password.
- With a failed re-seal dropping the entry's old sealed copy again (as the
  in-place re-seal did), `nothing_is_opened_created_changed_or_saved_without_rdseed`
  found the entry's password gone after a re-seal refused for want of
  random numbers.

40 of 40 caught.

The random-number code that mixes the OS generator with RDSEED
(`CRYPTO_PROFILES.md` §5) was checked the same way, three mutations, each
caught: a mixer that used only the OS half
(`entropy_mixer_is_the_documented_hkdf_construction` and
`entropy_mixer_depends_on_both_sources_and_every_diversifier` failed); a
per-word check that accepted a single zero or one bit
(`rdseed_health_checks_flag_stuck_repeated_and_biased_words`); and opening
refused only after the password check, where a wrong password then got a
different answer than the right one
(`nothing_is_opened_created_changed_or_saved_without_rdseed`).

The per-vault KDF salt was checked the same way, four mutations, each
caught: with a fixed salt at creation, two vaults with one password got
the same salt and the same key
(`each_vault_and_key_change_draws_its_own_kdf_salt`); with `passwd`,
`rekey` or `upgrade` keeping the old salt, that test or
`kdf_upgrade_and_no_downgrade` failed.

## Static analysis and binary checks

The first three items record earlier rounds; the two items marked 0.9.1 are
the release's static-analysis results (cppcheck's 7 findings still stand
for 0.9.1). The last item covers the release binaries.

- Deep-testing round: clang 18's static analyzer (`--analyze`; core, C++,
  dead-code, security and unix checkers) over all 47 project sources at the
  time: one finding, a harmless dead store (the cursor after the last field
  written in `runtime_store.cpp`).
- clang-tidy 18 (`bugprone-*`, `cert-*`, `clang-analyzer-*`,
  `concurrency-*`, `misc-*`, `performance-*`, `portability-*`) over the 48
  product sources (`src/`), round 5's final code: 472 warnings, all triaged,
  no defect (467 before the review fixes; the five new ones are of the
  kinds below: three `getenv` calls detecting SSH at startup, an unchecked
  `snprintf` of at most 7 characters into 16 bytes, a lock guard that could
  be `const`). Most are style (`misc-const-correctness` 146,
  `performance-enum-size` 125). The rest: products of small constants widened afterwards (time
  units, never input sizes); unchecked `printf`/`fflush` results;
  assignments in `if` conditions in the A2ONT C code (deliberate);
  `getenv`/`readdir`/`setlocale` flagged as not thread-safe, called only on
  the interface thread (the unlock worker calls none of them); `popen` with
  constant command lines (the clipboard tools' paste and clear, tmux with
  buffer names checked to be `bufferN`), so no injection, though the copy
  itself already runs its tool without a shell; and false positives (a
  `memcpy` into a length-counted buffer, widening of bounded loop indices,
  ASCII case folding into `char`, a deliberately repeated switch branch).
- cppcheck 2.13 (warning, performance, portability) over the same sources:
  7 findings, no defect (5 performance notes on parameters passed by value
  and moved, 2 input buffers "not initialized in the constructor" that are
  only ever read up to their length counter, and wiped on clear).
- 0.9.1, final code: clang-tidy 481 warnings, none a defect. The 9 more
  than round 5 are the same `tui_core.h` warnings counted in one more
  translation unit (`cli.cpp` now includes it), "could be `const`" notes on
  new locals, unchecked results of `printf` and terminal-restoring calls,
  a `push_back` loop without `reserve`, and one more padding note; the
  removed `popen` read and the old export's narrowing casts took 3 away.
  cppcheck flagged one new "uninitialized variable": a buffer that only
  ever receives `read()` output and is then wiped (a false positive, the
  conditional expression it is passed through confuses it); it is
  zero-initialized now, and cppcheck is back to the 7 above.
- 0.9.1, final code, release configuration (tests off), Linux and Windows
  code. The Windows-only code (`_WIN32`: console, clipboard, DACL, replace
  lock, session end) goes through a MinGW cross build on the Linux host:
  clang 18 with `--target=x86_64-w64-mingw32` and winlibs' own headers
  (mingw-w64 12, libstdc++ 14.2) as sysroot; it compiles all 48 sources
  (nothing links). A sanity query showed each CodeQL database holds its
  platform's calls (`ReadConsoleInputW`, `CreateWindowExW`, `OpenClipboard`
  and `InitializeSecurityDescriptor`; `tcsetattr`, `flock` and `posix_spawnp`).
  - Clang Static Analyzer, every stable checker (clang 18 on both, and clang
    19 natively on Windows): 24 warnings per platform, no defect. 21 are
    padding notes on three structs. An allocation of 0 bytes in `gf2.c`
    cannot happen: `block` comes only from a fixed table of 16, 8, 16 and 4.
    An unknown id cast to `enum class FieldId : uint16_t` is well-defined.
    The cursor's last advance in `runtime_store.cpp` is a dead store.
  - Alpha checkers (`alpha.security`, `alpha.unix`, `alpha.core`,
    `alpha.cplusplus`, `alpha.deadcode`, `alpha.nondeterminism`, with the
    aggressive binary-operation simplification they need): 10 warnings on
    Linux, 12 on Windows, all false positives.
    - Index 3 of `Cell::cp[3]` (`canvas.cpp`, `screen.cpp`): every writer
      keeps `ncp` at most 3 and every reader stays below `ncp`.
    - A `memcpy` past the secret segment (`runtime_store.cpp`): the path
      sizes the buffer for no secret and then writes one. The size is the
      sum over exactly the fields written, under the same conditions.
    - One past a scalar (`pw_bucket`): legal.
    - `malloc(L * 4)` in `permutation.c`: `L` is at most 2^31
      (`a2ont_iprofile_check_len`), and only 64-bit targets are built.
    - Three pointer and iterator warnings inside libstdc++'s `std::sort`.
    - Two Win32 structs (`TOKEN_USER`, `ACL`) read from `std::vector<uint8_t>`
      storage, which `operator new` aligns to 16 bytes.
  - CodeQL 2.27.3, `security-and-quality` and `security-experimental`, both
    platforms: 46 results in product code at 24 places, no defect.
    - 8 places are maintainability notes: large parameters, comment
      density, a long switch case, a complex condition, an array parameter.
    - `cpp/path-injection` (6): paths from the command line or the config
      folder's environment variables reach `open`. The program runs only with
      its user's rights, and these are that user's own files.
    - `cpp/uncontrolled-allocation-size` (1): the manifest buffer's size
      comes from the header, but `seis_header_parse` caps it at 1 MiB and
      requires the layout to add up to the file's exact size.
    - `cpp/multiplication-overflow-in-alloc` (2): the `gf2.c` table again.
    - `cpp/constant-comparison` (3): two misread the digits written through
      a reference in the cursor-report parser (covered by unit tests on
      recorded answers); one is a redundant `u >= 1` after `u == 0` returned.
    - `cpp/loop-variable-changed` (3): the options that take a value check
      `i + 1 < argc` first.
    - `cpp/empty-if` (1): an `ftruncate` whose result is deliberately
      ignored (the file is unlinked next).
    - The vendored argon2 had 48 results, all patterns of its reference
      code: defensive 32-bit checks, an already checked allocation, joined
      threads' stack data, SIMD pointer casts.
  - GCC 11's `-fanalyzer` over the 16 A2ONT C sources: no warning. A planted
    use-after-free and double free with the same flags are both reported.
  - Re-run on the final code (after the last round's four fixes): the Clang
    Static Analyzer's stable and alpha passes on both platforms and CodeQL
    on both platforms gave the same results as above, with nothing in the
    new code. clang-tidy: 483 warnings, the two more than before being
    "could be `const`" notes on the new `check_not_rekeyed`'s locals (the
    same notes its sibling `check_unchanged` has). cppcheck: the same 7.
  - Re-run on the release code (after the clipboard fingerprint, the square
    glyphs and the random-number mixer, `src/crypto/entropy.cpp`): the
    Clang Static Analyzer's counts are unchanged (24 stable warnings per
    platform; 10 alpha on Linux, 12 on Windows), with nothing in the new
    code. CodeQL: 48 results in product code at 25 places; the new place is
    a maintainability note (`cpp/array-in-interface`) on
    `ClipboardFingerprint::of`'s 32-byte output parameter, whose size is part
    of its documented interface. clang-tidy: 482. cppcheck: the same 7.
- Release binaries (`-DSECRAXIS_BUILD_TESTS=OFF`): no `SECRAXIS-WEAK-KDF`, no
  test-only allocation hook (`secure_alloc_fail_nth_for_test`; both present
  in the test builds as the positive control),
  no memory-probe code. Linux: PIE, non-executable stack, full RELRO
  (`BIND_NOW`), stack protector, `_FORTIFY_SOURCE` (12 checked libc calls),
  no RPATH. Windows: ASLR with high entropy, DEP, only Windows DLLs imported
  (the GCC runtime is linked in; before, `libstdc++-6.dll` and
  `libgcc_s_seh-1.dll` were loaded from wherever Windows found them first);
  it starts with only System32 on PATH. The running release program reports
  a 64 MiB minimum working set. Reproducibility: two Linux release builds of
  the final source in different folders (same toolchain, same dependency
  builds) are bit-for-bit identical; the Windows `.exe` is not, because the
  PE link time is stamped in. The SHA-256 of the tested binaries are in
  `RELEASE_NOTES.md`.
- Building from source as `MANUAL.md` describes, in a fresh folder on Ubuntu
  24.04 (libsodium 1.0.20 checked against its pinned SHA-256 and built,
  OpenSSL 3.5.1 built by `scripts/build_openssl.sh`): the release build
  reports `secraxis 0.9.1` with 0 warnings and no weak-KDF marker, and a test
  build passes 21 of 21. The old Linux line (`-DSECRAXIS_OPENSSL_ROOT=/usr`)
  fails to configure on Ubuntu: its `libcrypto` is in the multiarch folder
  `/usr/lib/x86_64-linux-gnu`, which the build does not search.

## End-to-end on real terminals

Scripted sessions against real terminal windows, with screenshots
(`tests/interop/scenarios/`; the drivers are in `tests/interop/`). Rows
marked 0.9.1 ran on the release's final code; the other rows record earlier
rounds. The "hidden console" is the classic console with its window hidden.

| Where | Driver | What runs | Result |
|---|---|---|---|
| Windows, classic console (conhost) | `console_drive` | `win_vault`, `win_launcher` | 27/27, 20/20 (2026-10-31, round 3) |
| Windows Terminal 1.24 | `console_drive` | `win_vault`, `win_launcher` | all pass (the classic-console paste steps are skipped: Windows Terminal's own paste cannot be triggered from outside) |
| Windows Terminal or the classic console → Windows OpenSSH → Linux | `console_drive` | `win_ssh` | 18/18 (round 3) |
| Windows, hidden console (nothing shown) | `console_drive` | `win_vault`, `win_launcher`, `win_memory`, `win_hangup`, `win_conflict`, `win_save` | 23/23, 20/20, 34/34, 20/20, 42/42, 59/59 (round 5's final code) |
| Windows hidden console → OpenSSH → Linux | `console_drive` | `win_ssh` | 16/16 (round 5) |
| Linux, VTE 0.76 (GNOME Terminal's engine), with and without `xclip` | `linux_drive` | `linux_vault` | 26/26 (round 5, with `xclip`) |
| Linux, VTE 0.76 with `xclip` | `linux_drive` | `linux_memory`, `linux_hangup`, `linux_conflict`, `linux_save` | 21/21, 50/50, 43/43, 47/47 (round 5's final code) |
| Linux, tmux 3.4 inside VTE | `linux_drive` | `linux_tmux` | 16/16 (round 5) |
| Windows, hidden console, 0.9.1 (before the last round) | `console_drive` | `win_vault`, `win_launcher`, `win_memory`, `win_hangup` (now also the session ending), `win_conflict`, `win_save`, `win_prompt` | 24/24, 21/21, 35/35, 32/32, 43/43, 59/59, 4/4; the release `.exe` itself: `win_vault` 24/24, `win_hangup` 32/32 |
| Windows, hidden console, 0.9.1 final code | `console_drive` | the same seven; `win_vault` now with the classic console's own paste | 28/28, 21/21, 35/35, 32/32, 43/43, 59/59, 4/4 (222 checks); the release `.exe` itself: `win_vault` 28/28, `win_hangup` 32/32 |
| Linux, 0.9.1 (VTE 0.76, tmux 3.4, xterm 390) | `linux_drive` | `linux_vault`, `linux_tmux`, `linux_save`, `linux_memory`, `linux_hangup`, `linux_conflict`, `linux_xterm` | 27/27, 17/17, 47/47, 22/22, 55/55, 44/44, 2/2 (+ screenshots); no lock file left |
| Linux, 0.9.1, the ASan+UBSan build of the program | `linux_drive` | `linux_vault`, `linux_tmux`, `linux_save`, `linux_hangup`, `linux_conflict`, `linux_xterm` | 27/27, 17/17, 47/47, 55/55, 44/44, 2/2; no sanitizer report |
| Linux, 0.9.1, the TSan build of the program | `linux_drive` | `linux_vault`, `linux_save`, `linux_hangup`, `linux_conflict` | 27/27, 47/47, 55/55, 44/44; no sanitizer report |
| Linux, xterm 390 | `linux_drive` | `linux_xterm` | judged by screenshots (no read-back) |

`*_hangup`: the terminal goes away with unsaved work and a copied password.
Linux: a pty hangup as when an SSH connection drops (the process holding the
pty's other side is killed), SIGTERM, SIGHUP, the VTE window closed (VTE
kills the program 0.07 ms after the hangup: nothing saved, vault intact,
clipboard cleared), and a SIGKILL with the shell alive (the copy still gone
within the clipboard timeout + 5 s). Windows: the console window closed,
Ctrl+Break and (0.9.1) the session ending as at log-off (`end-session`).
`*_conflict`: another save put in place while the vault is open;
saving asks, Esc leaves the file untouched, "save a copy" keeps both, and
locking and unlocking again opens the copy. `*_save`: `q` with unsaved
changes asks (Esc back, `d` discards and locks, `s` saves and locks);
Settings: "save automatically" (the file copied right after an added entry
holds it; the choice is in `settings.json` and comes back on the next
start); on Windows "discard" drops an unsaved entry at Ctrl+Break; on Linux
the VTE window closed right after an autosaved entry (SIGKILL) loses
nothing, and Esc stops an unlock stuck on a stalled drive (`stall_open.c`:
the vault's open blocks), after which the program quits at once.
`win_prompt`: a subcommand's hidden password prompt, ended with Ctrl+Break,
gives the console its echo back.

Both save scenarios also type `q` and `d` in one write (`type-burst` in
both drivers): keys typed ahead of the unsaved-changes question must not
answer it, and the question stays. Both conflict scenarios check that the
start page's list (`recent.json`) names the copy right after it is made.

`win_ssh` failed now and then at its first check of a Chinese name (round 4
took it for a slow redraw and waited longer). A screen dump at that point
showed the real cause: the remote program had started in its plain ASCII
set, drawing non-ASCII names as `?`, or with its widths shifted by one.
The POSIX startup probe matched the terminal's cursor reports to its
questions by order alone, all asked on one row, waiting 400 ms each: over
SSH to a busy host (the Windows-side console's answers relayed by `ssh.exe`)
one answer came late and was taken for the next question's. Now each step
asks on a row of its own and sets aside an answer from another row, the
glyph burst stops trusting answers after its first timeout (the rest are
drawn plainly, never shifted), and over SSH the first answer may take 2 s
and each later one three times what it took. With the host busy (fuzzers
running on it): 6 of 11 runs failed with the old probe, 1 of 5 with the
longer waits alone, 0 of 8 with the rows as well. VTE, tmux and xterm are
unchanged (they answer in milliseconds).

`linux_drive` itself crashed now and then right after closing a VTE
widget (1 run in 3 of `linux_hangup`): GTK could still deliver an event to
the destroyed widget (`gtk_widget_get_toplevel` on freed memory, found with
gdb). The closed widget is now kept referenced; 5 runs in a row pass.

The scenarios cover creating and unlocking a vault, entries in several
scripts, show-while-typing, `Ctrl+V`, the terminal's own paste (bracketed: a
pasted `dy` in the list deletes nothing), copy with the clipboard timeout
(the Windows clipboard checked; OSC 52 across SSH), show and auto-hide,
clicks, search, help, resizing, save, lock, the start page (new vault by
click, double-click to reopen, browse with a pasted path, forget), and idle
CPU. On Windows the terminal's own paste is the classic console's (its
window menu's Edit > Paste, on Windows 11 25H2), which `console_drive` posts
to the console's window, visible or hidden. Until the release review's last
round those steps were marked `[conhost]` and ran only in a visible classic
console (the round-3 rows above), so the hidden runs skipped them; they are
now marked `[conhost,hidden]` and ran on the final code, the release `.exe`
included (the final 0.9.1 row below). Windows Terminal skips them: its own
paste cannot be triggered from outside. `console_drive` only writes to the
console it launched (never global keystrokes) and gives the user's
clipboard back unless it changed meanwhile. The runs use the real Windows
clipboard, so a user copying something during a run can fail its clipboard
check (Secraxis then rightly leaves the user's copy alone).

`bench_tui` measures key-to-frame time on a 5,000-entry vault (see
`TUI_SPEC.md`, "Responsiveness").

## How to run

```
# unit/integration (Windows or Linux; OpenSSL 3.2 or later; on Linux also
# -DSECRAXIS_SODIUM_ROOT=<libsodium-prefix> unless libsodium is in /usr/local)
cmake -S . -B build -G Ninja -DSECRAXIS_OPENSSL_ROOT=<openssl-prefix>
cmake --build build && ctest --test-dir build --output-on-failure

# sanitizer + fuzz campaign (Linux)
sh remote/run_sanitizers.sh                  # ASan+UBSan suite + fuzz
sh remote/run_openssl_gcmsiv_sanitize.sh     # + OpenSSL GCM-SIV under ASan

# local fuzz smoke (no sanitizer)
cmake -S . -B build_fuzz -G Ninja -DSECRAXIS_FUZZ_STANDALONE=ON -DSECRAXIS_OPENSSL_ROOT=...
cmake --build build_fuzz
FUZZ_ITERS=300000 ./build_fuzz/src/fuzz_targets/fuzz_json
```
