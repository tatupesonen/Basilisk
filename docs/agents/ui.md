# Track `ui` — status report

Branch `ui`, worktree `basilisk-wt/ui`. Spec `docs/features/ui-shell.md`,
design `docs/features/ui-design.md`, screenshots
`docs/features/ui-screenshots/`. Kept current so the work can be continued
from this file alone.

## Look at these first

- `docs/features/ui-screenshots/main-dark-normal.png` — the CodeBrowser
  layout; decompiler cursor on `check_debugger()`, its instructions marked
  in the listing.
- `docs/features/ui-screenshots/main-light-normal.png` — the same, light.
- `docs/features/ui-screenshots/hover-preview-dark.png` — Ghidra's
  reference hover, the plate comment and XREFs.
- `docs/features/ui-screenshots/palette-dark.png` — the command palette.

## Design in brief

Ghidra's CodeBrowser, made calm and legible: Ghidra's window arrangement,
names, menu bar, tool bar order, popup menus, default key bindings (taken
from Ghidra's Java source) and listing field layout, drawn with a warm,
low-glare palette derived from the brand's soot and bone, Inter and
JetBrains Mono, Phosphor icons, a strict spacing scale, and ember used only
for "you are here" (cursor marker, active pane, focus, primary button,
palette matches). Additions sit beside the Ghidra way: a command palette
(Ctrl+Shift+P, and `G` as a fuzzy Go To), Enter to follow, a hover preview
in both code views, native pop-out windows. Details and every difference
from Ghidra: `ui-design.md` §8.

Decisions I would most want questioned:
1. **Dark as the default theme.** Ghidra users know a light listing; the
   spec asked for dark first. Light is one click away.
2. **Bytes truncated at six with `…`** instead of Ghidra's wrapped bytes,
   to keep every row the same height (the basis of O(1) scrolling).
3. **Functions, Defined Strings and References open by default** as tabs
   beside the Console (Ghidra opens them on demand).
4. **Twelve syntax colours.** Measured and distinct, but more colourful than
   Ghidra's listing; a quieter set (colour only names and literals) is a
   one-file change in `design/tokens.rs`.
5. **egui 0.36.2, not 0.37.0**, because `egui_dock` has no 0.37 release.

## Built

`crates/bk-ui` (library) and the GUI entry point in `crates/basilisk`
(`basilisk` or `basilisk gui`; `--version` prints the version).

- `model` — the data interface: `ProgramSource` (listing rows by range,
  address → rows, memory blocks, function/string tables by query window,
  function at an address, decompile, symbols, lookup, references, search,
  comments, apply command) and plain data types (tokens with kind and
  referent, listing rows by field, decompiled lines with address ranges,
  commands). No egui types.
- `task` — `DataClient`: worker threads, `Pending<T>` handles,
  cancel-on-drop, newest-first, a repaint waker, revision counter,
  cancellable jobs with progress shown in the status bar.
- `demo` — `licd`, a real program: `demo/licd.c` compiled for x86-64 macOS,
  disassembled by Ghidra's own decoder (`pcodedump`), decompiler lines
  mapped to instructions through the DWARF line table
  (`demo/generate.py`, `demo/README.md`); and `SyntheticProgram`, any
  number of rows with arithmetic row ↔ address (10 M rows for the
  benchmark).
- `design` — tokens (two themes × two densities), egui theme, fonts,
  syntax mapping, icons, components; contrast and distinctness asserted
  in tests.
- `actions` — one registry (Ghidra names, menu, group, default keys,
  scope, popup) and a remappable, saved key map.
- `nav` — current location and history (Ghidra semantics, 30 entries).
- `shell` — the application: menu bar, tool bar (with history
  drop-downs), status bar, docking (`egui_dock`) with native detached
  windows (deferred viewports) for any pane, Detach/Dock actions, layout
  persistence and Reset Window Layout, command palette and Go To, Rename /
  Edit Label / Add Label, Set Comment (all four kinds), Search Program
  Text / Search Memory, About, Tool Options (appearance, key bindings with
  capture), notifications, start screen, undo/redo of edits, and a
  native-window self-test mode.
- `views` — Listing (virtual scroller over `u64` rows, page cache, cached
  row layouts, cursor and selection, middle-click highlight, hover
  preview, Ghidra popup menu, next instruction/data/label/function,
  snapshots, horizontal scroll), Decompiler (line numbers, token cursor
  and other-use marks, cross-highlighting both ways, follow, highlight
  stepping, snapshots, hover preview), Functions, Defined Strings,
  References, Search Results (paged sortable tables over `egui_extras`),
  Symbol Tree (lazy folders, filter, counts), Program Trees, Console.

Every flow of spec §4.1 works by mouse and by keyboard (see the flow
tests).

## Tests

| Kind | Count | Where | Runs |
|---|---|---|---|
| Unit | 57 | `src/**` | always |
| Headless flow (egui_kittest, no GPU) | 21 | `tests/ui_flows.rs` | always |
| Screenshots (wgpu) | 1 (32 images) | `tests/screenshots.rs` | with `BK_UI_SCREENSHOT_DIR` |
| Scrolling benchmark | 1 | `tests/perf.rs` | `--release -- --ignored` |
| Native windows, real binary | 1 script, 8 checks | `tests/native-windows.sh` | by hand (needs a display) |

Flow tests: open in Ghidra's layout; palette go-to and back/forward; `G`
go to an address; double-click a call in the listing and the decompiler;
the toolbar back button; cross-highlighting both ways; filter the
Functions table and navigate; rename a variable by keyboard and undo
(asserting the command sent to the source); rename a function from the
listing's popup menu; comment with `;`; Show References to; Search Memory;
Search Program Text; several functions open as snapshots; Window menu
reopens a closed pane; Reset Window Layout; detach a pane, follow
navigation in it, Dock Window; restore a saved layout with a detached
window; a remapped key runs its action; remap in Tool Options; close to
the start screen and reopen; keyboard cursor and Enter to follow.

Ghidra GUI tests ported: none in this track (spec §3: they are ported view
by view as each view gets real data).

## Benchmarks

`docs/PERF.md`, bk-ui: ten-million-row listing in the full interface,
release, Apple M1 Pro: wheel scrolling mean 0.63 ms, p95 1.66 ms, max
12.26 ms a frame; jumps across the program p95 1.40 ms; idle p95 1.63 ms.
Budget 16.7 ms. The test asserts the listing really moved and each jump
arrived.

## Verified where

- **macOS (this machine), by running:** build, clippy, all tests above
  including the GPU screenshots; `cargo run -p basilisk` opens the
  interface on the demo; native windows via `tests/native-windows.sh`:
  detaching makes a real (not embedded) window that paints; it follows
  navigation done in the main window; a G press in its own input opens Go
  To in that window; Dock Window puts it back; closing it through the
  window system closes its pane, not the tool; quitting saves it and the
  next launch restores it at the same position and size. **Not verified:**
  operating-system key delivery into a detached window (this terminal may
  not send keystrokes: `osascript is not allowed to send keystrokes`), and
  dragging a tab out with a real mouse (no pointer control here; the
  floating-to-native conversion is covered by a unit test of the layout).
- **Windows:** `cargo check` and `cargo clippy -D warnings` for
  `x86_64-pc-windows-msvc`, all targets of `bk-ui` and `basilisk`: clean.
  Nothing has run on Windows.
- **Linux:** `cargo clippy -D warnings` for `x86_64-unknown-linux-gnu`,
  all targets: clean. Nothing has run on Linux.
- **CI only:** running the headless tests on Windows and Linux; the
  native-window behaviour there (known egui issues listed in
  `ui-design.md` §9).

## Crates added (workspace, used only by `bk-ui` and the binary)

egui/eframe 0.36.2 (`wgpu`, `accesskit`, `persistence`, `wayland`, `x11`;
no default fonts), egui_extras 0.36.2, egui_dock 0.21.1 (`serde`),
egui-phosphor 0.14.0 (regular), image 0.25.10 (png), serde 1.0.229,
fuzzy-matcher 0.3.7; dev: egui_kittest 0.36.2 (`wgpu`, `snapshot`),
serde_json, ron. Evaluations with download figures: `ui-design.md` §7.
Fonts: Inter 4.1 and JetBrains Mono NL 2.304 (OFL 1.1), Phosphor (MIT).

## Build cost

Clean `cargo build -p basilisk` (dev profile, `CARGO_BUILD_JOBS=2`, fresh
target folder, this machine while other agents were building): **4 min
36 s**; with `bk-ui`'s test dependencies (`egui_kittest`, snapshot) the
first build of the track took 7 min 09 s. Of the 537 s of summed crate
compile time (205 crates): wgpu/naga/Metal 25 %, egui/eframe/winit/
accesskit 18 %, image and its PNG/colour crates 11 % (pulled in by eframe
anyway), `bk-ui` and `basilisk` 6 %, the rest 41 % (font shaping
`read-fonts`/`skrifa`/`harfrust` for epaint, `syn`, `serde_derive`, …).
Excluding the GUI crates from the default workspace build would save
almost all of this for the other crates' gates. `cargo-deny` reports 24
duplicate-version warnings from the GUI stack (warnings, not errors).

## Gaps

- Not in this track (spec §3) and not built: Data Type Manager, Function
  Graph, Bookmarks, Memory Map, byte viewer, Graph menu.
- File → Open / Import and Save: disabled with the reason (no loaders or
  program database yet); the start screen opens the demo.
- Decompiler ↔ listing linking is per line (DWARF), not per token as
  Ghidra's `ClangToken` ranges are; the interface carries ranges per line.
- Dragging a tab between operating-system windows: not possible with
  `egui_dock`; Dock Window replaces it.
- Hover preview shows listing rows only (no decompiled preview).
- Selection is row ranges in the listing only; no selection in the
  decompiler, no Select menu actions beyond Clear Highlight.
- Ghidra's listing field customisation (Edit the Listing Fields) is not
  offered; the field layout is fixed.

## Where it is still weaker than it should be

- The bottom panel is mostly empty Console on first open; it earns its
  space only once the user opens a table.
- The Listing is cut at the right in a narrow pane (Ghidra's columns are
  wide); horizontal scrolling works but there is no visible horizontal
  scroll bar to drag, only a thin indicator.
- The Options window's Set…/Clear controls look like plain text; the key
  bindings page is functional but plain.
- Snapshot tabs open beside the live view in the same group, so the live
  view is hidden until its tab is clicked.
- Everything was checked against the demo program and the synthetic one.
  With real data the decompiler's per-line ranges, string literal
  resolution by text and the `PTR_`/`->` naming come from the demo
  generator, not from a real program model; the views only rely on the
  data interface, but those details will look different.

## Follow-ups for the next wave

- An adapter implementing `model::ProgramSource` over `bk-program` and
  `bk-decomp`; no view changes needed.
- Proposed ADR: GUI dependencies confined to `bk-ui` and `basilisk`
  (as done here); consider excluding them from the default workspace build
  if CI time matters (figures above).
- Upgrade to egui 0.37 when `egui_dock` releases for it.

## Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` → `0`;
last lines `bans ok, licenses ok, sources ok` and
`tests: 79 passed, 0 failed`.

## Commits

```
697ef5e docs(ui): escape a bracket in a doc comment
c7b0764 style(ui): collapse nested ifs in the self-test
9fc94de docs(ui): status report
d16504e docs(ui): screenshots of every view in both themes, main window also compact
f69f822 test(ui): self-test places a key in the detached window when keystrokes cannot be sent; log osascript errors
d0de9d2 docs(ui): status report skeleton
f1982b2 test(ui): native-window self-test for the real binary
e3e454d fix(ui): show no value for array data, as Ghidra's listing does
ac5c1c8 feat(ui): repaint detached windows on shared changes; scrolling benchmark and design document
9ef9821 style(ui): tidy flow test imports
de8d066 style(ui): clean clippy (pedantic and restriction lints), colours as #RRGGBB
dc14f0f fix(ui): row counts past four XREFs, first-frame reveal, dialog height, submenu arrows, shared hover preview
db0c723 test(ui): headless flow tests for every task in spec 4.1, and accessible names
9fff734 feat(ui): design system, shell, docking with native pop-out windows, and the core views
a143fae feat(ui): data interface, background client and licd demo program
```
(plus this report's commit). Branch not merged or rebased; it is behind
`master`, which the coordinator merges.
