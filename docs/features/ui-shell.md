# User interface: shell, design system and core views (`bk-ui`)

Track `ui`, started at the owner's request ahead of milestone M7. Format of
this document: `docs/LOOP.md`, "Feature documents".

Path abbreviations: `HELP/` = `Ghidra/Features/Base/src/main/help/help/topics/`
(Ghidra's user manual: HTML plus 380 screenshots, one folder per plugin),
`BASE/` = `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/`,
both under `../ghidra`. The postmortem project at `../postmortem`
(`crates/pm-ui`) is a working egui application by the same owner and the
reference for egui practice.

## 1. Purpose

basilisk's desktop interface: where a reverse engineer reads disassembly
and decompiled code, navigates, renames and annotates. The owner's brief:
**good-looking and intuitive**. Ghidra's interface is powerful and famously
awkward; basilisk keeps the power — the same views, the same information,
the same arrangement — and improves how it looks and feels (ADR-001; see
"Familiar to Ghidra users" below). This track builds the
application shell, the design system and the first core views, against a
data interface that the real program model will implement later.

### Familiar to Ghidra users (owner rule, 2026-11-12)

"Make the UI somewhat represent old Ghidra; if you are proficient in Ghidra
it should be easy to work in basilisk." This ranks above the freedom to
rethink in the paragraph above. Someone who knows Ghidra's CodeBrowser must
be able to sit down and work at once, so by default basilisk keeps:

- **Ghidra's default layout**: Program Trees, Symbol Tree and Data Type
  Manager stacked on the left, the Listing in the centre, the Decompiler
  on the right, the Console at the bottom — the CodeBrowser arrangement
  (`HELP/CodeBrowserPlugin/images/CodeBrowser.png`).
- **Ghidra's names** for windows, views, actions and concepts (Listing,
  Decompiler, Symbol Tree, Defined Strings, Bookmarks, plate comment, EOL
  comment, XREF, label, …). Do not rename what Ghidra users already know.
- **Ghidra's menu structure** (File, Edit, Analysis, Navigation, Search,
  Select, Tools, Window, Help) with actions where a Ghidra user looks for
  them, and Ghidra's right-click menus on the listing and decompiler.
- **Ghidra's default key bindings** as basilisk's defaults, not an
  optional preset: `G`, `L`, `;`, `D`, `C`, `Ctrl+Shift+E`,
  `Alt+Left`/`Alt+Right` and the rest, from Ghidra's help.
- **The listing's field layout** as Ghidra draws it — address, bytes,
  mnemonic, operands, comments, XREFs in the same places — and the
  decompiler's presentation.
- **Ghidra's interaction habits**: double-click to follow, the middle-
  mouse highlight of matching tokens, the navigation history buttons.

What the designer improves is how it *looks and feels*, and what is
*added* — never where things are: a cleaner visual system (type, colour,
spacing, icons), legibility, responsiveness, sensible defaults, and
additions that take nothing away (the command palette, fuzzy go-to,
non-modal errors). A departure from Ghidra's arrangement or naming needs a
strong reason, is listed in `ui-design.md`, and where practical keeps the
Ghidra way available.

## 2. Sources

| Source | What to take from it |
|---|---|
| `HELP/CodeBrowserPlugin/`, `HELP/DecompilePlugin/` (under `Features/Decompiler/src/main/help`), `HELP/SymbolTreePlugin/`, `HELP/SymbolTablePlugin/`, `HELP/FunctionWindowPlugin/`, `HELP/ProgramTreePlugin/`, `HELP/Navigation/`, `HELP/Search/`, `HELP/BookmarkPlugin/`, `HELP/CommentsPlugin/`, `HELP/MemoryMapPlugin/`, `HELP/DataTypeManagerPlugin/`, `HELP/DockingWindows/`, `HELP/Tool/` | What each Ghidra view shows and does, with screenshots (`images/*.png`). Read the screenshots: they are the fastest way to learn what a reverse engineer expects to see in a listing row, a decompiler pane, a symbol tree |
| `BASE/codebrowser/`, `ghidra/app/util/viewer/field/` (Base) | The listing's fields: address, bytes, mnemonic, operands, labels, comments (EOL, pre, post, plate), cross-references, function signatures, separators — and the order and conditions in which they appear |
| `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/` (`ClangToken*`, `ClangLine`, `component/`) | The decompiler view's token model (each token knows its kind and what it refers to), which is what makes cross-highlighting with the listing possible |
| `BASE/navigation/`, `BASE/gotoquery/`, `ghidra/app/nav/` | Navigation history, go-to syntax |
| `../postmortem/crates/pm-ui` (`app/`, `task.rs`, `table.rs`, `palette.rs`, `tests/ui_flows.rs`), its `docs/DECISIONS.md` ADR-008 and ADR-023 | Proven egui patterns: virtualised tables over paged queries, background tasks with channels, a command palette, `egui_kittest` flow tests, deferred viewports for pop-out windows and the workarounds for their bugs |
| `assets/brand/` (this repository) | The logo, icon and palette (ember, soot, bone). The interface's identity starts from these |

Other tools in the field (IDA, Binary Ninja, Cutter) are fair to learn
from for interaction ideas; do not copy their look or assets.

## 3. Scope

**In (this track):**
1. `bk-ui`, a library crate: the design system, the application shell and
   the views below, all against the data interface in section 4.2.
2. A realistic **demo data source** implementing that interface, so the
   application runs, can be judged, and can be tested before the real
   program model exists.
3. The `basilisk` binary opens the interface (`basilisk` with no
   arguments, or `basilisk gui`), showing the demo program for now.
4. `docs/features/ui-design.md`: the design system and the reasoning
   behind the layout and interaction decisions, written by the designer.

**Crates owned:** `crates/bk-ui`, and the GUI entry point in
`crates/basilisk`. `bk-ui` depends on **no other `bk-*` crate**: the core
crates are being written on other branches. Everything the views need
comes through the data interface.

**Not in this track:** real program data, analysis, decompilation, saving,
import dialogs (they arrive as the core lands); the function graph, data
type manager, memory map, byte viewer editing, program diff, debugger
views (later waves — but the shell must make adding a view cheap);
porting Ghidra's GUI tests (they are ported view by view as each gets real
data, ADR-006; this track writes its own flow tests).

## 4. Behaviour

### 4.1 What a reverse engineer does here
Design for these, in this order of frequency: read a function in the
decompiler and the listing side by side; follow a reference (double-click
or Enter on a call target, address or symbol) and come back (history);
jump to a function, symbol or address by name; see who references the
thing under the cursor; rename a function or variable and comment a line;
search (strings, text, bytes); keep several functions open. Everything on
this list must be reachable from the keyboard, and the common ones in one
keystroke or one palette query.

### 4.2 Data interface
`bk-ui` defines the traits and plain data types the views consume — a
view-model layer, not Ghidra's API. It must be:

- **Paged and indexed**: a listing is millions of rows. The interface
  serves ranges ("rows from this address, this many"), counts and
  lookups; it never hands a view the whole program. Rows are addressed so
  that scrolling to an arbitrary address is direct.
- **Off the UI thread**: calls may be slow (storage, decompilation), so
  the interface is asynchronous in effect — requests go to a background
  worker and results arrive over a channel, with the view showing
  placeholder rows meanwhile and never blocking a frame (ADR-012). Design
  the pattern once (postmortem's `task.rs` is the model) and use it for
  every view.
- **Structured**: a listing row is fields (address, bytes, label,
  mnemonic, operands with their referents, comments, cross-references),
  not a preformatted string; decompiled code is lines of tokens, each with
  its kind and what it refers to (function, variable, type, address), so
  views can colour, highlight and navigate. Model these on Ghidra's
  listing fields and `ClangToken` kinds.
- **Complete enough for the views in 4.4** and for edits (rename,
  comment) to be expressed as commands sent back through it.

Later an adapter implements it over `bk-program` and `bk-decomp`; keep it
free of anything those cannot provide and of anything egui-specific.

### 4.3 Shell
- **Layout**: dockable panes — tabs, splits, drag to rearrange — with a
  sensible default arrangement that a newcomer can use without touching
  it, layout persistence between runs, and a "reset layout" action.
  Panes can pop out into native windows (deferred viewports, as
  postmortem does) or the design may defer this to a later wave if it
  says why.
- **Command palette** (one shortcut): every action, plus go-to for
  functions, symbols and addresses, fuzzy-matched, with the shortcut
  shown beside each action. It is an addition: Ghidra's menus, toolbar
  and bindings remain the familiar way in, and the palette reaches the
  same actions faster.
- **Actions and key bindings**: one registry of actions (name,
  description, default shortcut, enabled-when); menus, palette, context
  menus and shortcuts all come from it. Bindings are remappable and
  stored. Ghidra's default bindings are basilisk's defaults for
  every action the two share (take them from Ghidra's help), so Ghidra
  users are at home; say where and why basilisk differs.
- **Navigation**: one location model shared by all views; back/forward
  history; views follow the current location according to a clear rule
  (and can be pinned).
- **Status bar** (current address, function, selection, background task
  progress), **task/progress** display for long work with cancel,
  **notifications** that do not steal focus, an **options** window
  (appearance, key bindings).
- **Welcome state** when no program is open: the logo, recent programs,
  open/import. Not a blank window.
- Nothing modal unless it must be. Errors are shown where they happen and
  say what to do.

### 4.4 Views in this track
- **Listing**: virtualised disassembly with Ghidra's fields; function
  headers and separators; labels; operands whose referents are navigable
  and hover to preview; comments; cross-reference summaries; cursor and
  selection; current-line and same-token highlighting; smooth scrolling
  through millions of rows; go-to.
- **Decompiler**: token-coloured C for the current function; clicking a
  token highlights its other uses; cross-highlighting with the listing in
  both directions (cursor in one moves the highlight in the other);
  navigable references; rename and comment from here.
- **Functions**: a sortable, filterable table (name, address, size,
  …) over the paged interface; type to filter.
- **Symbol tree**: namespaces, functions, labels, imports, exports, with
  filtering.
- **References** to the item under the cursor (a pane or popup).
- **Strings**: defined strings table with filter.
- **Output/console** for log messages.

Each view is its own module behind a small trait so that a view added
later (function graph, data types, memory map, bytes) plugs into docking,
navigation, the action registry and the palette without touching the
shell.

### 4.5 Design system
A single source for colour, type, spacing and component styles; views use
tokens from it and never hard-code a colour or a size.

- **Identity**: starts from the brand — ember `#FF6A2B`, soot `#150F0D`,
  bone `#F1ECE6` (`assets/brand/README.md`). Ember is an accent, used
  sparingly: an interface people stare at for hours cannot be orange.
- **Themes**: dark first (the default), and a light theme from the same
  tokens. Both must hold contrast: body text at least 4.5:1, syntax
  colours distinguishable from each other and from the background, and
  not relying on red/green alone.
- **Syntax colours** for the listing and decompiler: a considered palette
  with a role per token kind (mnemonic, register, immediate, address,
  label, comment, keyword, type, function, variable, string, constant),
  consistent between the two views.
- **Typography**: a proportional face for chrome and a monospaced face
  for code, chosen for legibility at small sizes and for unambiguous
  `0O 1lI` glyphs. A bundled font must have a licence compatible with
  distribution in a GPL-3.0 product (for example the SIL Open Font
  License); record the font and its licence. Sizes and line heights form
  a scale; density is adjustable (compact/comfortable).
- **Layout rhythm**: a spacing scale; consistent pane headers, tables,
  inputs, menus; clear focus indication for keyboard use; visible but
  quiet separators; motion only where it explains a change.
- **Icons**: a small consistent set (from a licence-compatible icon font
  or drawn), not emoji from egui's default fonts.
- Sizes and colours go through egui's style where it has the concept, and
  through the token set otherwise, so the whole application restyles from
  one place.

Write the system and the reasoning down in `docs/features/ui-design.md`:
the tokens, the palette with contrast figures, the type scale, the default
layout and why, and each place the interaction deliberately differs from
Ghidra with the reason.

## 5. Design (engineering)

- **Stack** (ADR-008): `eframe`/`egui` with the wgpu renderer,
  `egui_extras` for tables, `egui_kittest` for tests — the versions
  postmortem runs (`0.36.2`) unless a newer release at least two weeks old
  is better; pin exactly. For docking, evaluate `egui_dock` and
  `egui_tiles` under ADR-011 (features needed here, maintenance,
  download figures) and record the choice.
- Modules: `design/{tokens, theme, typography, syntax, icons, widgets}`,
  `model/{location, listing, decomp, symbols, functions, strings,
  commands, source}`, `demo/` (the demo data source), `task` (background
  work), `actions/{registry, keymap}`, `shell/{app, dock, palette, menu,
  status, options, welcome, notifications}`, `views/{listing, decompiler,
  functions, symbol_tree, references, strings, console}`, `nav`.
- **State**: views do not own program data; they hold view state (scroll,
  selection, filter) and cached pages. One place owns the current
  location and history. No global mutable state.
- **Performance** (ADR-012): only visible rows are laid out; row heights
  are uniform or cheaply computed so scrolling to any address is O(1);
  text layout for visible rows is cached between frames; no allocation
  per row per frame in steady state. Budget: 60 frames per second while
  scrolling a ten-million-row listing on this machine; measure frame time
  and record it.
- **Demo data**: a believable small program — a few dozen functions with
  real x86-64 disassembly and plausible decompiled C, cross-references
  that resolve, strings, imports — plus a synthetic generator that
  produces a ten-million-row listing for the performance test. The
  disassembly may be captured from the reference tools
  (`../reference/bin/pcodedump`, `decomp`) so it is real.
- `bk-ui` follows the workspace rules: no `unsafe`, no panics, typed
  errors, documented public items, no file over 1,000 lines.

## 6. Tests

- **Flow tests** with `egui_kittest` for every item in 4.1: open the demo
  program, navigate by double-click and by palette, go back, cross-
  highlight between listing and decompiler, filter the function table,
  rename and comment (asserting the command sent to the data source),
  rearrange and reset the layout, remap a key.
- **Snapshot images** of the main window in both themes and of each view,
  rendered headlessly, kept as `insta`/kittest snapshots. They are also
  the designer's eyes: the design is judged from renders, not from code.
- **Unit tests**: the action registry and keymap, navigation history,
  fuzzy matching, paging and cache logic, the token contrast checks
  (assert the contrast figures the design doc claims).
- **Performance test**: frame time while scrolling the ten-million-row
  listing; numbers in `PERF.md`.
- UI tests must run headless in CI; anything that needs a GPU is opt-in
  behind an environment variable, as in postmortem.

## 7. Acceptance

1. `cargo run -p basilisk` opens the interface on the demo program and
   every flow in 4.1 works by mouse and by keyboard.
2. The design holds together when looked at: the designer has reviewed
   rendered screenshots of every view in both themes at normal and
   compact density, and the screenshots are in the repository
   (`docs/features/ui-screenshots/`) for the owner to judge.
3. `docs/features/ui-design.md` documents the system and the deliberate
   differences from Ghidra.
4. The data interface is paged, off-thread and free of egui types, and
   the demo source is the only implementation the views know about.
5. Flow tests pass headless; the scrolling budget is met and recorded.
6. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- A command palette is added as a fast way to reach actions and
  locations; Ghidra has none. Menus, toolbars and key bindings stay where
  Ghidra has them.
- Views consume a paged, asynchronous data interface rather than calling
  the program model on the UI thread.

(The implementing agent appends the rest, with reasons, and mirrors them
in `ui-design.md`.)

## 9. Status

Not implemented yet.
