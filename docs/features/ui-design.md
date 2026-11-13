# basilisk interface design

The design system and the reasoning behind the interface of `bk-ui`: what
it looks like, why, and where it departs from Ghidra. The contract it
answers to is `docs/features/ui-shell.md`; the screenshots it describes are
in `docs/features/ui-screenshots/` (rendered by
`crates/bk-ui/tests/screenshots.rs`).

## 1. The brief, as decided

The owner's brief was "good-looking and intuitive", later sharpened: **the
interface should feel like Ghidra to someone who knows Ghidra**, and should
let panes be rearranged freely and popped out into their own windows. So the
design task is not to invent a new tool but to make Ghidra's CodeBrowser
look and feel good:

- **Keep where things are.** Ghidra's default window arrangement, its window
  and action names, its menu bar, its tool bar order, its right-click menus,
  its default key bindings, the shape of its listing and decompiler. A
  Ghidra user should find everything where they expect it.
- **Improve how it looks and feels.** Type, colour, spacing, icons,
  alignment, legibility over hours, responsiveness (nothing ever waits on
  the program), sensible defaults.
- **Add without taking away.** A command palette as a second route to every
  action and location; a hover preview; cross-window docking. Each addition
  sits beside the Ghidra way, never instead of it.

Test applied to each screen: next to Ghidra's screenshot of the same view
(`Ghidra/Features/Base/src/main/help/help/topics/CodeBrowserPlugin/images/CodeBrowser.png`
and the Decompiler's `DecompWindow.png`), a Ghidra user recognises it at
once and finds everything in the same place.

## 2. Layout

### Default arrangement (Ghidra's CodeBrowser)

```
┌ File Edit Analysis Navigation Search Select Tools Window Help ───────────────┐
│ [save] [← ▾ → ▾] [I D L F] [undo redo] [views]        [palette field] [☀] │
├───────────────┬──────────────────────────────┬────────────────────────────┤
│ Program Trees │ Listing: licd                │ Decompile: main - (licd)   │
│               │                              │                            │
├───────────────┤                              │                            │
│ Symbol Tree   │                              │                            │
│               ├──────────────────────────────┴────────────────────────────┤
│               │ Console │ Functions │ Defined Strings │ References         │
├───────────────┴───────────────────────────────────────────────────────────┤
│ last message                          main + 0x4b  1000018fb  x86:LE:64:… │
└───────────────────────────────────────────────────────────────────────────┘
```

- Program Trees above the Symbol Tree on the left (19 % of the width), the
  Listing in the centre, the Decompiler on the right (48 % of the rest), the
  Console at the bottom (21 % of the height) — Ghidra's places.
- Ghidra's Data Type Manager (bottom left) is not built in this track, so it
  is not in the default rather than shown as an empty placeholder.
- **Addition:** Functions, Defined Strings and References open by default as
  tabs beside the Console. Ghidra opens them on demand in floating windows;
  a newcomer cannot guess they exist. They take no space until chosen.
- Window → *any window* opens it where its family lives (tables beside the
  Console, trees in the left column), or brings it to the front if open.
  Window → Reset Window Layout restores this arrangement.

### Rearranging and native windows

- Every pane is a dockable tab (`egui_dock`): drag a tab onto another group
  to stack it, onto an edge to split, drag separators to resize, close with
  its ×, reopen from the Window menu. The layout is saved between runs.
- **Detach Window** moves a pane into its own operating-system window: from
  the tab's right-click menu, the Window menu, the palette, by
  double-clicking the tab, or by dragging the tab out of the dock area
  (egui_dock makes a floating window, which the shell turns into a native
  window at the same place on the next frame). A detached window is a dock
  area of its own: more panes can be stacked or split inside it.
- **Dock Window** puts its panes back: the button in the detached window's
  header strip, the tab's right-click menu, the Window menu, the palette.
- Closing a detached window closes its panes (reopen them from the Window
  menu), as closing a Ghidra window does; it never closes the tool.
- Detached windows reopen where they were (position and size are saved with
  the layout).
- All windows share one state (location, history, highlights, selection):
  a detached Decompiler follows the docked Listing with no special case,
  and the key bindings work in every window.

## 3. Names, menus, tool bar, key bindings

Window names are Ghidra's: Listing (`Listing: licd`), Decompile
(`Decompile: main - (licd)`), Symbol Tree, Program Trees, Functions
(`Functions - 77 items`), Defined Strings, Console, and the references
window (`References to log_msg`). Concepts keep Ghidra's words: plate
comment, pre/post/EOL comment, XREF, LAB_ / FUN_ / DAT_ / s_ labels,
thunk, snapshot.

**Menu bar** in Ghidra's order (File, Edit, Analysis, Navigation, Search,
Select, Tools, Window, Help — Ghidra's MenuBarManager puts File and Edit
first, the rest alphabetically, Window and Help last; this cut has no Graph
menu because there is no graph view yet). Actions sit where Ghidra puts
them: Go To in Navigation, Program Text and Memory in Search, Tool Options in
Edit, Auto Analyze in Analysis.

**Tool bar** in Ghidra's group order: Save; Previous/Next Location with their
history drop-downs; next Instruction, Data, Label, Function; Undo, Redo; then
view buttons. Added at its right end: the palette field and the theme switch.

**Right-click menus** on the Listing and Decompiler follow Ghidra's groups:
Copy; Follow Reference, Rename Function / Edit Label / Rename Variable (the
name follows what is under the cursor, as Ghidra's does), Comments ▸ (Set…,
Set EOL / Pre / Post / Plate Comment…, Delete), References ▸ (Show
References to *name*); Snapshot.

**Default key bindings are Ghidra's**, taken from the action definitions in
Ghidra's source (not from memory). Ctrl means the platform command key, as
in Ghidra (`DockingUtils.CONTROL_KEY_MODIFIER_MASK`): Ctrl on Windows and
Linux, Cmd on macOS; labels show the platform's name.

| Action | Key | Ghidra source |
|---|---|---|
| Go To… | G | `GoToAddressLabelPlugin.java:88` |
| Previous / Next Location in History | Alt+Left / Alt+Right | `NextPrevAddressPlugin.java:312` |
| Previous / Next History Function | Alt+Shift+Left / Right | `NextPrevAddressPlugin.java:405` |
| Go To Next / Previous Function | Ctrl+Down / Ctrl+Up | `GotoNextFunctionAction.java:42` |
| Rename (Edit Label, Rename Function, Rename Variable) | L | `EditLabelAction.java`, `RenameLocalAction.java:50` |
| Set Comment | ; | `CommentsActionFactory.java:129` |
| Delete Comment | Delete | `CommentsPlugin.java:193` |
| Show References to | Ctrl+Shift+F | `AbstractFindReferencesDataTypeAction.java:37` |
| Search Program Text | Ctrl+F | `SearchTextPlugin.java:420` |
| Search Memory | S | `MemorySearchPlugin.java:88` |
| Auto Analyze (disabled until M5) | A | `AutoAnalysisPlugin.java:146` |
| Decompile window | Ctrl+E | `DecompilerProvider.java:165` |
| Next Instruction / Data / Label | Ctrl+Alt+I / D / L | `NextPrevious*Action.java` |
| Next / Previous Highlight | Ctrl+. / Ctrl+, | `NextHighlightedTokenAction.java:38` |
| Undo / Redo | Ctrl+Z / Ctrl+Shift+Z | `UndoAction.java`, `RedoAction.java` |
| Open / Close / Save | Ctrl+O / Ctrl+W / Ctrl+S | `ProgramManagerPlugin.java:522`, … |
| Copy | Ctrl+C | `ClipboardPlugin.java:398` |
| **Command Palette** (basilisk) | Ctrl+Shift+P | — (unused by Ghidra) |
| **Follow Reference** (basilisk) | Enter | — (Ghidra: double-click only) |
| Exit (basilisk) | Ctrl+Q | — |

Bindings are remappable in Edit → Tool Options → Key Bindings by pressing
the new keys; taking a key from another action says so; "Restore Ghidra
Defaults" resets all. Bare keys (G, L, ;, S) never fire while a text field
has the keyboard.

## 4. The code views

### Listing

The field layout is Ghidra's default format, line for line:

```
                        ****************************************************
                        *                     FUNCTION                     *
                        ****************************************************
                        int parse_config_line(config_t *param_1,char *param_2)
            int              EAX:4              <RETURN>
            config_t *       RDI:8              param_1
                        parse_config_line                 XREF[1]:  load_config:100000ec9(c)
  100000d50  55               PUSH      RBP
  100000d51  48 89 e5         MOV       RBP,RSP                        EOL comment
```

Address, bytes, mnemonic, operands and EOL comment in fixed columns; plate
comments boxed in asterisks; the signature, then return/parameters/stack
variables with type, storage and name; the label with `XREF[n]:` and up to
four references (`function:address(c)`), then `[n more]`; `LAB_`, `FUN_`,
`DAT_`, `s_…` default labels; operands that refer to something replaced by
its name (`CALL validate_key`, `LEA RDI,[s_usage…]`, `JMP qword ptr
[->atoi]`). Spellings come from Ghidra's own decoder (`pcodedump`).

Departures, each to keep one row per line (§8): bytes beyond six are shown
as `…` rather than wrapped onto extra lines (the full bytes are in the
hover preview and Copy); a narrow pane scrolls horizontally rather than
wrapping.

Interaction (Ghidra's habits): click places the cursor on a row and token;
**double-click** follows the reference under the cursor; **middle-click**
highlights every matching token in the Listing and Decompiler (Ghidra's
"Cursor Text Highlight", middle button by default); right-click opens the
popup; shift-click or drag selects rows. Hovering a name shows a preview of
the listing at its target (Ghidra's reference hover). Arrow keys, Page
Up/Down, Home/End move the cursor; Left/Right step through tokens.

### Decompiler

Token-coloured C with line numbers (Ghidra's "Display Line Numbers"), two
spaces per indent level, plate comments as `/* … */` above the signature and
pre-comments above their statement, as Ghidra prints them. Clicking a token
puts the cursor on it and lightly marks its other uses; middle-click sets
the persistent highlight shared with the Listing; double-click follows;
Ctrl+. / Ctrl+, step between highlighted tokens.

### Cross-highlighting and following

One location is current for the tool (`nav::Navigator`). The rule:

- Going somewhere on purpose (go to, double-click, a table row, the palette)
  adds a history entry; moving the cursor within what is shown does not —
  Ghidra's navigation history semantics, 30 entries.
- Listing and Decompiler follow the current location unless they are
  snapshots. The Listing puts the target's header a third of the way down
  (Ghidra's go-to placement) and the cursor on the code unit.
- **Listing → Decompiler:** the decompiler shows the function containing
  the location and marks the lines produced from that instruction.
- **Decompiler → Listing:** putting the cursor on a statement moves the
  location to its first instruction (the Listing follows) and marks all of
  that statement's instructions with a quiet gutter bar and tint.
- Tables and trees mark the current function and navigate on selection.

## 5. Visual system

### Principles

- **Calm for long reading.** Warm, low-glare darks derived from the brand's
  soot; text slightly under full bone; no pure black or white surfaces.
- **Colour carries meaning, not decoration.** Twelve syntax roles, each a
  distinct hue at similar lightness, so nothing shouts; chrome is neutral.
- **Ember is the "you are here" colour, used sparingly:** the cursor
  marker, the active pane's tab icon, the focus ring, the primary button,
  palette matches. Nothing else is orange. An interface read for hours
  cannot be orange.
- **Hierarchy by surface.** Chrome (menu, tool bar, tab strips, status
  bar) is darkest and recedes; panes are one step lighter; floating things
  (menus, palette, dialogs) one step lighter again with a soft shadow.
  Separators are near-invisible lines in the chrome colour.

### Colour tokens (`design/tokens.rs`)

Surfaces, dark / light: chrome `#15100E` / `#EFEAE4`, surface `#1D1815` /
`#FBF8F4`, raised `#27211D` / `#FFFFFF`, selection (ember-tinted)
`#45291C` / `#F8D9C6`, cursor line `#2C241F` / `#F3ECE4`, linked rows
`#262421` / `#F5F0E6`, token highlight `#4A3D17` / `#F7E39A` (Ghidra's
highlight is yellow; this is its calm form).

Measured WCAG contrast (`design/contrast.rs` asserts these in tests: body
text ≥ 12, secondary ≥ 5.5, muted and comments ≥ 4.5, syntax ≥ 5.0 on every
code background, accent ≥ 3.0 as a mark):

**Dark**

| Token | Colour | on surface | on chrome | on cursor line |
|---|---|---|---|---|
| text | `#ECE5DD` | 14.1 | 15.1 | 12.2 |
| text_secondary | `#B3A89E` | 7.5 | 8.1 | 6.5 |
| text_muted | `#968C82` | 5.3 | 5.7 | 4.6 |
| accent (ember) | `#FF6A2B` | 6.2 | 6.6 | 5.3 |
| accent_text | `#FF8A57` | 7.6 | 8.1 | 6.5 |
| mnemonic | `#E4DCD3` | 13.0 | 13.9 | 11.2 |
| register | `#8DB8E8` | 8.5 | 9.1 | 7.4 |
| number (immediate, constant) | `#A8DCA0` | 11.2 | 12.1 | 9.7 |
| label (and bare address) | `#E3AC7E` | 8.8 | 9.4 | 7.6 |
| function (and import) | `#EAC86E` | 10.9 | 11.7 | 9.4 |
| global | `#EE98B0` | 8.2 | 8.8 | 7.1 |
| variable (and field) | `#C0D2EA` | 11.4 | 12.3 | 9.9 |
| parameter | `#B5A6F5` | 8.2 | 8.8 | 7.1 |
| keyword | `#DA94D0` | 7.6 | 8.2 | 6.6 |
| type | `#4EC5C1` | 8.4 | 9.1 | 7.3 |
| string | `#D3D98A` | 11.8 | 12.6 | 10.2 |
| comment | `#968C82` | 5.3 | 5.7 | 4.6 |

**Light**

| Token | Colour | on surface | on chrome | on cursor line |
|---|---|---|---|---|
| text | `#1E1814` | 16.6 | 14.7 | 15.0 |
| text_secondary | `#5E554E` | 6.9 | 6.1 | 6.2 |
| text_muted | `#6E645C` | 5.4 | 4.8 | 4.9 |
| accent (ember deep) | `#E8551A` | 3.5 | 3.1 | 3.1 |
| accent_text | `#B93D0A` | 5.3 | 4.7 | 4.8 |
| mnemonic | `#2A221D` | 14.7 | 13.1 | 13.3 |
| register | `#1D5FA8` | 6.1 | 5.4 | 5.5 |
| number | `#276B1A` | 6.2 | 5.5 | 5.6 |
| label | `#9A4E12` | 5.7 | 5.1 | 5.2 |
| function | `#7A5A00` | 6.0 | 5.3 | 5.4 |
| global | `#B02A5E` | 5.9 | 5.3 | 5.4 |
| variable | `#3F5163` | 7.7 | 6.8 | 7.0 |
| parameter | `#5B45C7` | 6.4 | 5.6 | 5.7 |
| keyword | `#9A2F96` | 6.2 | 5.5 | 5.6 |
| type | `#006A75` | 6.0 | 5.3 | 5.4 |
| string | `#5F5E00` | 6.4 | 5.7 | 5.8 |
| comment | `#6E655D` | 5.4 | 4.8 | 4.9 |

Distinctness: every pair of syntax roles differs by at least ΔE\*ab 16 (the
closest pairs: dark register/variable 17.9, light function/string 16.0);
the test asserts ≥ 15. No two roles differ only in red versus green: the
one green (numbers) has no red counterpart, and every role differs in
lightness or blue-yellow as well. Roles share a colour only where they mean
the same thing: immediates and C constants (a literal number), functions and
imports (something callable), variables and structure fields, labels and
unnamed addresses. Light ember is too pale for text on bone (2.9:1), so
light text accents use `#B93D0A`, and the mark uses Ember deep, as the brand
guide asks.

### Type

- **Inter** (chrome) and **JetBrains Mono NL** (code), both SIL OFL 1.1 —
  compatible with shipping in a GPL-3.0 program — bundled in the binary
  with their licence texts (`crates/bk-ui/assets/fonts/`). Inter is drawn
  for screens at small sizes; JetBrains Mono has a tall x-height and
  unambiguous `0O 1lI` (the no-ligature build, as listings must show every
  character as written). Semibold weights for headings and for function
  names where they are defined.
- **Scale** (points), comfortable / compact: body 13 / 12, small 12 / 11,
  code 13 / 12, title 16 / 15, display 28 / 26.
- **Rows:** code 20 / 17, tables and trees 24 / 20, tabs 30 / 26, tool bar
  36 / 30, status 26 / 22. Compact fits about 18 % more code rows. Row
  height is a token, not measured from the font, so the virtual scroller's
  arithmetic holds on every platform and DPI.

### Spacing and shape

Spacing scale 2, 4, 6, 8, 12, 16, 24, 40 px; radii 4 (controls), 6
(menus), 8 (palette, dialogs). Every gap uses the scale.

### Icons

Phosphor (MIT) through `egui-phosphor`, drawn in their own font family:
Inter carries private-use glyphs that would shadow Phosphor's codepoints in
a fallback chain (the first render showed `!` for Save). A small named set
in `design/icons.rs` (`BACK`, `SAVE`, `FUNCTION`, …) so a glyph changes in
one place. No emoji.

### Components (`design/widgets.rs`)

Icon button (quiet until hovered, accessible name = its tooltip), key chip
(a shortcut as a keycap), filter field (search icon, clear ×, accessible
name = its hint), pane tool bar strip, empty state (icon, what, what to
do), loading placeholder bar, section label, primary and secondary
buttons, focus ring. Views use these instead of styling egui widgets
themselves.

### Focus and states

The pane keys go to is the last one clicked; its tab icon is ember and its
cursor marker ember; other panes show their cursor in grey. Rows still
loading show soft placeholder bars, never a blank or a spinner per row.
Errors appear where they happen (a failed page shows its message in the
row; a rejected rename says why under the field) and in the Console;
transient notices sit in the lower right and never take focus.

## 6. Command palette (addition)

Tools → Command Palette (Ctrl+Shift+P), or the field at the end of the tool
bar: one list of every action (with its menu path and key) and every
function, label, import, global and string (fuzzy-matched by the data
source), and any address typed in hex. `G` opens the same palette in Go To
mode (titled "Go To Address/Label", locations only) — Ghidra's Go To dialog
with fuzzy matching. Disabled actions are listed with the reason (Auto
Analyze: "arrives with the core (milestone M5)").

## 7. Crates

| Need | Choice | Evaluation (crates.io, 2026-11-12) |
|---|---|---|
| GUI | `eframe`/`egui` **0.36.2**, wgpu | ADR-008. 0.37.0 (2026-10-15) exists, but `egui_dock` has no release for it; 0.36.2 is the version postmortem runs. Features: `wgpu`, `accesskit`, `persistence`, `wayland`, `x11`; no `default_fonts` (fonts are bundled). |
| Docking | **`egui_dock` 0.21.1** | 4.93 M downloads, 29 dependents, released 2026-08-06; `egui_tiles` 0.18.0: 2.70 M, 36 dependents, built for egui 0.37 (0.17.1 for 0.36). Both give tabs, splits, drag to rearrange and serde. Neither opens native windows. egui_dock's tear-out makes an in-window floating surface with a known rectangle, which the shell converts into a native window — the least fragile path to drag-to-detach; it is also the industry-standard choice by downloads and the one ADR-008 names. |
| Tables | `egui_extras` 0.36.2 `TableBuilder` | Resizable columns, virtualised body. |
| Icons | `egui-phosphor` 0.14.0 (regular only) | 442 k downloads, MIT/Apache; Phosphor glyphs MIT. |
| Fuzzy matching | `fuzzy-matcher` 0.3.7 (skim) | 38.4 M downloads, MIT, stable since 2020; `nucleo-matcher` 0.3.1 (6.1 M, MPL-2.0) is faster and newer but less used; the owner's rule prefers the industry standard. |
| PNG decode | `image` 0.25.10, `png` only | Brand marks and the window icon. |
| Tests | `egui_kittest` 0.36.2 (`wgpu`, `snapshot`) | Headless flows; GPU only for screenshots. |

Fonts: Inter 4.1, JetBrains Mono 2.304 (no-ligature), from their release
archives.

## 8. Differences from Ghidra

Each is deliberate; where practical the Ghidra way is still there.

1. **Command palette** (Ctrl+Shift+P) and a palette field in the tool bar:
   a second route to every action and location. Menus keep everything.
2. **Go To (`G`) is fuzzy and live**: matches appear as you type, functions
   first; an address typed in hex is always the first entry. Ghidra's
   dialog takes an exact label or address (and a wildcard query).
3. **Enter follows the reference under the cursor** in the code views
   (Ghidra: double-click only). Double-click still does.
4. **One row per line in the Listing**: instruction bytes beyond six show
   as `…` instead of wrapping onto extra rows; a narrow Listing scrolls
   sideways. This keeps every row the same height, which makes scrolling
   through ten million rows and jumping to any address O(1).
5. **Functions, Defined Strings and References open by default** beside
   the Console, so they can be found without knowing the Window menu.
6. **Views never wait for the program.** All program access runs on worker
   threads (ADR-012); pages still loading show placeholders. Ghidra's views
   call the program model on the Swing thread.
7. **Detached windows can be docked back only by the Dock Window action**
   (header button, tab menu, Window menu, palette), not by dragging a tab
   from a native window into the main one: `egui_dock` cannot drag between
   operating-system windows. Ghidra allows the drag. Tabs move freely by
   dragging within any one window.
8. **Double-clicking a tab detaches it** (a quick route besides the menus;
   Ghidra undocks by dragging a window's title).
9. **Hover preview in the Decompiler too**, not only the Listing.
10. **The References window lists all references to the target** in one
    table with a filter (Ghidra's "Location References" provider, opened by
    Show References to); it sits beside the Console.
11. **Rename and Set Comment are small, non-blocking dialogs**: Enter
    saves, Escape cancels, Shift+Enter starts a new comment line. Ghidra's
    comment dialog takes Enter as a new line by default.
12. **Theme and row density** are first-class (Edit → Switch Theme /
    Compact Rows, the sun/moon button); dark is the default.
13. **Every navigable token is an accessibility node** (a link with its
    text), so screen readers can read the code views — and tests can find
    tokens by name.
14. **No Graph menu, Data Type Manager or Bookmarks yet** (not in this
    track); their menu places and default keys are reserved for them.

## 9. Platforms

Built and verified on macOS; Windows and Linux are first-class (ADR-022)
and the design avoids what differs between them:

- Settings and the layout are stored by eframe's persistence in the
  platform's own configuration directory; the interface writes no paths.
- Shortcuts match egui's platform command modifier (Ctrl on Windows and
  Linux, Cmd on macOS) and are labelled per platform.
- Row heights and character widths are tokens and measured glyph advances,
  not pixel assumptions, so DPI scaling changes sizes, not arithmetic.
- The demo program is embedded and parsed with `str::lines`, which accepts
  CRLF if git converts line endings on Windows.
- Fonts, icons and the brand images are embedded in the binary.
- Headless tests need no GPU or display on any system; the screenshot test
  runs only when `BK_UI_SCREENSHOT_DIR` is set.
- Native windows use egui's deferred viewports. Known issues by platform
  (from postmortem's inventory 07 §1.1 and egui's tracker): on Windows a
  deferred viewport may not redraw while the root window has focus (egui
  #8466); on macOS opening a child from a full-screen root can flicker
  (#8259); on Wayland a viewport behind the main window can freeze (#5145).
  The interface schedules a repaint of every window whenever data arrives
  or the location changes.

## 10. What a later wave changes

- Real data: an adapter implementing `model::ProgramSource` over
  `bk-program` and `bk-decomp`; no view changes.
- The Data Type Manager, Function Graph, Bookmarks, Memory Map and byte
  viewer plug in as new `ViewKind`s (`views/mod.rs`).
- Token-level decompiler↔listing mapping (each `ClangToken` with its own
  address range) replaces today's line-level ranges when the real
  decompiler provides it.
