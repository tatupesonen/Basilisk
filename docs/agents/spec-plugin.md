# spec-plugin — status and final report

Specification track for the plugin system (ADR-014), worktree
`basilisk-wt/spec-plugin`, branch `spec-plugin`. Done; nothing in
progress.

## Written

- **`docs/inventory/05-extension-points.md`** — Ghidra's extension surface:
  scripts (the `GhidraScript`/`FlatProgramAPI` surface, state, lifecycle,
  transactions, `ask*` resolution, headless behaviour of GUI calls,
  providers), a census of the 335 bundled scripts, analyzers, loaders and
  opinions, exporters, plugins/services/events, the other extension-point
  suffixes, discovery and packaging, headless pre/post scripts,
  PyGhidra, idioms scripts rely on, and the Ghidra tests for all of it by
  checklist id. Every claim is marked source line, command, or judgement.
- **`docs/features/plugin-api.md`** (nine sections) — process model,
  Python object model, scripts, the flat layer with a table of all 225
  public method names of `FlatProgramAPI` and `GhidraScript`, Ghidra
  names on objects and in imports, the porting estimate and ten
  acceptance scripts, plugin packages (declaration, discovery, enabling,
  load order, isolation, reloading), plugin kinds (scripts, analyzers,
  loaders, exporters, actions, declarative views, decompiler proposers),
  threads and the GIL, transactions and undo, versioning; design, tests,
  nine tracks with acceptance checks, differences from Ghidra.
- **`docs/features/plugin-binding-constraints.md`** — 15 rules for the
  other specs, each with reason, conforming and non-conforming
  signatures, and where basilisk's crates and specs stand (cited).
- **`docs/agents/spec-plugin-experiments/`** — the script census tool
  and output; two PyO3 0.30.1 experiments with commands and results
  (README).

## Findings that matter beyond this track

1. **ADR-014's "embeds CPython" and DIRECTION's "single binary" conflict
   if read literally.** A binary that links libpython does not start when
   the library is absent — measured on macOS: `dyld: Library not loaded`,
   exit 134, even in a mode that never touches Python; it is also tied to
   one minor version and install path. Static linking makes Python
   mandatory, fixes its version, and on Windows third-party C extensions
   cannot bind to it (ADR-022 gap). Run-time loading is not supported by
   PyO3 (data-symbol imports). The spec therefore makes basilisk a Python
   **extension module** hosted by the user's CPython (`python -m
   basilisk`, or `import basilisk`), with the binary handing over to a
   found interpreter — Ghidra's own PyGhidra architecture. ADR candidate A
   below; this is the one decision the owner should look at.
2. **Ghidra commits a script's changes even when the script throws or is
   cancelled** (`GhidraScript.java:457-466`, `end(true)` in `finally`);
   its "keep changes?" prompt is dead code. The spec rolls back instead
   (opt-out per script).
3. **PyO3 0.30.1's macros emit no `unsafe` into the user's crate**
   (verified under `#![forbid(unsafe_code)]`), so `bk-plugin` keeps the
   workspace lint and needs no `unsafe-crates.txt` entry; ADR-020's
   "checked with sanitizers" note for `bk-plugin` can be narrowed.
4. **`bk-ui` must change before plugin UI work**: `ActionId` is a closed
   enum and `ACTIONS` a `const` table (`registry.rs:18,198,224`),
   `ViewKind` is closed (`views/mod.rs:30`). Constraint item 10.
5. **The monitor type lives in `bk-ui`** (`task::Progress`); library
   crates need one shared monitor before M4/M5 define their own
   (constraint item 7).
6. **Program-model requirements for ADR-025 item 6**: model edits need an
   origin and the replaced value so proposals can be removed (constraint
   item 11); variables need a stable identity, not an index (item 3).
7. **Decompiler results must be keepable**: the final `Ssa` and output
   tree movable into an `Arc` and `Sync`, with the architecture reachable
   through an `Arc` (item 6) — to settle in D07/D17.

## Decisions to confirm (ADR candidates, ready to paste)

```markdown
## ADR-030 — Python support is the `basilisk` extension module; the interpreter hosts it
(Coordinator, <date>, from the `spec-plugin` track; `features/plugin-api.md` 4.1,
`docs/agents/spec-plugin-experiments/README.md`. Refines ADR-014.)

ADR-014 says `bk-plugin` "embeds CPython"; `DIRECTION.md` says basilisk is a
single binary. A `basilisk` executable that links libpython does not start
where the library is absent (measured on macOS: `dyld: Library not loaded`,
exit 134, even in a mode that never uses Python) and is tied to one minor
version and installation path; linking CPython statically makes Python
mandatory, fixes its version and leaves Windows unable to load third-party C
extensions (ADR-022); PyO3 cannot load libpython at run time. Therefore:

* The `basilisk` executable contains no Python and runs everywhere.
* `bk-plugin` builds the `basilisk` Python extension module (PyO3
  `abi3-py310`, one wheel per platform, built with maturin), containing the
  whole application. It is used as a library (`import basilisk`, PyGhidra's
  role) or as the application with plugins (`python -m basilisk`).
* When Python plugins are wanted, the binary finds a CPython >= 3.10 that can
  import the same version of `basilisk` and hands over to `python -m
  basilisk` with the same arguments (`exec` on Linux and macOS, spawn and
  wait on Windows); without one it runs without plugins and says why.
* Release archives ship the wheel beside the binary; `basilisk python setup`
  installs it into a managed virtual environment, as Ghidra's PyGhidra
  launcher does. "Single binary" keeps meaning one executable and no helper
  programs.
* "Embedding" in ADR-014 is read as: CPython and basilisk share one process
  and Rust calls Python callbacks in it; CPython's executable owns `main`.
```

```markdown
## ADR-031 — Plugin API conventions
(Coordinator, <date>, from the `spec-plugin` track; `features/plugin-api.md` 4.2-4.10.)

* CPython 3.10 and newer, stable ABI (`abi3-py310`); free-threaded builds are
  deferred (`abi3t` is reconsidered when usable); no Rust code relies on the
  GIL for its own synchronisation and every pyclass is `frozen` and `Sync`.
* A script, action or console statement is one transaction and one undo step;
  normal end commits, any exception (including cancellation) rolls back —
  unlike Ghidra, which commits; `KEEP_CHANGES_ON_ERROR = True` restores
  Ghidra's behaviour per script.
* The flat layer keeps Ghidra's `FlatProgramAPI`/`GhidraScript` names and
  behaviour; model objects also answer Ghidra's bean-style getters in scripts.
* Plugin views are declarative (tables, token text, trees fed by paged
  providers); the UI thread never calls Python.
* `basilisk.API_VERSION` is versioned separately from the application,
  `(0, n)` until M9 is accepted; plugins declare a PEP 440 range; removals
  follow a deprecation of at least two minor releases.
* Language-model proposals (ADR-025 item 6) are off by default, applied with
  `Provenance::Model` and an origin through ordinary edits, never replace a
  value of higher rank, and are removable by origin.
```

```markdown
## ADR-032 — Core APIs follow the plugin binding constraints
(Coordinator, <date>, from the `spec-plugin` track; `features/plugin-binding-constraints.md`.)

Specs for the program model, storage, loaders, analysis, the decompiler's
host and results, and the UI state for each of the fifteen items of
`plugin-binding-constraints.md` whether they meet it or why they depart.
Two changes are made before the work that needs them: the monitor type moves
from `bk-ui` to a low crate, and `bk-ui`'s action registry and view kinds
accept run-time entries.
```

## Plan changes proposed

- **M9** in `PLAN.md`: replace its three items with the tracks of
  `plugin-api.md` 7 — P0 reference fixtures, P1 host and packaging, P3
  flat layer (these three can start now), P6 UI hooks (after the `bk-ui`
  registry change), P2 program bindings (with M4), P4a loaders (M4), P4b
  analyzers and exporters (M5/M6), P5 decompiler and proposers (after M5),
  P7 further script ports.
- **Crate map**: add `bk-plugin-ui` and `basilisk-py` (cdylib) beside
  `bk-plugin`; `crates/basilisk` gains a lib target (`run(args)`).
- **Queue before M4/M5 specs**: move the monitor type out of `bk-ui`;
  add constraint items 3, 6, 7, 9, 11, 13 to the M4 program-model/storage,
  M5 analysis and D07/D17 decompiler specs.
- **Next UI track**: the run-time action registry and plugin view kinds
  (constraint item 10).
- **ADR-020**: `bk-plugin` needs no `unsafe-crates.txt` entry (finding 3);
  the "later the PyO3 boundary in `bk-plugin`" sentence can say the
  sanitizer runs are of the Python test suite.
- **Test checklist**: propose marking `BundleHostTest`,
  `BundleStatusManagerTest` (OSGi) and `AutoServiceTest` (service
  framework) not applicable when P1 lands; PyGhidra's 47 pytest tests are
  not in the JUnit checklist and are tracked in `plugin-api.md` 6.2.

## Verified, and how

- Ghidra facts: read in source at the cited lines; counts by the commands
  in `05-extension-points.md` section 13 (script census reproducible from
  `script-census/README.md`).
- PyO3 0.30.1 (released 2026-10-14) features, build-config behaviour
  (extension-module detection, `-undefined dynamic_lookup`, `shared`
  config, free-threaded overriding abi3, `abi3t`), FFI data symbols, and
  pyclass `Send + Sync` assertion: read in the crate sources.
- Experiments on macOS arm64 (rustc 1.97.1): one abi3 build imports and
  passes all checks on CPython 3.10.11, 3.11.13, 3.12.11, 3.13.7, 3.14.9
  and fails cleanly on 3.9.6; GIL release (600 ms → 300 ms for two
  threads); callbacks from eight Rust threads; exception propagation both
  ways; cancellation from another Python thread; transaction context
  manager; Rust error enum to exception hierarchy; `forbid(unsafe_code)`
  compatibility; an `auto-initialize` binary failing to start without its
  libpython.

## Not verified

- Anything on Linux or Windows (loader behaviour without libpython is
  stated from how the loaders work, not run).
- The hand-over from the binary to `python -m basilisk`, the GUI (egui,
  winit) running inside a Python-hosted process, maturin builds and
  `manylinux_2_28` compliance of a wheel that contains the GUI — first
  acceptance items of P1.
- `PyThreadState_SetAsyncExc` under abi3 for cancelling stuck plugin code.
- Which Linux distribution Pythons lack a shared libpython (stated from
  build defaults; it does not affect the chosen design).
- The regex-based census tiers beyond the ten scripts read in full.

## Commits

```
20320a2 docs(plugin-api): wording fixes
d7a474f docs(plugin): binding constraints checklist for the other specs
a6cf94e docs(plugin-api): design, tests, acceptance and tracks, differences, status
b730609 docs(plugin-api): packages, plugin kinds, threads and GIL, transactions, versioning
c6701a3 docs(plugin-api): forbid(unsafe_code) experiment; askPassword note
f56ce9f docs(plugin-api): flat layer method table, Ghidra names, porting estimate, ten acceptance scripts
7198988 docs(plugin-api): purpose, sources, scope, process model, object model, scripts
7f9ad59 docs(spec-plugin): status
1d24eb0 docs(spec-plugin): PyO3 0.30.1 experiments (abi3 module across 3.10-3.14, GIL release, callbacks, embedding failure without libpython)
35c9f24 docs(inventory): Ghidra's extension surface (05-extension-points), bundled-script census
c83dab9 docs(spec-plugin): status file
```
(plus the commit adding this report)
