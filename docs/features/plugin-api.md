# Plugin API: Python through PyO3 (`bk-plugin`, the `basilisk` package)

Track family `plugin`, specified early at the owner's request (2026-11-14)
so that the crates being built now are shaped for it; the implementation
milestone stays M9 for most of it (section 7). Decision of record:
ADR-014. Format: `docs/LOOP.md`, "Feature documents". Inventory of what
Ghidra offers: `docs/inventory/05-extension-points.md` (cited as *inv.*).
Rules for the Rust APIs other specs define: `plugin-binding-constraints.md`.

Path abbreviations: `BASE/` = `Ghidra/Features/Base/src/main/java/ghidra/`,
`PYG/` = `Ghidra/Features/PyGhidra/`, under `../ghidra`. Claims about
PyO3 are against **PyO3 0.30.1** (crates.io, 2026-10-14), read in its
source or measured by the experiments in
`docs/agents/spec-plugin-experiments/` (cited as *exp.*); anything not
verified is marked **unverified**.

## 1. Purpose

Users must be able to extend basilisk themselves, as they extend Ghidra
with scripts, analyzers, loaders, exporters and plugins. basilisk's
extension language is Python 3: a package `basilisk` exposes the program
model, analysis, the decompiler and UI hooks with a Python-shaped API; a
flat scripting layer keeps Ghidra's `FlatProgramAPI`/`GhidraScript` names
so existing scripts port with small, mechanical changes; and the same
package is importable from any Python process to drive basilisk as a
library (PyGhidra's role).

## 2. Ghidra sources

| Source | What is taken from it |
|---|---|
| `BASE/program/flatapi/FlatProgramAPI.java` (2,696 lines), `BASE/app/script/GhidraScript.java` (4,117) | The flat layer: every public method (section 4.4), the state fields, the `ask*` resolution order, headless behaviour of GUI calls, the transaction around `run` (inv. 2) |
| `BASE/app/script/` (`GhidraState`, `ScriptInfo`, `GhidraScriptProvider`, `GhidraScriptUtil`, `ScriptControls`), `BASE/app/plugin/core/script/RunScriptTask.java` | Script metadata tags, providers, directories, running, error reporting |
| `Features/Decompiler/.../decompiler/flatapi/FlatDecompilerAPI.java` | `decompile(function[, timeout])` |
| `BASE/app/services/Analyzer.java`, `AnalyzerType.java`, `AnalysisPriority.java`, `BASE/app/plugin/core/analysis/{AutoAnalysisManager,AnalysisScheduler}.java` | Analyzer contract, kinds, priorities, added/removed sets, options (inv. 4) |
| `BASE/app/util/opinion/{Loader,LoadSpec,LoaderTier,AbstractProgramWrapperLoader,QueryOpinionService}.java` | Loader contract and selection (inv. 5) |
| `BASE/app/util/exporter/Exporter.java` | Exporter contract (inv. 6) |
| `Framework/Project/.../plugintool/{PluginInfo,Plugin}.java`, `BASE/app/plugin/ProgramPlugin.java` | Which program events a plugin can follow (inv. 7) — not the service framework itself (ADR-001) |
| `BASE/app/util/headless/{HeadlessAnalyzer,HeadlessScript}.java` | Pre/post scripts, continuation options, headless store (inv. 10) |
| `PYG/` (`src/main/py/src/pyghidra/*.py`, `PyGhidraScriptProvider.java`, `support/pyghidra_launcher.py`) | The process model (Python hosts the application), script globals, `transaction()` rolling back, finding a Python and a virtual environment (inv. 11) |
| `Framework/SoftwareModeling/.../symbol/SourceType.java` | `AI` source type at `ANALYSIS` rank (lines 28-54) — basilisk's `Provenance::Model` |
| Ghidra's bundled scripts (335; inv. 3) | The porting target and the ten acceptance scripts (4.5) |

Java is the only implementation of all of this; there is no C++ side.

## 3. Scope

**In:**
1. `bk-plugin`: the PyO3 bindings, the plugin host (discovery,
   registration, isolation, reloading), the script runner and the flat
   layer's Rust side; built as the `basilisk` Python extension module.
2. The Python package `basilisk` (Rust extension plus a small pure-Python
   part: the flat layer, the Ghidra-compatibility names, decorators,
   type stubs).
3. The hand-over from the `basilisk` binary to a Python interpreter that
   hosts the extension (4.1), in `crates/basilisk`.
4. Plugin kinds: scripts, analyzers, loaders, exporters, UI actions and
   views, decompiler proposers (ADR-025 item 6).
5. Ports of ten bundled Ghidra scripts as acceptance (4.5); further ports
   as a later track.

**Not in:** running Java or Jython (basilisk has no JVM, ADR-005); a
service-locator framework (ADR-001); Ghidra's OSGi bundles; sandboxing
(plugins are trusted, ADR-014); plugins that draw egui directly (views are
declarative, 4.7.6); file systems, relocation handlers, ELF extensions,
demanglers and correlators as plugin kinds (later; inv. 8 ranks them
second); a Python debugger integration (PyGhidra's `debug_callback`).

**Crates.** `bk-plugin` (new, the only crate with PyO3 and the only one
whose `unsafe` comes from CPython: `unsafe-crates.txt` entry
`bk-plugin no-miri:CPython FFI through PyO3`, ADR-020), a pure-Python tree
`python/basilisk/` beside it, and a small `plugin` module in
`crates/basilisk` (the hand-over). `bk-plugin` depends on the library
crates it binds; nothing depends on `bk-plugin` except the extension
build. The tracks that build it are in section 7.

## 4. Behaviour

### 4.1 Process model: the interpreter hosts basilisk

ADR-014 says "`bk-plugin` embeds CPython", and `DIRECTION.md` says
basilisk is a single binary. Taken literally — the `basilisk` executable
links libpython — the two cannot both hold, on any of the three systems:

- **Linking libpython dynamically** (PyO3 `auto-initialize`): the
  executable records libpython as a load-time dependency. Measured on
  macOS (*exp.* `pyo3-embed`): the binary records Homebrew's
  `…/Python.framework/Versions/3.12/Python` by absolute path, and with
  that file absent **it does not start at all**, not even in a mode that
  never touches Python (`dyld: Library not loaded`, exit 134). On Linux
  (`DT_NEEDED libpython3.X.so.1.0`) and Windows (import of
  `python3X.dll`) the loaders behave the same way (unverified: not run).
  The binary would also be tied to one minor version.
- **Linking CPython statically** (PyO3 supports it through a
  `PYO3_CONFIG_FILE` with `shared=false`; `pyo3-build-config`
  `impl_.rs`, the `shared(…)` default): the interpreter is always
  present, so it is no longer optional; the minor version is fixed by
  the basilisk release, so users' virtual environments must match it;
  the standard library must be shipped; and on Windows third-party
  extension modules (`numpy`, `capstone`, model clients with native
  parts) import `python3XX.dll` by name and cannot bind to an interpreter
  inside `basilisk.exe` [J] — a Windows-only gap ADR-022 forbids.
- **Loading libpython at run time** (`dlopen`): PyO3 has no such mode, and
  its FFI imports data symbols (`_Py_NoneStruct`, `pyo3-ffi` `object.rs:655`;
  `PyExc_TypeError`, `pyerrors.rs:196`), which the platform loaders bind
  at start-up and Windows cannot delay-load [J]. Many Pythons have no
  shared libpython at all (Debian's `/usr/bin/python3.X`, pyenv builds
  without `--enable-shared`) [J; the local Homebrew and pyenv builds were
  checked, *exp.* README]. Moving the PyO3 code into a separately loaded
  library would put two copies of every `bk-*` crate in the process with
  no stable ABI between them [J].

**Decision (ADR candidate A, section 9.1).** basilisk's Python support is
the `basilisk` **extension module**, and a CPython interpreter hosts it —
which is how Ghidra's own CPython support works (PyGhidra starts the JVM
inside CPython; Python scripts run only "if Ghidra was started with
PyGhidra", `PyGhidraScriptProvider.java:71-77`). Concretely:

1. `bk-plugin` builds one cdylib, the `basilisk` extension module, with
   PyO3's `abi3-py310` feature. It contains the whole application —
   headless pipeline, analysis, decompiler, GUI — callable from Python.
2. **As a library**: `pip install basilisk` (a wheel) and `import
   basilisk` from any CPython ≥ 3.10. Verified: one build loads and works
   in 3.10, 3.11, 3.12, 3.13 and 3.14, and fails cleanly with
   `ImportError` in 3.9 (*exp.* `pyo3-abi3`).
3. **As the application with plugins**: `python -m basilisk [args]` (and
   a `basilisk-py` console script) runs the same CLI and GUI as the
   binary, with the plugin host active. `basilisk.main()` must be called
   on the interpreter's main thread (the GUI event loop needs the process
   main thread on macOS) and runs the event loop with the GIL released.
4. **The single binary** `basilisk` contains no Python. When Python
   plugins are wanted — the setting `plugins.python = "on"`, the flag
   `--python`, or a command that needs Python (`basilisk script x.py`,
   `basilisk analyze --post-script x.py`) — it looks for an interpreter
   (order below) that is CPython ≥ 3.10, not a free-threaded build, and
   can `import basilisk` with `basilisk.__version__` equal to the
   binary's version. It then hands over: on Linux and macOS it `exec`s
   `<python> -m basilisk <the same arguments>` (same process id, same
   terminal); on Windows it spawns that command, waits, and exits with its
   status. If none is found it carries on without Python: plugins are
   listed as unavailable with the reason (status bar, Plugins window,
   `basilisk --version`), and a command that needs Python fails with the
   reason and the setup command. The binary never half-loads Python.
5. **Interpreter search order**: `--python <path>`; the setting
   `plugins.python_executable`; `BASILISK_PYTHON`; the active virtual
   environment (`VIRTUAL_ENV`, then `bin/python` or `Scripts\python.exe`);
   the basilisk-managed environment (below); on Windows `py -3`; then
   `python3` and `python` on `PATH`. Each candidate is probed once with
   `-c` (version, free-threading, `basilisk.__version__`) and the result
   cached with the executable's modification time.
6. **The managed environment**: `basilisk python setup` creates a virtual
   environment in the user settings directory with a found interpreter
   and installs the wheel shipped beside the binary in the release
   archive (or, if absent, `basilisk==<version>` from the package index),
   as `pyghidra_launcher.py` does for Ghidra (`:132-212`). `basilisk
   python install <package>` runs `pip install` in it. Externally managed
   system Pythons (PEP 668) are never written to.

Per platform:

| | Python found | No Python |
|---|---|---|
| macOS (arm64, x86-64) | hand-over by `exec`; python.org, Homebrew, pyenv, uv and conda interpreters all qualify (no shared libpython needed) | binary runs, plugins unavailable |
| Linux (x86-64, aarch64) | as macOS; distribution Pythons qualify (statically linked ones too) | as macOS |
| Windows (x86-64, arm64) | spawn and wait; `py -3` launcher or `python.exe` | as macOS |

What was verified: items 2 and 3's threading behaviour on macOS arm64
only (*exp.*). The hand-over itself, the wheels for Linux and Windows,
and the GUI running inside a Python-hosted process are **unverified** and
are the first acceptance items of track P1 (section 7).

**Stable ABI.** One `abi3-py310` wheel per platform instead of one per
minor version (5 versions × 6 platforms today). The cost: the limited API
forbids a few fast paths (no direct struct access), which matters for
nothing in a binding whose calls are dominated by program-model work [J].
**Supported versions**: CPython 3.10 and newer (Ghidra: 3.9–3.15,
`Ghidra/application.properties:10`; 3.9 left support in October 2025).
PyPy and GraalPy are out of scope.

**Free-threaded CPython** (3.13t, 3.14t): an abi3 module cannot load in
it; PyO3 turns an abi3 build against a free-threaded interpreter into a
version-specific free-threaded build (`pyo3-build-config` `impl_.rs`,
"This fires even if is_abi3() is True"). PyO3 0.30 has an `abi3t`
feature (`abi3t-py315`) for the free-threaded stable ABI. **Open
question**: whether to ship an `abi3t` wheel once it is usable. Rule
fixed now so the answer stays cheap: no Rust code relies on the GIL for
its own synchronisation, and every pyclass is `frozen` and `Sync`
(4.8).

### 4.2 The object model

One package, `basilisk`, designed for Python: snake_case, properties for
attributes, iteration for collections, context managers for transactions,
exceptions for errors, type stubs (`.pyi`) for editors.

```
basilisk                  open(path) -> Program, import_file(...), Program, Address, AddressSet,
                          API_VERSION, __version__, exceptions, main()
basilisk.program          Program, Memory, MemoryBlock, Listing, CodeUnit, Instruction, Operand,
                          Data, Comments, CommentKind, Bookmarks, Equates
basilisk.address          Address, AddressSpace, AddressRange, AddressSet
basilisk.symbols          SymbolTable, Symbol, SymbolKind, Namespace, Provenance
basilisk.references       ReferenceManager, Reference, RefType
basilisk.functions        FunctionManager, Function, Parameter, Variable, Prototype
basilisk.types            DataTypeManager, DataType and its kinds, parse_c(), open_archive()
basilisk.lang             Language, Register, CompilerSpec
basilisk.pcode            PcodeOp, Varnode, Opcode
basilisk.decompiler       Decompiler, DecompileResult, TokenLine, Token, HighFunction, HighSymbol
basilisk.analysis         AnalysisManager, Analyzer, AnalyzerKind, Priority, Option, MessageLog
basilisk.loaders          Loader, LoadSpec, LoaderTier, ByteProvider
basilisk.exporters        Exporter
basilisk.ui               context(), go_to(), select(), highlight(), notify(), status(),
                          show_addresses(), table(), ask_*(), Action, View
basilisk.task             Monitor, CancelledError
basilisk.plugin           PluginInfo, script, analyzer, loader, exporter, action, view, proposer,
                          Proposal, reload()
basilisk.flat             FlatAPI: Ghidra's flat names (4.4)
basilisk.ghidra           compatibility names for ported scripts (4.4.2)
```

Program (one per open program; several may be open):
`name`, `path`, `language`, `compiler_spec`, `image_base`,
`min_address`, `max_address`, `memory`, `listing`, `symbols`,
`references`, `functions`, `types`, `comments`, `bookmarks`, `equates`,
`analysis`, `decompiler`, `addr(x)` (from `int` in the default space or
from text `"ram:401000"`), `transaction(name)`, `undo()`, `redo()`,
`save()`, `options`.

Typical use:

```python
import basilisk
with basilisk.open("licd") as program:          # headless, from an ordinary Python
    main = program.functions.by_name("main")[0]
    for caller in main.callers:
        print(caller.name, caller.entry)
    with program.transaction("Annotate"):
        main.comment = "entry after libc start-up"
        for ref in program.references.to(main.entry):
            program.comments.set(ref.from_address, basilisk.CommentKind.EOL, "-> main")
    result = program.decompiler.decompile(main)   # releases the GIL while it runs
    print(result.c)
```

**Conventions.**
- **Handles.** A Python object for a program entity (`Function`,
  `Symbol`, `Instruction`, `Data`, `MemoryBlock`, `DataType`, …) holds the
  program's shared handle and the entity's stable id, nothing borrowed.
  Attribute reads query the model; two handles are equal when program and
  id are equal, and are hashable. If the entity is deleted, the next
  access raises `StaleObjectError` (Ghidra's DB objects report
  `isDeleted`). Handles stay valid across transactions, undo and redo
  (the id is stable; an undone creation makes the handle stale).
- **Values** are immutable Python values: `Address` (space plus offset,
  hashable, ordered within a space; `addr + 4`, `b - a` → `int`,
  `int(addr)`, `str(addr)` in Ghidra's format `00401000` /
  `stack[-0x10]`), `AddressRange`, `AddressSet` (set algebra, iteration
  over ranges and addresses), `RefType`, `CommentKind`, `Provenance`,
  `Opcode` as `enum.Enum`s.
- **Collections** are lazy views: `program.functions` supports
  iteration in address order, `len()`, `in`, `.at(a)`, `.containing(a)`,
  `.before(a)`, `.after(a)`, `.first`, `.last`, `.by_name(n)`,
  `.in_range(r)`, `.create(...)`, `.remove(f)`; the same pattern for
  instructions, data, symbols, references, blocks, types. Iterators fetch
  pages (256 items) with the GIL released for each fetch and resume from
  a key, so iterating a ten-million-instruction listing never builds a
  list, and a concurrent change does not break the iterator (it may or
  may not see the change; Ghidra's database iterators behave the same).
- **Bytes**: `program.memory.read(a, n) -> bytes`, `memory[a]`,
  `memory[a:b]`, `write(a, data)`, typed `read_u8 … read_u64`,
  `read_i8 … read_i64`, `read_f32`, `read_f64` in the program's byte
  order, and the matching `write_*`.
- **Errors** are exceptions. Domain errors derive from `BasiliskError`:
  `AddressError` (`NoSuchAddress`, `AddressOutOfBounds`),
  `MemoryAccessError`, `InvalidNameError`, `DuplicateNameError`,
  `CodeUnitConflictError`, `NoTransactionError`, `StaleObjectError`,
  `ReadOnlyError`, `DecompileError`, `LoaderError`, `ApiVersionError`;
  `basilisk.task.CancelledError` derives from `BasiliskError`. Python's
  own types are used where idiom expects them (`TypeError`, `ValueError`,
  `KeyError`, `IndexError`). Each Rust error type of the bound crates maps
  to exactly one class (binding constraints, item 4); the mapping is a
  table in `bk-plugin` with a test per row. Verified that a Rust error
  enum maps onto a Python hierarchy (*exp.* `NoSuchAddress` is a
  `BasiliskError`).
- **Provenance** is visible on every name, type and comment that has it
  (`symbol.provenance`, `variable.type_provenance`), and every write
  takes an optional `provenance=` that defaults to `Provenance.USER` in
  scripts and actions, `ANALYSIS` in analyzers and `MODEL` in proposers
  (ADR-025 item 3f).
- **Context**: `basilisk.ui.context()` returns the current program,
  location, address, selection, highlight and function — from the GUI,
  or what a headless run set. Scripts receive it as globals (4.3).
- **Read without a transaction, write within one** (4.9).

### 4.3 Scripts

A script is a `.py` file in a script directory: the user's
`basilisk_scripts` directory, each plugin's `scripts/`, and the bundled
ports. Header comments use Ghidra's tags, so a ported script keeps them:
`# @category A.B`, `# @menupath Tools.Do Thing`, `# @keybinding ctrl shift K`,
`# @toolbar icon.png`, `# @author`, plus `# @runtime basilisk` (Ghidra
reads `@runtime` to pick Jython or PyGhidra, `ScriptInfo.java:48`; a
script whose `@runtime` is `Jython` is offered with a note that it needs
porting).

**Globals.** A script runs as module `__main__` with these names bound:

| Pythonic | Ghidra name | Meaning |
|---|---|---|
| `program` | `currentProgram` | the current program (or `None`) |
| `location` | `currentLocation` | the current location (address plus field) |
| `address` | `currentAddress` | its address |
| `selection` | `currentSelection` | `AddressSet` or `None` |
| `highlight` | `currentHighlight` | `AddressSet` or `None` |
| `monitor` | `monitor` | the task monitor (4.8) |
| `flat` | `this`, `state` | the `FlatAPI` instance; `state` is its `GhidraState`-like object |
| — | every flat method | `toAddr`, `getFunctionAt`, `askString`, `println`, … (4.4) |

Assigning `currentAddress`, `currentSelection` or `currentHighlight` (or
the Pythonic names) moves the tool's cursor, selection or highlight when
the script ends, as Ghidra copies its fields back to the state
(`GhidraScript.java:546-558`). `print` writes to the script's output (the
Console, or standard output headless), as PyGhidra rebinds it
(`pyghidra/script.py:133-145`). A script may instead define
`def run(ctx):`; then the runner calls it with the same context and binds
no globals.

**Running.** From the Script Manager (a view listing scripts by
category, as Ghidra's), a key binding or menu path from the header, the
command palette, `runScript("name")` from another script,
`basilisk script <file> [args] --program <p>` headless, and
`basilisk analyze … --pre-script/--post-script` (Ghidra's headless
options). A script runs on a worker thread as a job with progress and
Cancel in the status bar (as Ghidra runs `RunScriptTask`), inside one
transaction (4.9), with `sys.argv` set to the script path and arguments,
the script's directory first on `sys.path`, and the modules it imported
removed from `sys.modules` afterwards so the next run sees edits (both as
`pyghidra/script.py:226-279`).

**`ask*`**: the resolution order is Ghidra's (`GhidraScript.java:1962-2000`):
the next script argument; else the key `title + " " + message` in
`<script>.properties` beside the script (or a directory named by
`--properties-path`); else the default; else, headless, `ValueError`
naming the key. In the GUI the dialog opens pre-filled with that value and
the last value given in this session; Cancel raises `CancelledError`.

**GUI calls headless**: as Ghidra (inv. 2.4): `popup` logs; `goTo`
returns `False`; selection and highlight setters update the context;
`setBackgroundColor`, `clearBackgroundColor`, `setToolStatusMessage`
raise `ImproperUseError`. Two deliberate differences: `show(addresses)`
and `createTableChooserDialog(...)` print their rows to the output
headless instead of raising, so scripts like
`DecompilerStackProblemsFinderScript` give their result in batch runs
(section 8).

**Headless continuation** (Ghidra's `HeadlessScript`,
`HeadlessScript.java:40-53,151-390`): `setHeadlessContinuationOption`,
`storeHeadlessValue`/`getStoredHeadlessValue` (shared by all scripts of a
`basilisk analyze` run), `enableHeadlessAnalysis`, `isHeadlessAnalysisEnabled`,
`isImporting`, `analysisTimeoutOccurred` exist on the flat layer when a
script runs under `basilisk analyze`; elsewhere they raise
`ImproperUseError` as Ghidra's do.
