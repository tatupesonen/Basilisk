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

**Crates.** `bk-plugin` (new, the only crate that depends on PyO3; the
C dependency on CPython is the one ADR-014 allows). PyO3 0.30.1's macros
emit no `unsafe` into the user's crate — verified by building the
experiment under `#![forbid(unsafe_code)]` (*exp.* README) — so
`bk-plugin` keeps the workspace's `unsafe_code = "forbid"` and needs no
`unsafe-crates.txt` entry; the FFI's `unsafe` stays inside `pyo3` and
`pyo3-ffi`, a widely used crate that encapsulates it, as ADR-020
prefers. Miri cannot run CPython; the Python test suite also runs in a
nightly AddressSanitizer build (section 6). A pure-Python tree
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

### 4.4 The flat scripting layer

`basilisk.flat.FlatAPI` is Ghidra's `FlatProgramAPI` and `GhidraScript`
under their own names, written in Python over the object model (4.2). It
exists so that scripts port with small changes; new code should use the
object model. Rules:

1. **Same names, same arguments, same results** where basilisk has the
   concept. Ghidra's overloads become one Python function with optional
   or typed arguments (Python has no overloading); each overload in
   Ghidra is a row of the drift test (section 6.3).
2. Results are basilisk objects, which in a flat-layer script also answer
   Ghidra's bean-style names (4.4.2), so `getFunctionAt(a).getName()`
   works as well as `.name`.
3. Java exceptions become their basilisk classes: `CancelledException` →
   `CancelledError`, `MemoryAccessException` → `MemoryAccessError`,
   `InvalidInputException` → `InvalidNameError`,
   `DuplicateNameException` → `DuplicateNameError`,
   `CodeUnitInsertionException` → `CodeUnitConflictError`,
   `AddressOutOfBoundsException` → `AddressOutOfBounds`,
   `ImproperUseException` → `ImproperUseError`; methods Ghidra declares as
   returning `null` return `None`, and `boolean`-returning methods return
   `bool`.
4. A method whose backing feature does not exist yet raises
   `UnsupportedError` naming the feature and milestone ("needs projects,
   M8"); this is behaviour, listed below and checked by the table test,
   not a stub. A method with no basilisk meaning is absent, and the table
   says why.

Status column: **same** — same behaviour; **same\*** — same, with the
note; **later (Mx)** — raises `UnsupportedError` until milestone Mx;
**none** — not provided, with the reason. "Pythonic" names the object-model
equivalent new code should use.

#### 4.4.1 `FlatProgramAPI` (123 names, 166 overloads; inv. 2.1)

| Ghidra name (overloads) | Status | Pythonic equivalent / note |
|---|---|---|
| `getCurrentProgram`, `getMonitor` | same | `program`, `monitor` |
| `start`, `end(commit)` | same\* | open/close the script's transaction early; `end(False)` rolls back (4.9) |
| `getProgramFile` | same | `program.source_path` (`pathlib.Path`) |
| `getAddressFactory` | same\* | `program.address_spaces`; supports `getAddress(text)`, `getDefaultAddressSpace()`, `getAddressSpace(name)` |
| `toAddr` (3: int, long, String) | same | `program.addr(x)`; a negative int raises `ValueError` |
| `createAddressSet` | same | `basilisk.AddressSet()` |
| `analyze` (deprecated), `analyzeAll`, `analyzeChanges` | same\* | `program.analysis.run_all()`, `run_changes()`; in a script with `SUSPENDED`/`DISABLED` analysis mode they follow `GhidraScript`'s override (inv. 2.3) |
| `disassemble` | same | `program.listing.disassemble(a)` |
| `clearListing` (5) | same | `program.listing.clear(range_or_set, code=…, data=…, symbols=…, comments=…, properties=…, functions=…, registers=…, equates=…, user_refs=…, analysis_refs=…, import_refs=…, default_refs=…, bookmarks=…)`, defaults as Ghidra's overloads |
| `createMemoryBlock` (2: stream, bytes) | same | `program.memory.create_block(name, start, data, overlay=False)`; a file-like object or `bytes` |
| `getMemoryBlock` (2: name, address), `getMemoryBlocks`, `removeMemoryBlock` | same | `program.memory.block(x)`, `.blocks`, `.remove_block(b)` |
| `createLabel` (3), `createSymbol` (2, deprecated) | same | `program.symbols.create_label(a, name, namespace=None, primary=…, provenance=…)`; Ghidra's default source in scripts is `USER_DEFINED` → `Provenance.USER` |
| `removeSymbol` | same | `program.symbols.remove(symbol)` |
| `addEntryPoint`, `removeEntryPoint` | same | `program.symbols.add_entry_point(a)`, `remove_entry_point(a)` |
| `setPlateComment`, `setPreComment`, `setPostComment`, `setEOLComment`, `setRepeatableComment` | same | `program.comments.set(a, CommentKind.X, text)` |
| `getPlateComment`, `getPreComment`, `getPostComment`, `getEOLComment`, `getRepeatableComment` | same | `program.comments.get(a, CommentKind.X)` |
| `find` (3: byte, bytes, text) | same | `program.memory.find(pattern, start)`; text: `program.listing.find_text(text)` (Ghidra searches comments, labels, mnemonics and operands in that order) |
| `findBytes` (5, one deprecated) | same\* | `program.memory.find_pattern(regex, start_or_set, limit=1, alignment=1, forward=True)`; Ghidra matches a Java regular expression against the bytes read as ISO-8859-1 characters; basilisk translates the pattern to `regex::bytes` syntax, and the patterns Java and Rust read differently are listed in the implementation's tests |
| `findStrings`, `findPascalStrings` | same | `program.memory.find_strings(set, min_length, alignment, require_null_end, all_char_widths)`, `find_pascal_strings(…)` |
| `createFunction`, `removeFunction`, `removeFunctionAt` | same | `program.functions.create(entry, name=None)`, `.remove(f)` |
| `getFunctionAt`, `getFunctionContaining`, `getFunctionBefore` (2), `getFunctionAfter` (2), `getFirstFunction`, `getLastFunction` | same | `program.functions.at/containing/before/after(x)`, `.first`, `.last` |
| `getFunction` (deprecated), `getGlobalFunctions` | same | `program.functions.by_name(name)` (global namespace) |
| `getFirstInstruction` (2), `getLastInstruction`, `getInstructionAt`, `getInstructionContaining`, `getInstructionBefore` (2), `getInstructionAfter` (2) | same | `program.listing.instructions.first/last/at/containing/before/after(x)`; `getFirstInstruction(function)` → `function.instructions.first` |
| `getFirstData`, `getLastData`, `getDataAt`, `getDataContaining`, `getDataBefore` (2), `getDataAfter` (2) | same | `program.listing.data.…` (defined data) |
| `getUndefinedDataAt`, `getUndefinedDataBefore`, `getUndefinedDataAfter` | same | `program.listing.undefined.at/before/after(a)` |
| `getSymbolAt` (3, one deprecated), `getSymbolBefore` (2), `getSymbolAfter` (2) | same | `program.symbols.at(a, name=None, namespace=None)`, `.before(x)`, `.after(x)` |
| `getSymbol` (deprecated), `getSymbols` | same | `program.symbols.by_name(name, namespace)` |
| `getNamespace`, `createNamespace`, `createClass` | same | `program.symbols.namespace(parent, name)`, `.create_namespace(…)`, `.create_class(…)` |
| `createFragment` (4, two deprecated), `getFragment` | later (M7) | program-tree modules and fragments arrive with the Program Trees editing view |
| `getDataTypes` | same | `program.types.find(name)` (all categories) |
| `createData` | same | `program.listing.create_data(a, dtype)` |
| `createByte`, `createWord`, `createDWord`, `createDwords`, `createQWord`, `createFloat`, `createDouble`, `createChar`, `createAsciiString` (2), `createUnicodeString` | same | `program.listing.create_data(a, basilisk.types.byte)` etc.; string forms as Ghidra (terminated or given length) |
| `removeData`, `removeDataAt`, `removeInstruction`, `removeInstructionAt` | same | `program.listing.clear(…)` on the unit |
| `addInstructionXref` | same | `program.references.add_memory(from_, to, ref_type, op_index, provenance=USER)` |
| `getReferencesFrom`, `getReferencesTo` | same\* | `program.references.from_address(a)`, `.to(a)`; `getReferencesTo` stops at 4,096 as Ghidra's does (`FlatProgramAPI.java:76,2156-2166`); the Pythonic form is unbounded and lazy |
| `getReference` (2: instruction, data) | same | `insn.reference_to(a)`, `data.reference_to(a)` |
| `createMemoryReference` (2), `createExternalReference` (3), `createStackReference` | same | `program.references.add_memory/add_external/add_stack(…)` |
| `removeReference`, `setReferencePrimary` (2) | same | `program.references.remove(r)`, `.set_primary(r, True)` |
| `createEquate` (2), `getEquate` (2), `getEquates`, `removeEquate` (2), `removeEquates` | same | `program.equates.create/get/at/remove(…)` |
| `createBookmark`, `getBookmarks`, `removeBookmark` | same | `program.bookmarks.create(a, category, note)`, `.at(a)`, `.remove(b)` |
| `openDataTypeArchive` (deprecated), `openFileDataTypeArchive` | same\* | `basilisk.types.open_archive(path, read_only)`: basilisk's own archive format; a Ghidra `.gdt` is a packed database basilisk does not read (ADR-003) and raises `UnsupportedError` naming that |
| `saveProgram` (2: program; program and project path) | same\* / later (M8) | `program.save()`; the form with a project folder path needs projects (M8) |
| `getProjectRootFolder` | later (M8) | projects |
| `getByte`, `getShort`, `getInt`, `getLong`, `getFloat`, `getDouble`, `getBytes` | same\* | `program.memory.read_i8/i16/i32/i64/f32/f64(a)`, `read(a, n)`; signed like Java's types; `getBytes` returns `bytes` (Python has no signed byte arrays; `b[i]` is 0–255 where Java gave −128–127 — the one change a port may need) |
| `setByte`, `setShort`, `setInt`, `setLong`, `setFloat`, `setDouble`, `setBytes` | same | `program.memory.write_*(a, v)`, `write(a, data)` |

#### 4.4.2 `GhidraScript` (102 names, 128 overloads; inv. 2.1)

| Ghidra name (overloads) | Status | Pythonic equivalent / note |
|---|---|---|
| `analyzeAll`, `analyzeChanges` | same | see 4.4.1 |
| `setAnalysisOption`, `setAnalysisOptions`, `resetAnalysisOption`, `resetAnalysisOptions`, `resetAllAnalysisOptions`, `getAnalysisOptionDefaultValue`, `getAnalysisOptionDefaultValues`, `getAnalysisOptionDescription`, `getAnalysisOptionDescriptions`, `getCurrentAnalysisOptionsAndValues`, `isAnalysisOptionDefaultValue` | same | `program.analysis.options`: a mapping from `"Analyzer Name.Option Name"` (Ghidra's key form, `GhidraScript.java:1412-1460`) to values as strings, with defaults and descriptions; an unknown key or a value that does not parse raises `KeyError`/`ValueError` (Ghidra: `testSetInvalidAnalysisOptionsAndValues`) |
| `getProjectRootFolder` | later (M8) | projects |
| `askString` (2), `askInt`, `askLong`, `askDouble`, `askYesNo`, `askAddress` (2), `askBytes`, `askChoice`, `askChoices` (2), `askFile`, `askDirectory`, `askValues`, `askPassword`, `askLanguage` | same | `basilisk.ui.ask_string(…)` etc.; resolution order and headless rules of 4.3; `askPassword` never reads script arguments or properties and raises `ImproperUseError` headless (`GhidraScript.java:3218-3222`) |
| `askProgram` (2) | same\* | chooses among open programs, or a file to open; the project form needs M8 |
| `askDomainFile`, `askProjectFolder` | later (M8) | projects |
| `parseAddress`, `parseBoolean`, `parseBytes`, `parseChoice`, `parseChoices` (2), `parseDirectory`, `parseDouble`, `parseInt`, `parseLong`, `parseLanguageCompileSpecPair` | same | the string conversions the `ask*` methods use for script arguments and properties |
| `parseDomainFile`, `parseProjectFolder` | later (M8) | projects |
| `print` (2), `println` (3), `printf`, `printerr` | same\* | the colour argument colours Console output and is ignored headless; `printf` takes Java format strings, translated for the subset `%s %d %x %08x %c %f %n %%` (the conversions bundled scripts use) and raising `ValueError` on others |
| `popup` | same | `basilisk.ui.notify(message)`; logs headless |
| `goTo` (3: address, symbol, function) | same | `basilisk.ui.go_to(x)`; `False` headless |
| `createSelection`, `setCurrentSelection`, `removeSelection` | same | `basilisk.ui.select(set)` |
| `createHighlight`, `setCurrentHighlight`, `removeHighlight` | same | `basilisk.ui.highlight(set)` |
| `setCurrentLocation` | same | `basilisk.ui.go_to(a)` without history entry |
| `setBackgroundColor` (2), `clearBackgroundColor` (2) | same | `basilisk.ui.color(set, rgb)`; `ImproperUseError` headless (Ghidra's rule) |
| `setToolStatusMessage` | same | `basilisk.ui.status(msg)`; `ImproperUseError` headless |
| `show` (2) | same\* | `basilisk.ui.show_addresses(title, addresses)`: a results view; headless prints the addresses (Ghidra raises) |
| `createTableChooserDialog` (2) | same\* | `basilisk.ui.table(title, columns, rows, executor=None)`: a declarative table view (4.7.6); headless prints the rows (Ghidra raises) |
| `getCodeUnitFormat` | same\* | `program.listing.format(unit)` gives the listing text of a unit as basilisk shows it |
| `getPlateCommentAsRendered`, `getPreCommentAsRendered`, `getPostCommentAsRendered`, `getEOLCommentAsRendered`, `getRepeatableCommentAsRendered` | same | `program.comments.rendered(a, kind)`: annotations expanded |
| `getState` | same\* | a `GhidraState`-like object: current program, location, selection, highlight, `getEnvironmentVar`/`addEnvironmentVar`/`removeEnvironmentVar`/`getEnvironmentNames`; `getTool()` and `getProject()` return `None` |
| `getControls` | same\* | writer, error writer and monitor |
| `runScript` (4), `runScriptPreserveMyState` | same | runs another basilisk script with the same (or a copied) state, its transaction nested in the caller's (4.9) |
| `runCommand` (2: command, background command) | same\* | runs a `basilisk.ghidra` command object (`applyTo(program, monitor)`); basilisk provides the commands bundled scripts use, by frequency in tier A/B: `DisassembleCommand` (18 uses), `CreateFunctionCmd` (12), `ClearFlowAndRepairCmd` (7), `DemanglerCmd` (6), `SetFlowOverrideCmd` (4), `DecompilerSwitchAnalysisCmd`, `CreateDataCmd`, `CompoundCmd`, `BookmarkEditCmd`, `AddLabelCmd` (3 each), `RenameLabelCmd` (2) |
| `getScriptName`, `getSourceFile`, `setSourceFile`, `getCategory` | same | from the file and its header |
| `getScriptArgs`, `setScriptArgs` | same | `sys.argv[1:]` as well |
| `setPropertiesFile`, `setPropertiesFileLocation`, `setPotentialPropertiesFileLocations` | same | where `.properties` values come from |
| `setReusePreviousChoices`, `getReusePreviousChoices` | same | whether `ask*` dialogs pre-fill with this session's last answer |
| `getScriptAnalysisMode` | same | a script sets `ANALYSIS_MODE = "suspended"` (or `"disabled"`) at module level, or overrides the method in a class-based script; the analysis manager must support both modes (binding constraints, item 9) |
| `isRunningHeadless` | same | |
| `cleanup` | same | a module-level `def cleanup(success):` is called last |
| `getLanguage`, `getDefaultLanguage` | same | `basilisk.lang.language(id)`, `.default_language(processor)` |
| `importFile`, `importFileAsBinary`, `createProgram` (3), `openProgram`, `closeProgram` | same | `basilisk.import_file(path, …)`, `basilisk.create_program(name, language, compiler)`, `basilisk.ui.open(program)`, `.close(program)` |
| `getDemangled` (deprecated) | later (M6) | `basilisk.demangle(name)` with the demanglers |
| `getUserName` | same | the operating-system user |
| `getGhidraVersion` | same\* | returns basilisk's version string; scripts that compare it with Ghidra version numbers must be changed |
| `toHexString` (4: byte, short, int, long) | same | Java's two's-complement width for the type named by a keyword (`toHexString(v, zeropad, header, width=8)`) |
| `setServerCredentials`, `setAnonymousServerCredentials` | later (M8) | the multi-user server |
| `execute` (2), `set` (3) | none | the runner's own entry points; "not intended to be called by script writers" (`GhidraScript.java:278-284`) |
| `toString` | none | Python's `str()` |

The two tables name all 225 public method names of the two classes
(`FlatProgramAPI` 123, `GhidraScript` 102, three overriding), from the
lists made by inv. command 6.

#### 4.4.3 Ghidra names on objects and in imports

Ported scripts call Ghidra's getters on what the flat methods return
(`func.getEntryPoint()`, `currentProgram.getListing().getInstructions(True)`)
and import Ghidra's enums (`from ghidra.program.model.symbol import
SourceType`). Measured over the 179 tier A and B scripts: 4,759 method
calls on receivers under 665 distinct names; the 200 most used names
cover 83 % of the calls and the 400 most used 92 % (the list includes
Java library names such as `hasNext`, `toString`, `add`) [command in 4.5].
They import from 86 `ghidra.*` packages (849 import lines), dominated by
`ghidra.app.script`, `ghidra.program.model.{address,listing,symbol,mem,data,lang}`
and `ghidra.util.{exception,task}`.

1. **Bean names.** Every basilisk object answers `getX()` and `isX()`
   for its property `x` and `setX(v)` for a writable one, by one generic
   rule in the binding's base class, plus an alias table for names that
   differ (`getEntryPoint` → `entry`, `getFunctionManager` → `functions`,
   `getSymbolTable` → `symbols`, `getReferenceManager` → `references`,
   `getMinAddress` → `min_address`, `getMnemonicString` → `mnemonic`,
   `getSymbolIterator(forward)` → `symbols.in_order(forward)`, …). The
   alias table is generated from the census — every program-model method
   name the 179 scripts call — and each entry has a test. Iterators also
   answer `hasNext()`/`next()`. These names are available in every
   script; they are not part of the documented object model, and the API
   drift test (6.3) lists them separately.
2. **Imports.** `basilisk.ghidra` exports Ghidra's commonly imported
   names under their Ghidra spelling: `SourceType` (= `Provenance`, with
   `USER_DEFINED`, `IMPORTED`, `ANALYSIS`, `AI`, `DEFAULT`), `RefType`,
   `FlowType`, `CommentType` and `CodeUnit`'s comment constants,
   `OperandType`, `BookmarkType`, the built-in data types
   (`ByteDataType`, `StringDataType`, …), `AddressSet`,
   `CancelledException`, `MemoryAccessException`, and the command classes
   of 4.4.2. A port changes `from ghidra.x.y import Z` to
   `from basilisk.ghidra import Z` — a mechanical edit. basilisk does not
   install a fake top-level `ghidra` package, so it never collides with
   PyGhidra in the same environment.

### 4.5 How much ports, and ten scripts

**Estimate.** From the census (inv. 3; tool and output in
`docs/agents/spec-plugin-experiments/script-census/`): of Ghidra's 335
bundled scripts,

- **94 (28 %), tier A**, use only the flat layer, the core program model
  and `ask*`/`print*`. They port mechanically once tracks P1–P3 are done
  and the program model (M4) exists: Python syntax, imports from
  `basilisk.ghidra`, the bean names of 4.4.3.
- **85 (25 %), tier B**, also use data types, the decompiler, p-code,
  languages, analysis options, commands, the assembler or the flat GUI
  calls. They port as mechanically once the corresponding bindings (P4,
  P5) and features (M5 analysis, M3 decompiler, M6 assembler) exist.
- **156 (47 %), tier C**, need something basilisk does not offer to
  plugins at M9: a Swing tool or tool service (70), projects and
  repositories (62), a feature module such as BSim, Function ID, Version
  Tracking, PDB or the debugger (56), a binary-format parser package
  (19), the emulator (7) or a third-party Java library (22) (flags
  overlap). They are ported, if at all, with their modules.

So **53 % of the bundled scripts (179) port with mechanical changes**
once the bindings and the features they use exist, 28 % as soon as the
program model is bound. How the estimate was made: regular expressions
over each script's text (inv. 3; they over-count tier C), and the ten
scripts below read in full, which agree with their tiers. For Java
scripts "mechanical" means a statement-by-statement translation to Python
that keeps every flat and bean name; for Jython scripts it means Python 3
syntax (`print x` → `print(x)`), `basilisk.ghidra` imports, and nothing
else in the ten read here.

Command for the 4.4.3 counts (from `../ghidra`; `ab.lst` is the tier A
and B rows of `census.tsv`): a Perl pass over those files counting
`\.\s*([a-z]\w*)\s*\(` (receiver calls) and bare calls of the 225 flat
names, comments stripped.

**The ten acceptance scripts** (chosen to cover both tiers, both Java and
Jython, every major flat-API group, and four of the five tier A or B
scripts that have their own Ghidra test):

| # | Script (module, lines, tier) | What it exercises | What the port needs | Ghidra test |
|---|---|---|---|---|
| 1 | `CountSymbolsScript.java` (Base, 43, A) | `state.getCurrentProgram()`, `getSymbolTable().getSymbolIterator(true)` (address order, no externals or dynamic labels, `SymbolTable.java:569-579`), `monitor.setMessage/isCancelled`, `println` | Python syntax; bean names `getSymbolTable`, `getSymbolIterator`, `getName` | — |
| 2 | `DeleteFunctionDefaultPlatesScript.java` (Base, 54, A) | `currentSelection`, `getFunctionManager().getFunctions(set, true)`, `getCommentAsArray`, `setComment(None)` | Python syntax; bean names | `DeleteFunctionDefaultPlatesScriptTest` (2) |
| 3 | `FindAndReplaceCommentScript.java` (Base, 61, A) | two `askString`, `listing.getCommentAddressIterator(memory, true)`, every `CommentType`, `setComment`, `printf` | Python syntax; `CommentType` from `basilisk.ghidra`; `str.replace` for Apache Commons `Strings.CS.replace` | `FindAndReplaceCommentScriptTest` (9) |
| 4 | `PrintFunctionCallTreesScript.java` (Base, 71, A) | `currentAddress`, `getFunctionContaining`, `getCallingFunctions(monitor)`, `getCalledFunctions(monitor)`, sorting by entry | Python syntax; `sorted(key=…)` | — |
| 5 | `ComputeCyclomaticComplexity.java` (Base, 41, A) | `currentAddress`, `printerr`, Ghidra's `CyclomaticComplexity` utility | Python syntax; `function.cyclomatic_complexity(monitor)` must exist in the model (it is a utility class in Ghidra, `ghidra.program.util`) | — |
| 6 | `AutoRenameLabelsScript.java` (Base, 69, B) | `currentSelection`, `askString`, primary symbols with `SourceType.DEFAULT`, `CompoundCmd` of `RenameLabelCmd`, `setToolStatusMessage` | Python syntax; commands from `basilisk.ghidra` | `AutoRenameLabelsScriptTest` (2) |
| 7 | `EditBytesScript.java` (Base, 120, B) | `askBytes`, `currentLocation.getByteAddress()`, code units over a set, `getDataAt`, `getInstructionContaining`, `clearListing`, `setBytes`, `createData`, `DisassembleCommand`, `popup` | Python syntax; `DisassembleCommand` | `EditBytesScriptTest` (17) |
| 8 | `mark_in_out.py` (Base, 115, Jython A) | Jython bean properties (`instruction.address`, `currentProgram.referenceManager`, `.mnemonicString`, `.fallFrom`), `OperandType` and `RefType` imports, `getOpObjects`, `addMemoryReference` into an overlay space, `print` statements | `print(...)`; `basilisk.ghidra` imports; overlay address text `IOMEM::0x10` | — |
| 9 | `RecursiveStringFinder.py` (Base, 163, Jython A) | flat calls from Python classes, `getReferences`, `StringDataType` `isinstance`, `exceptions.Exception`, `print` statements | `print(...)`; `Exception` for `exceptions.Exception`; `isinstance(dt, StringDataType)` from `basilisk.ghidra` | — |
| 10 | `FixSwitchStatementsWithDecompiler.java` (Decompiler, 104, B) | instructions with computed jumps, `ParallelDecompiler` with a callback, `DecompilerSwitchAnalysisCmd`, `BookmarkEditCmd` | Python syntax; `program.decompiler.decompile_many(functions, callback)` (4.7.7) and the two commands | — |

`EditBytesScriptTest` and `PasteCopiedListingBytesScriptTest` drive the
GUI; their checks on program state are ported headless, their dialog
steps as `egui_kittest` flows (ADR-006). `ExportFunctionInfoScript`
(tier C: it writes JSON through Gson) and `FixOffcutInstructionScript`
(tier B) also have Ghidra tests and are ported in track P6.

**How Ghidra's side is obtained** (ADR-007, full Ghidra,
`GHIDRA_INSTALL_DIR`): each acceptance input is a *fixture program* —
a small JSON description (language id, memory blocks with bytes, and the
functions, symbols, comments and references the script needs, built
with Ghidra's `ToyProgramBuilder`/`ProgramBuilder` conventions where a
Ghidra test exists). A reference tool `tools/reference/ghidra_scripts/RunOnFixture.java`
builds the program from the JSON inside `analyzeHeadless`
(`-preScript`), runs the original script (`-postScript`, with
`-propertiesPath` for `ask*` answers and the location given as script
arguments), and writes the script's output and a canonical dump of the
program state (symbols, comments, references, bookmarks, code units,
bytes of touched ranges) as text. `bk-testkit` builds the same program
from the same JSON, runs the port, and writes the same dump. Outputs and
dumps from Ghidra are checked in as goldens, so CI does not need Ghidra.
Script 10's input is a fixture whose switch the reference decompiler
resolves; it is accepted only once the jump-table track (D13) is.

### 4.6 Plugin packages

**What a plugin is.** A Python package that tells basilisk what it
provides. It is found either as an installed distribution with an entry
point in the group `basilisk.plugins`
(`[project.entry-points."basilisk.plugins"] myplugin = "myplugin"` in its
`pyproject.toml`), or as a directory `<settings>/plugins/<name>/` holding
`plugin.toml` and the package. Its entry module declares:

```python
import basilisk
from basilisk.plugin import PluginInfo, action, analyzer

PLUGIN = PluginInfo(
    name="thunk-tools",            # identifier: [a-z0-9][a-z0-9_-]*, unique
    version="1.2.0",               # PEP 440
    api=">=1.0,<2",                # PEP 440 specifier on basilisk.API_VERSION (4.10)
    description="Names and comments thunks",
    author="…",
    requires=["string-tools>=0.3"],  # other plugins, optional
)

@action(id="rename-thunks", name="Rename Thunks", menu="Tools/Thunk Tools")
def rename_thunks(ctx): ...

def register(r):                   # optional; without it every decorated
    r.add(rename_thunks)           # object in the module is registered
```

`plugin.toml` repeats `name`, `version`, `api`, `description`, `author`,
`requires` and adds `entry = "package.module"`, so a directory plugin's
API range is checked before any of its code runs; for an entry-point
plugin the check uses `PLUGIN` right after import.

**Discovery**, in this order (the first plugin of a name wins; a later
one is listed as shadowed): plugins bundled in the package (the script
ports, examples); entry points of the running environment
(`importlib.metadata.entry_points(group="basilisk.plugins")`); the user's
plugin directory; directories named in the setting `plugins.paths`.
Script directories (4.3) are scanned separately; scripts are not plugins.

**Enabling.** A plugin installed with `basilisk plugin install <wheel,
zip, directory or package name>` is enabled. A plugin that discovery
finds for the first time is listed as *new* and disabled until the user
enables it in the Plugins window or with `basilisk plugin enable` —
plugins are trusted code with the user's privileges (ADR-014), so code
that appeared in an environment by other means does not run unasked.
Headless runs load the enabled set, or exactly `--plugin <name>…`.
State is kept in the settings (`plugins.enabled`, `plugins.disabled`).

**Load order**: topological by `requires`, ties by name. A plugin whose
API range excludes the running API, whose requirement is missing,
disabled or failed, or whose import raises is not loaded; the Plugins
window and `basilisk plugin list` show the reason and the traceback.

**Registration** is recorded per plugin: every script, analyzer, loader,
exporter, action, view and proposer carries its plugin's name, so errors
are attributed and everything can be removed again.

**Error isolation.** A plugin must not take basilisk down.
- Import or `register` raises: everything that plugin registered so far
  is removed; the plugin is marked failed.
- A callback raises (any exception, including `SystemExit`): caught at
  the boundary, logged to the Console and the log with the plugin name
  and traceback; the operation it served fails and the rest carries on —
  an analyzer's task fails with the error in the analysis log and
  analysis continues; a loader's probe counts as "no load spec"; an
  action shows a notification; a view shows the error in place of its
  content; a proposer yields nothing. Three consecutive failures of the
  same callback in one session disable that registration for the session,
  with a notification (setting `plugins.failure_limit`).
- `KeyboardInterrupt` in a plugin job cancels that job only.
- What cannot be contained in process: a crash in native code a plugin
  loads (a C extension), `os._exit`, and Python code that never returns
  and never checks its monitor. For the last, Cancel first sets the
  monitor; if the code has not returned after two seconds basilisk
  raises `CancelledError` in that thread asynchronously
  (`PyThreadState_SetAsyncExc`; **unverified** that it is usable under
  abi3 — P1 checks, and without it Cancel only sets the monitor).

**Reloading** for development: `basilisk.plugin.reload("name")`, the
Plugins window's Reload, or `basilisk plugin reload`: remove every
registration of the plugin (actions leave the menus, its analyzers'
pending tasks are dropped, its views close), call its optional
`unregister()`, remove its modules (its package prefix) from
`sys.modules`, import and register again. Scripts need no reload: they
are read afresh at every run (4.3). With the setting `plugins.watch`,
a change to a file of an enabled directory plugin reloads it.

### 4.7 Plugin kinds

#### 4.7.1 Scripts
4.3. A plugin can also register a function as a script:
`r.script(fn, name=…, category=…, menupath=…, keybinding=…)`; it then runs
as a script does (job, transaction, monitor, error isolation) with
`fn(ctx)`.

#### 4.7.2 Analyzers
Ghidra's contract (inv. 4), in Python:

```python
from basilisk.analysis import Analyzer, AnalyzerKind, Priority, Option

class StringXrefs(Analyzer):
    name = "String Xrefs"            # no "." (the options key; AnalysisScheduler.java:42-47)
    description = "Labels references to strings"
    kind = AnalyzerKind.DATA         # BYTES, INSTRUCTIONS, FUNCTIONS, FUNCTION_MODIFIERS,
                                     # FUNCTION_SIGNATURES, DATA (AnalyzerType.java:47-52)
    priority = Priority.DATA.after() # FORMAT 100 … DATA_TYPE_PROPAGATION 900, HIGHEST, LOW;
                                     # before()/after() shift by one (AnalysisPriority.java)
    default_enabled = True
    one_shot = True                  # offered under Analysis → One Shot
    prototype = False
    options = [Option("Minimum length", 4, "Shortest string to label")]

    def can_analyze(self, program) -> bool: ...
    def added(self, program, addresses, monitor, log) -> bool: ...
    def removed(self, program, addresses, monitor, log) -> bool: ...   # optional
    def options_changed(self, options, program) -> None: ...           # optional
    def analysis_ended(self, program) -> None: ...                     # optional
```

- One instance per program, created when the analysis manager is
  created for it, kept if `can_analyze` is true (as
  `AutoAnalysisManager.java:169-172`).
- The manager accumulates added and removed address sets for it from
  change events of its kind while it is enabled, and queues one task at
  its priority (as `AnalysisScheduler`). `added` runs on an analysis
  worker thread inside the analysis transaction; writes default to
  `Provenance.ANALYSIS`.
- **Python analyzers are exclusive tasks**: the manager runs one at a
  time, never while a Rust analyzer writes to the same program, and
  holds no lock while it calls in (4.8). In Ghidra all analyzers run one
  at a time, so this costs nothing against Ghidra [J].
- Options appear in the Analysis Options dialog under the analyzer's
  name and in `program.analysis.options` (4.4.2); a `.pspec` override of
  default enablement applies as in Ghidra.
- `basilisk analyze` and Analysis → Auto Analyze run enabled Python
  analyzers with the built-in ones in one priority order.

#### 4.7.3 Loaders
Ghidra's contract (inv. 5), the `AbstractProgramWrapperLoader` shape:

```python
from basilisk.loaders import Loader, LoaderTier, LoadSpec

class MyFormat(Loader):
    name = "My Format"
    tier = LoaderTier.SPECIALIZED_TARGET
    tier_priority = 50
    extensions = (".myf",)

    def find_load_specs(self, provider) -> list[LoadSpec]:
        if provider.read(0, 4) != b"MYF\0":
            return []
        pairs = basilisk.lang.query_opinions(self.name, primary="7", secondary=None)
        return [LoadSpec(image_base=0x10000, language=p) for p in pairs]

    def default_options(self, provider, spec) -> list: ...      # optional
    def validate_options(self, provider, spec, options): ...    # optional; message or None
    def load(self, provider, spec, options, program, monitor, log) -> None:
        ...   # fill the program basilisk created for the spec
```

`find_load_specs` gets a read-only byte provider (`read(offset, n)`,
`len()`), is called for every imported file, and must be cheap; Python
loaders are ranked with the built-in ones by tier, tier priority and
name (`Loader.java:293-298`). `basilisk.lang.query_opinions` is
`bk-lang`'s `.opinion` query (`QueryOpinionService` is already ported).
Loading into an existing program and multi-program results (Ghidra's
`loadInto`, `LoadResults`) come later.

#### 4.7.4 Exporters
```python
from basilisk.exporters import Exporter

class MyExport(Exporter):
    name = "My Format"
    extension = "myf"
    supports_address_restriction = True
    def options(self) -> list: ...                            # optional
    def export(self, program, path, addresses, options, monitor) -> None: ...
```
Offered in File → Export and `basilisk export --format "My Format"`
(inv. 6).

#### 4.7.5 UI actions
Registered into `bk-ui`'s action registry, so menus, popup menus, the
palette, key bindings and the Key Bindings options all list them:

```python
@action(id="rename-thunks", name="Rename Thunks",
        description="Rename every thunk after its target",
        menu="Tools/Thunk Tools", popup=("listing", "decompiler"),
        keybinding="ctrl shift T", scope="program", requires=("function",))
def rename_thunks(ctx): ...
```

- Ids are namespaced `<plugin>.<id>` and are what the key map stores.
- Menus are Ghidra's top-level menus (File … Help) and paths below them.
- A default key binding that clashes with a built-in one is dropped with
  a warning; the user can still bind it.
- Enablement is declarative — a `scope` (`global`, `program`,
  `code-view`, `decompiler`) and `requires` facts the shell knows
  (`function`, `selection`, `address`) — because the shell evaluates it
  every frame on the UI thread, which never calls Python (4.8).
- Invoking it runs `fn(ctx)` as a job on the plugin executor, inside a
  transaction named after the action, with a monitor shown in the status
  bar; never on the UI thread.

#### 4.7.6 UI views
Views are **declarative**: Python supplies data, `bk-ui` draws it.
egui redraws every frame on the UI thread; a Python callback per frame
would hold the GIL on that thread and tie the interface's frame rate to
plugin code, which ADR-012 ("the UI never blocks") forbids. Kinds:

- `TableView(columns, provider)`: typed columns (text, integer, address,
  function, …); `provider.count()` and `provider.rows(start, count)` are
  called on worker threads through the same paged client the built-in
  tables use (`ui-shell.md` 4.2); sorting and filtering by basilisk; an
  address column navigates. `createTableChooserDialog` is this view
  (4.4.2).
- `TextView(provider)`: lines of tokens with the token kinds and
  referents of the listing and decompiler (`bk-ui` `model::token`), so
  colouring, highlight-uses and navigation work as in built-in views.
- `TreeView(provider)`: lazily expanded nodes with text, icon and an
  optional location.
- `view.refresh()` from any thread asks for new data.

A view is registered with an id, a title and a Window menu entry, docks
and detaches like built-in views, and keeps its place in the saved
layout. **Built in when Python is active**: the Python console
(Ghidra's interpreter window: statements run on the plugin executor, each
top-level statement that changes the program runs in its own transaction
"Python Console", completion of names), the Script Manager (Ghidra's
layout: category tree, script table, run, edit, key binding), the
Plugins window, and the Proposals view (4.7.7).

#### 4.7.7 Decompiler hooks: proposers (ADR-025 item 6)
A language model never edits decompiled code. A plugin can **propose**
names, types and comments; basilisk validates and applies them with the
program's ordinary rename, retype and comment operations, records their
provenance and can remove them. Off by default.

```python
from basilisk.plugin import proposer, Proposal

@proposer(name="llm-names", kinds={"name", "type", "comment"})
def propose(result, monitor):          # result: DecompileResult, read-only
    hf = result.high_function
    yield Proposal.rename(hf.symbol("local_10"), "header_len",
                          confidence=0.8, rationale="compared with 0x14 before memcpy")
    yield Proposal.retype(hf.symbol("param_1"), "struct header *")
    yield Proposal.rename_function(result.function, "parse_header")
    yield Proposal.comment(result.function.entry, basilisk.CommentKind.PLATE, "Parses …")
```

1. **Switches.** `decompiler.proposers` = `off` (default) | `review` |
   `apply`, plus a per-proposer enable. Turning proposers on starts in
   `review`.
2. **When.** After the Decompiler view decompiles a function, on the
   action "Ask Proposers", or headless with `basilisk propose
   --proposer <name> [--function …]`. The proposer runs on the plugin
   executor with the finished, immutable result; decompilation never
   waits for it.
3. **Targets are program entities**, not per-decompilation ids: a
   function; a parameter or local by function and storage (and first use
   address for locals, as Ghidra identifies high symbols); a global
   symbol; an address and comment kind. `hf.symbol(name)` and the
   token's `high_symbol` give such targets.
4. **Validation** against the current program: the target exists, the
   name is legal and unique where required, the type parses with the
   program's types. Invalid proposals are dropped and listed with the
   reason.
5. **Never above its rank.** A proposal may replace a value whose
   provenance ranks no higher than `Provenance.MODEL` — `DEFAULT`,
   `ANALYSIS`, `MODEL` — and never `USER`, `IMPORTED`, `DEBUG_INFO` or
   `LIBRARY_SIGNATURE` (`bk-core` `Provenance::trust`; Ghidra ranks `AI`
   with `ANALYSIS`, `SourceType.java:28-54`).
6. **Review** keeps proposals pending in a per-program table (origin,
   target, value, confidence, rationale), shown in the Proposals view and
   as markers in the Decompiler; Accept or Reject one or many.
7. **Apply** writes accepted proposals (in `apply` mode: all valid ones)
   in one transaction "Proposals from <plugin>/<proposer> for <function>"
   with `Provenance.MODEL` and the origin `<plugin>/<proposer>`; one undo
   step. The decompiler shows the change at the next decompile, through
   the program trait like any other name or type.
8. **Removal**: "Remove Proposals from <origin>" for a function or the
   program restores, for each applied proposal, the value it replaced —
   only where the current value is still the proposal's (a later user
   edit stays) — in one transaction. This needs the program model to keep
   the origin and the replaced value of `MODEL` edits (binding
   constraints, item 11).

`program.decompiler.decompile(f, timeout=None, monitor=None)` and
`decompile_many(functions, callback=None, workers=None)` (Ghidra's
`ParallelDecompiler`: Rust workers decompile, the callback runs with the
GIL for each finished result, in function order) give plugins and
scripts the same results the proposers see: `c` (text), `lines` (tokens
with kinds, referents and addresses), `high_function` (symbols with
storage, type and provenance; p-code ops with sequence numbers and
varnodes; blocks), `summary` (ADR-025 3d) and `error`.

### 4.8 Threads, the GIL and long work

1. **Long native work releases the GIL.** Every binding call that can
   take more than about a millisecond — decompiling, analysis, import,
   export, search, saving, undo and redo, and each page fetch of an
   iterator — runs inside `py.detach`. Measured: two Python threads each
   running 300 ms of native work take 600 ms when the GIL is held and
   300 ms when it is released (*exp.*).
2. **Where Python runs**: on the thread that called into basilisk
   (library use); on the **plugin executor**, a small pool (two threads
   by default) for scripts, actions, view providers, proposers and the
   console; on analysis worker threads for Python analyzers. **The UI
   thread never attaches to the interpreter.** In a Python-hosted GUI
   `basilisk.main()` runs the event loop inside `py.detach`.
3. **Callbacks from parallel Rust code**: a registration holds its
   callable as `Py<PyAny>` (`Send + Sync`) in an `Arc`, and the Rust
   worker calls it inside `Python::attach`; results and exceptions come
   back as values. Measured: eight Rust threads calling one Python
   callable while the caller is detached: correct ordered results, eight
   distinct OS threads, 20–32 ms, and a Python exception in one callback
   reaches the caller as that exception (*exp.*). Calls serialise on the
   GIL; that is why Python analyzers are exclusive tasks (4.7.2).
4. **No deadlock between the GIL and program locks.** Rule for every
   binding and every Rust caller of Python: never attach while holding a
   program or storage lock; never block on such a lock while attached —
   detach first (`py.detach(|| program.write())`). The binding acquires
   storage locks only inside `detach`. A test runs a Python analyzer that
   writes while Rust analysis and a script read and write the same program
   (section 6).
5. **Cancellation and progress** use one monitor type shared by every
   crate (binding constraints, item 7): a cancel flag and progress
   counters behind an `Arc`, read without locks. `basilisk.task.Monitor`
   wraps it: `cancelled`, `check()` (raises `CancelledError`), `message`,
   `maximum`, `progress`, `increment(n=1)`, `indeterminate`; in the flat
   layer, Ghidra's `TaskMonitor` names (`isCancelled`, `checkCancelled`
   — and `checkCanceled`, which Ghidra removed from `TaskMonitor` but its
   own `ghidra_basics.py:75` still calls — `setMessage`, `initialize`,
   `setMaximum`, `setProgress`, `incrementProgress`, `setIndeterminate`,
   `setShowProgressValue`, `getMessage`, `getProgress`, `getMaximum`,
   `cancel`, `clearCancelled`; `TaskMonitor.java:55-209`). A script's
   monitor is passed into the long calls it makes, so Cancel stops the
   decompile it is waiting on. Measured: a cancel set from another
   Python thread stops Rust work running without the GIL within one 10 ms
   step, and the progress it wrote is visible from Python (*exp.*).
6. **Headless interrupt**: in `python -m basilisk script …`, SIGINT
   cancels the running job's monitor (Python only acts on SIGINT while
   Python code runs on the main thread).
7. **Free-threaded CPython**: open (4.1). Requirements fixed now: every
   pyclass `frozen` and `Sync`; no Rust code uses the GIL as its lock;
   nothing assumes callbacks are serialised except the documented
   exclusive-task rule, which would then be relaxed deliberately.

### 4.9 Transactions, undo and safety

**Ghidra** (inv. 2.3): a script is one transaction named after its class,
**committed even when `run` throws or is cancelled** (`end(true)` in a
`finally`, `GhidraScript.java:457-466`); the prompt that would ask whether
to keep the changes is never called. A nested transaction that ends
without commit aborts the whole outer transaction
(`Framework/Project/.../data/DomainObjectDBTransaction.java:151-163`).
Writing without a transaction is an error (`db/NoTransactionException.java`).
PyGhidra's `transaction()` context manager rolls back on an exception
(`pyghidra/api.py:256-275`).

**basilisk:**
1. Every change happens inside a transaction; a write without one raises
   `NoTransactionError`. Reads need none.
2. The runner opens one transaction around each script, action, console
   statement and proposal batch, named after it ("Script:
   FindAndReplaceCommentScript"); analyzers run inside the analysis
   transaction. One outermost transaction is one undo step with that
   name.
3. **Normal end commits. An exception — including `CancelledError`,
   `KeyboardInterrupt` and `SystemExit` with a non-zero code — rolls the
   transaction back**, and the error is reported. This departs from
   Ghidra's script behaviour on purpose (section 8): a failed script
   leaves no half-applied edits, as Python context managers and PyGhidra's
   `transaction()` behave. A script that wants Ghidra's behaviour sets
   `KEEP_CHANGES_ON_ERROR = True` at module level.
4. `with program.transaction(name):` and the flat `start()`/`end(commit)`
   give explicit control. Transactions nest: the outermost names the undo
   step; an inner one that ends by exception or `end(False)` marks the
   outermost aborted, as Ghidra does; further writes in it raise
   `TransactionAbortedError`, and it rolls back when it ends.
5. A transaction belongs to the thread that opened it; a write from
   another thread needs its own transaction and waits for the single
   writer (ADR-003: one writer, many readers).
6. `program.undo()`, `redo()` and `save()` raise while a transaction is
   open. Undo, redo and the UI's Edit → Undo act on the same per-program
   stack of outermost transactions.
7. Handles survive commit, rollback, undo and redo; an entity removed by
   any of them makes its handles stale (4.2).

**What plugins may not do** (each enforced by an error, not by
convention): write without a transaction; write from a proposer (it gets
a read-only program: `ReadOnlyError`) or from a loader's
`find_load_specs`; start analysis from inside an analyzer; touch a closed
program (`StaleObjectError`); run code on the UI thread (no API exists);
undo, redo or save inside a transaction. Plugins are trusted code with
the user's privileges (ADR-014); basilisk does not sandbox them, and says
so where plugins are installed and enabled.

### 4.10 Versioning and compatibility

- `basilisk.API_VERSION` is a `(major, minor)` pair separate from the
  application version. It is `(0, n)` while the M9 tracks build it —
  any `0.n` may break — and becomes `(1, 0)` when M9 is accepted.
- A plugin declares `api` as a PEP 440 specifier (`">=1.2,<2"`); without
  one it is not loaded. The host checks it before importing a directory
  plugin and right after importing an entry-point plugin.
- **Breaking** means: removing or renaming a documented module, class,
  function, method, property, parameter, keyword, enum member or
  exception class; making an optional parameter required; accepting
  fewer argument types; returning a type that is not compatible with the
  documented one; changing documented semantics (iteration order, address
  formatting, default provenance, transaction behaviour, which exception
  a failure raises — except to a subclass of the documented one).
  **Not breaking**: new names, new optional parameters, new enum members
  (enums are documented as open), new exception subclasses, `repr` text,
  performance, new Ghidra bean names (4.4.3).
- The flat layer and `basilisk.ghidra` are part of the versioned surface
  under Ghidra's names.
- **Deprecation**: a name to be removed is deprecated in a minor release
  (a `DeprecationWarning` when used, a note in its docstring, PEP 702
  `@deprecated` in the stubs), kept for at least two further minor
  releases, and removed only in the next major release.
- **Drift is tested** (6.3): a manifest of the whole surface, generated
  from the built module and checked in, plus `mypy.stubtest` comparing
  the shipped type stubs with the runtime.

## 5. Design

### 5.1 Crates and build

| Crate / tree | Kind | Contents | Depends on |
|---|---|---|---|
| `crates/bk-plugin` | rlib | PyO3 bindings of the library crates, the plugin host, the script runner's Rust side, the monitor and error mapping | `pyo3` (`abi3-py310`), the bound `bk-*` crates; never `bk-ui` |
| `crates/bk-plugin-ui` | rlib | Python-facing UI hooks: actions into the registry, declarative views, console, Script Manager, Plugins and Proposals views | `bk-plugin`, `bk-ui` |
| `crates/basilisk-py` | cdylib, module `basilisk._native` | the `#[pymodule]` assembling the two crates above and `basilisk::run` (the application entry) | `bk-plugin`, `bk-plugin-ui`, `basilisk` (lib target) |
| `python/basilisk/` | pure Python | `__init__.py` (re-exports `_native`), `flat.py`, `ghidra.py`, `plugin.py` (decorators, `PluginInfo`), `__main__.py`, `py.typed`, `*.pyi` stubs, `api-manifest.json` | — |
| `crates/basilisk` | bin + lib | adds a lib target exposing `run(args) -> ExitCode` so the extension runs the same application; adds `plugin.rs` (interpreter search, hand-over) | as today |

- The wheel is built with **maturin** (PyO3's standard build tool;
  ADR-011 evaluation to record: alternatives `setuptools-rust`, plain
  cargo plus a hand-written wheel; maturin is the industry standard) in a
  mixed Rust/Python layout: `pyproject.toml` at `python/`, module
  `basilisk._native`. Wheels: `cp310-abi3` for `macosx_11_0_arm64`,
  `macosx_10_12_x86_64`, `manylinux_2_28_x86_64`, `manylinux_2_28_aarch64`,
  `win_amd64`, `win_arm64`. A plain `cargo build` of the cdylib needs
  `build.rs` to call `pyo3_build_config::add_extension_module_link_args()`
  (*exp.*); maturin does this itself.
- `bk-plugin` is not in the default members of `cargo test` without a
  Python: its Rust tests that need an interpreter skip with a printed
  reason when `PYO3_PYTHON` cannot be found, as reference-tool tests do
  (ADR-007's rule). CI provides Python 3.10 and 3.14.
- Lints: the workspace set, including `unsafe_code = "forbid"` (section 3).

### 5.2 `bk-plugin` modules

`py/` — one module per bound area: `address`, `program`, `memory`,
`listing`, `symbols`, `references`, `functions`, `types`, `lang`, `pcode`,
`decompiler`, `analysis`, `loaders`, `exporters`, `task`, `errors` (the
error table), `iter` (the paged iterator), `compat` (bean rule, alias
tables). `host/` — `discover`, `metadata` (plugin.toml, `PluginInfo`,
API check), `registry` (registrations by plugin), `isolate` (boundary
calls, failure counting), `reload`, `executor` (the plugin thread pool).
`script/` — `header` (tags), `runner` (globals, `sys.argv`, `sys.path`,
module cleanup, transaction), `ask` (resolution order, properties
files). `embed` — `main()`, the GIL-released event loop, SIGINT.

### 5.3 Rust shapes (sketch)

```rust
/// A handle Python holds: shared program state plus a stable id.
#[pyclass(frozen, module = "basilisk.functions", name = "Function")]
pub struct PyFunction { program: ProgramHandle, id: FunctionId }

#[pymethods]
impl PyFunction {
    #[getter] fn name(&self, py: Python<'_>) -> PyResult<String> {
        py.detach(|| self.program.read(|p| p.functions().get(self.id).map(|f| f.name().to_owned())))
            .map_err(to_py)        // FunctionError::Stale -> StaleObjectError, …
    }
}

/// A Python analyzer as the analysis manager sees it.
pub struct PyAnalyzer { plugin: PluginId, obj: Arc<Py<PyAny>>, meta: AnalyzerMeta }
impl bk_analysis::Analyzer for PyAnalyzer {
    fn added(&self, cx: &mut AnalysisCx<'_>, set: &AddressSet, mon: &Monitor) -> Result<bool, AnalyzerError> {
        // the manager guarantees: no program lock held here (4.8 rule 4)
        Python::attach(|py| isolate::call(py, self.plugin, &self.obj, "added", (/* handles */)))
    }
}

pub struct Registry { by_plugin: BTreeMap<PluginId, Vec<Registration>> }
pub enum Registration { Script(..), Analyzer(..), Loader(..), Exporter(..), Action(..), View(..), Proposer(..) }
```

`ProgramHandle`, `FunctionId`, `AddressSet`, `Monitor`, `AnalysisCx` and
the error types are what the program, analysis and decompiler specs
define; `plugin-binding-constraints.md` lists what they must satisfy for
this to be written as shown.

### 5.4 Performance
- Iteration pages of 256 items, one GIL release per page; no Python
  object is created for items the caller does not reach.
- Budget (measured by P2, recorded in `PERF.md`): iterating 1,000,000
  instructions from Python reading address and mnemonic in at most 2 s
  on the development Mac; a call that does no work (a property read on a
  handle) under 1 µs plus the model's own cost; `decompile` from Python
  within 5 % of the same call from Rust.
- Python never sits on a hot path the user did not put it on: built-in
  analysis, decompilation and UI never call Python unless a plugin
  registered something there.

## 6. Tests

### 6.1 Ghidra tests (checklist ids; inv. 14)

| Checklist id (file) | Tests | Track | How |
|---|---:|---|---|
| `ghidra.app.script.GhidraScriptTest` (features-base) | 28 | P3, P2 | flat-layer behaviour on fixture programs: bookmarks, functions, data, the five comment kinds, typed memory reads, `toHexString`, analysis options set/reset/invalid, `askChoice(s)` defaults; `testCreateTableChooserDialog` in P6 |
| `ghidra.app.script.GhidraScriptAskMethodsTest` (features-base) | 16 | P1 | `ask*` resolution with arguments, properties files (including the alternate location) and defaults, headless and as dialogs (`egui_kittest`) |
| `ghidra.app.script.GhidraScriptRealProgramTest` (features-base) | 11 | P2 | `findBytes` (four forms), `find` text, next/previous symbol, equates, memory, external and stack references, `createData` |
| `ghidra.app.script.GhidraScriptUtilTest` (test-integrationtest) | 7 | P1 | script directories and lookup by name |
| `ghidra.app.plugin.core.script.GhidraScriptMgrPlugin1Test`, `…2Test`, `…3Test` (features-base) | 56 | P6 | the Script Manager view (`egui_kittest`); OSGi-bundle cases marked not applicable (no bundles) |
| `ghidra.app.plugin.core.script.JavaScriptInfoTest` (features-base), `ghidra.pyghidra.PythonScriptInfoTest` (features-pyghidra), `ghidra.jython.JythonScriptInfoTest` (extensions-jython) | 15 | P1 | header tags of `.py` scripts; Java-source specifics not applicable |
| `ghidra.app.plugin.core.script.BundleHostTest`, `BundleStatusManagerTest` (features-base) | 12 | — | not applicable: OSGi bundles (proposed mark) |
| `ghidra.jython.JythonScriptTest` (extensions-jython) | 2 | P1 | a Python script's globals and output |
| `ghidra.jython.JythonInterpreterTest`, `JythonCodeCompletionTest`, `JythonPluginTest` (extensions-jython), `ghidra.app.plugin.core.interpreter.InterpreterPanelTest` (features-base) | 16 | P6 | the Python console view |
| `AutoRenameLabelsScriptTest`, `DeleteFunctionDefaultPlatesScriptTest`, `EditBytesScriptTest`, `FindAndReplaceCommentScriptTest` (features-base) | 30 | P2 | with the ported scripts (4.5) |
| `ExportFunctionInfoScriptTest`, `FixOffcutInstructionScriptTest`, `PasteCopiedListingBytesScriptTest` (features-base), `WindowsResourceReferenceScriptTest` (test-integrationtest) | 11 | P7 | with those scripts' ports |
| `ghidra.app.plugin.core.AutoAnalysisWorkerTest`, `ghidra.app.plugin.core.analysis.AnalysisOptionsTest`, `AnalysisOptions2Test` (features-base) | 22 | P4b | analysis modes `SUSPENDED`/`DISABLED`, options of Python analyzers |
| `ghidra.framework.project.extensions.ExtensionInstallerTest` (framework-project) | 19 | P1 | `basilisk plugin install` from zip and directory, replacing an installed version, the API check in place of the version-equality warning |
| `ghidra.framework.plugintool.PluginManagerTest` (test-integrationtest), `ghidra.framework.plugintool.dialog.ManagePluginsTest`, `ManagePlugins2Test` (features-base) | 26 | P1, P6 | enable, disable, dependencies, failure (host in P1, the window in P6) |
| `ghidra.util.classfinder.ClassSearcherTest` (framework-generic) | 2 | P1 | its intent (only declared extensions are found) through entry-point and directory discovery |
| `ghidra.framework.plugintool.AutoServiceTest` (debug-proposedutils) | 5 | — | not applicable: service framework (ADR-001) (proposed mark) |
| `ghidra.util.task.TimeoutTaskMonitorTest`, `UnknownProgressWrappingTaskMonitorTest` (framework-gui), `TaskMonitorSplitterTest` (framework-docking) | 6 | the crate that owns the monitor type (constraints item 7); P1 for the Python side | time-outs, unknown-progress wrapping and splitting of the shared monitor |
| `help.screenshot.GhidraScriptMgrPluginScreenShots` (test-integrationtest) | 12 | P6 | kittest snapshots of the Script Manager |

### 6.2 PyGhidra's pytest suite
`PYG/src/main/py/tests` (47 tests, not in the JUnit checklist):
`test_core` (19: opening programs, running scripts, analysis, project
handling) → P1/P2 equivalents for `basilisk.open`, `run_script`,
`analyze`; `test_argparser` (21) → `python -m basilisk` arguments, P1;
`test_plugin` (4) → plugin host, P1; `test_version` (3) → version and
plugin metadata, P1. Project-only cases are not applicable until M8.

### 6.3 API drift
`python/basilisk/api-manifest.json` lists every public module, class,
function, method, property, parameter (name, kind, default), enum member
and exception base, generated by `python -m basilisk._manifest` from the
built module. The test regenerates it and fails on any difference;
removals and incompatible changes also fail unless `API_VERSION`'s major
changed (or the minor, while it is 0). `python -m mypy.stubtest
basilisk` compares the stubs with the runtime. Every public name has a
docstring (test).

### 6.4 The flat-layer table
`python/basilisk/tests/flat_api_table.tsv` has one row per Ghidra
overload (166 + 128): name, Ghidra signature, status, Pythonic name — the
tables of 4.4 in machine form. The test asserts: every row whose status
is not `none` exists on `FlatAPI` with a docstring; every `later` row
raises `UnsupportedError` naming its milestone; every `none` row is
absent; and, when `../ghidra` is present, the list of Ghidra's public
methods regenerated from `FlatProgramAPI.java` and `GhidraScript.java`
equals the table's (skipped with a printed reason otherwise).

### 6.5 Differential tests
The ten scripts of 4.5 against Ghidra's goldens (track P0 builds them):
output text equal line for line; program-state dump equal. Script 10
when D13 is accepted.

### 6.6 Behaviour tests (pytest, run against the built wheel)
- Threads: the four *exp.* checks as tests (GIL release, Rust-thread
  callbacks, cancellation crossing, exception propagation), plus the
  deadlock test of 4.8 rule 4 under a 60 s bound.
- Transactions: commit, rollback on each exception kind,
  `KEEP_CHANGES_ON_ERROR`, nesting and inner abort, cross-thread writes,
  undo/redo labels, stale handles.
- Isolation: a plugin that fails to import, fails in `register`, raises
  in each callback kind, raises three times, calls `sys.exit`, never
  returns (Cancel).
- Discovery and order: entry points, directories, shadowing, `requires`
  cycles and missing requirements, API ranges.
- Reload: an action and an analyzer disappear and come back; old
  callbacks are not called after reload.
- Proposers: off by default; rank rule against each provenance;
  review/accept/reject; apply as one undo step; removal restores only
  untouched values.

### 6.7 Benchmarks and sanitizers
The 5.4 budgets as `#[ignore]` release tests driving Python, numbers in
`PERF.md`. Nightly: the pytest suite against a wheel built with
AddressSanitizer (`RUSTFLAGS=-Zsanitizer=address`, Linux), since Miri
cannot run CPython.

## 7. Acceptance and tracks

Each track has disjoint crates, is finishable by one agent, and is done
when its checks pass on all three systems in CI (ADR-022) and the gate is
green. "Fixture" means a JSON fixture program of 4.5.

| Track | Owns | Can start | Needs |
|---|---|---|---|
| **P0** reference fixtures | `tools/reference/ghidra_scripts/`, `tests/data/plugin-fixtures/` | now | a Ghidra installation (`GHIDRA_INSTALL_DIR`; in the x86-64 container or on the lent box) |
| **P1** host and packaging | `bk-plugin` (`host/`, `script/`, `task`, `errors`, `address`, `lang`, `embed`), `basilisk-py`, `python/basilisk/{__init__,__main__,plugin}.py`, `crates/basilisk` lib target and `plugin.rs` | now (binds `bk-core`, `bk-lang`) | — |
| **P3** flat layer | `python/basilisk/{flat,ghidra}.py`, `python/basilisk/testing/fake.py` (a pure-Python fake implementing the 4.2 API for tests) | now | P1's package skeleton (or a stub `basilisk` package it replaces) |
| **P6** UI hooks | `bk-plugin-ui` | after the UI change in constraints item 10 is merged; works against the demo `ProgramSource` | P1 |
| **P2** program bindings | `bk-plugin` `py/{program,memory,listing,symbols,references,functions,types,iter,compat}` | when M4's `bk-program`, `bk-store`, `bk-datatypes` APIs are merged | P1, P3 |
| **P4a** loaders | `bk-plugin` `py/loaders` | with `bk-loader` (M4) | P2 |
| **P4b** analyzers and exporters | `bk-plugin` `py/{analysis,exporters}` | with `bk-analysis` (M5) and the exporter framework (M6) | P2 |
| **P5** decompiler and proposers | `bk-plugin` `py/{decompiler,pcode}`, the proposal store's binding | with D17 (M3) and the decompiler wired to the program (M5) | P2, P6 for the Proposals view |
| **P7** further script ports | `python/basilisk/scripts/` | after P2–P5 | — |

Acceptance checks (no check depends on the implementer's judgement):

- **P0**: for each of the ten scripts, `analyzeHeadless` with
  `RunOnFixture.java` and the original script produces output and a state
  dump; both checked in; rerunning reproduces them byte for byte; the
  fixture schema is documented in `tests/data/plugin-fixtures/README.md`.
- **P1**: (1) maturin builds the six wheels in CI; the Linux ones pass
  `auditwheel show` as `manylinux_2_28`. (2) In CI on each system, a fresh
  virtual environment with Python 3.10 and one with 3.14 install the
  wheel, and `python -c "import basilisk; print(basilisk.API_VERSION)"`
  prints the version. (3) `python -m basilisk --version` and `basilisk
  --version` print the same version. (4) An integration test runs
  `basilisk --python …` with `BASILISK_PYTHON` pointing at the test
  environment and sees the marker printed by `python -m basilisk`; with
  no interpreter available it sees the documented message and exit code;
  with an interpreter whose `basilisk` version differs, the version
  message. (5) The UI self-test (`BASILISK_UI_SELF_TEST=run`, then
  `restore`) passes when started as `python -m basilisk` on macOS,
  Linux and Windows. (6) The pytest suites of 6.6 for discovery, order,
  isolation, reload and threads pass. (7) The tests of 6.1 assigned to P1
  are ported and marked. (8) The manifest test of 6.3 exists and passes.
  (9) A script that only prints, asks and checks its monitor runs from
  `basilisk script` and from `python -m basilisk script`, with identical
  output.
- **P3**: the table test of 6.4 passes (all 294 rows); `GhidraScriptTest`
  cases that need only the flat layer pass against the fake; the
  compatibility names of 4.4.3 for the 179 tier A/B scripts are generated
  from `census.tsv` and each has a test.
- **P6**: a plugin action appears in its menu, the palette and Key
  Bindings, runs as a job, and its failure shows a notification
  (`egui_kittest`); table, text and tree views render provider data and
  navigate on the demo program; the console runs statements; Script
  Manager tests of 6.1 pass; a view or action removed by reload leaves no
  trace in menus or layout.
- **P2**: scripts 1–9 of 4.5 produce output and state dumps equal to P0's
  goldens; P3's tests pass against the real bindings; `GhidraScriptRealProgramTest`
  and the four script tests of 6.1 are ported and marked; the 5.4 budgets
  are met and recorded.
- **P4a**: a Python loader for a toy format imports its fixture with the
  same memory map and symbols as the equivalent Rust loader would; it is
  ranked by tier with the built-ins; a raising probe does not stop import.
- **P4b**: a Python analyzer runs at its priority between named built-in
  analyzers (order recorded and asserted), receives exactly the added
  sets the manager accumulated (asserted against a recording Rust
  analyzer), and its options round-trip; `AutoAnalysisWorkerTest` and the
  two options tests are ported; a Python exporter appears in `basilisk
  export`.
- **P5**: script 10 matches P0's golden; `decompile_many` returns results
  in function order; the proposer tests of 6.6 pass.

Order: P0, P1 and P3 now; P6 when the UI registry change lands; P2 with
M4; P4a with M4's loaders; P4b with M5; P5 after M5's decompiler wiring;
P7 last. M9 in `PLAN.md` is complete when P1–P6 are accepted.

## 8. Differences from Ghidra

- Python 3 (CPython ≥ 3.10) only; no Java scripts, no Jython (ADR-005).
  Ports keep Ghidra's flat and bean names (4.4).
- A failed or cancelled script's transaction is rolled back; Ghidra
  commits it (4.9). `KEEP_CHANGES_ON_ERROR = True` restores Ghidra's
  behaviour per script.
- `show` and `createTableChooserDialog` print their rows headless instead
  of raising `ImproperUseException`.
- `getReferencesTo` keeps Ghidra's 4,096 limit only in the flat layer; the
  object model's `references.to` is unbounded and lazy.
- Plugins declare an API range; Ghidra extensions must equal the Ghidra
  version (`ExtensionInstaller.java:89,142-161`).
- Newly discovered plugins are disabled until the user enables them.
- Views are declarative; plugins do not draw UI code (Ghidra plugins
  build Swing components).
- No service locator, events or tool configuration: plugins register
  kinds; program events reach Python as callbacks on the registered kinds
  (ADR-001).
- Language-model proposals carry an origin and the replaced value and can
  be removed per origin; Ghidra's `SourceType.AI` records only the source.
- Python analyzers run as exclusive tasks (Ghidra runs every analyzer one
  at a time anyway).
- The interactive console runs each changing statement in its own
  transaction.

(Implementing tracks append here.)

## 9. Status

Specification written 2026-11-14 (track `spec-plugin`); not implemented.

### 9.1 Decisions to confirm

- **A. The interpreter hosts basilisk** (4.1): the binary stays free of
  Python; Python support is the `basilisk` extension module, run by
  `python -m basilisk` or imported, with the binary handing over to a
  found interpreter. This reads ADR-014's "embeds CPython" as "CPython
  and basilisk share one process, with CPython's executable as the host",
  because linking libpython into the binary breaks the single binary on
  every platform (measured on macOS). The wheel ships beside the binary in
  release archives (not inside it); embedding its bytes in the binary is
  the alternative, at roughly twice the binary's size.
- **B. abi3, CPython 3.10+**, one wheel per platform; free-threaded
  builds deferred.
- **C. Scripts roll back on error** (4.9), opt-out per script.
- **D. Views are declarative** (4.7.6).
- **E. API versioning** separate from the application version, `(0, n)`
  until M9 is accepted (4.10).
- **F. Plugin tracks P0, P1, P3 start now**; P6 after the UI registry
  change; the rest with M4–M5 (section 7).
