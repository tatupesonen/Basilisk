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
Jython, every major flat-API group, and every bundled script that has its
own Ghidra test and is tier A or B):

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
