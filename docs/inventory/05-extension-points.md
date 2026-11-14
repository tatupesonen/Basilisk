# 05 — Ghidra's extension surface (inventory)

What Ghidra lets its users extend, how each kind of extension is found,
registered, configured and run, what state it sees, and how scripts meet
transactions, undo and headless mode. Written for `features/plugin-api.md`
(ADR-014). Source: `../ghidra` at commit `42db038f3c`, read-only.

**Marking.** Every claim carries one of:
`[src path:line]` read in Ghidra's source (paths below `Ghidra/` unless they
start with `GPL/`; `BASE/` = `Features/Base/src/main/java/ghidra/`);
`[cmd N]` counted by command N in section 13; `[J]` the author's judgement.

## 1. Summary

| Kind | Size | Discovered by | Registered as | Configured by | Invoked | Progress, cancel |
|---|---|---|---|---|---|---|
| Script (Java) | 310 bundled scripts + 21 helper classes [cmd 2] | file in a script directory (`ghidra_scripts`, user dir) [src `BASE/app/script/GhidraScriptUtil.java:50,83-84`] | provider per extension: `JavaScriptProvider` compiles to an OSGi bundle (`BundleHost`) [src `GhidraScriptUtil.java:76-84`] | header tags `@category @keybinding @menupath @toolbar @runtime @author` [src `BASE/app/script/ScriptInfo.java:43-48`], `.properties` file beside the script, script arguments | Script Manager, key binding, menu, `runScript`, headless `-preScript/-postScript` | `monitor` (`TaskMonitor`) field |
| Script (Python) | 25 bundled (15 Jython, 4 Base, 5 BSim, 1 PyGhidra) [cmd 1] | same directories, `.py` | `PyGhidraScriptProvider` (CPython via JPype) or `JythonScriptProvider` (Jython 2.7) chosen by `@runtime` [src `Features/PyGhidra/src/main/java/ghidra/pyghidra/PyGhidraScriptProvider.java:40`, `Extensions/Jython/src/main/java/ghidra/jython/JythonScriptProvider.java:26`] | as Java | as Java | as Java |
| Analyzer | 135 concrete `*Analyzer` classes, 46 in Base [cmd 3] | `ClassSearcher` (suffix `Analyzer`) [src `Features/Base/data/ExtensionPoint.manifest`] | instance per program, put in one of six task lists by `AnalyzerType` [src `BASE/app/plugin/core/analysis/AutoAnalysisManager.java:166-196`] | `registerOptions`/`optionsChanged` under `Program.ANALYSIS_PROPERTIES`; default enablement, overridable by the `.pspec` [src `AnalysisScheduler.java:50-60`] | auto-analysis on change events, by priority; one-shot from the menu | `TaskMonitor` and `MessageLog` arguments [src `BASE/app/services/Analyzer.java:94,109`] |
| Loader | 50 concrete `*Loader` classes, 35 in Base [cmd 3] | `ClassSearcher` (suffix `Loader`) | — | `getDefaultOptions`/`validateOptions` [src `BASE/app/util/opinion/Loader.java:176,191`]; `.opinion` files | importer: `findSupportedLoadSpecs` on every loader, user or tier picks one, `load` [src `Loader.java:123,148`] | `ImporterSettings.monitor` [src `Loader.java:89-91`] |
| Exporter | 22 concrete `*Exporter`, 8 in Base [cmd 3] | `ClassSearcher` (suffix `Exporter`) | — | `getOptions`/`setOptions` [src `BASE/app/util/exporter/Exporter.java` (abstract methods after line 160)] | File → Export, headless scripts | `TaskMonitor` argument of `export` |
| Plugin (tool) | 237 concrete `*Plugin`, 127 in Base [cmd 3] | `ClassSearcher` (suffix `Plugin`) [src `Framework/Project/data/ExtensionPoint.manifest`] | `@PluginInfo` (status, package, category, descriptions, services provided/required, events produced/consumed) [src `Framework/Project/src/main/java/ghidra/framework/plugintool/PluginInfo.java:52-125`] | tool options, saved tool configuration | the tool's lifecycle (`init`, `dispose`), events (`ProgramPlugin.programActivated`, `locationChanged`, `selectionChanged`, …) [src `BASE/app/plugin/ProgramPlugin.java:150-232`] | `Task`/`TaskLauncher`, background commands |
| Other extension points | 29 suffixes in Base's manifest, about 75 across all manifests [cmd 4] | `ClassSearcher` | — | — | the subsystem that owns the suffix | — |
| Extension (package) | 9 under `Extensions/` [cmd 5] | `extension.properties` in an installed directory or zip | `ExtensionInstaller` copies it into the user's extension directory [src `Framework/Project/src/main/java/ghidra/framework/project/extensions/ExtensionInstaller.java:44,89`] | — | loaded at start-up with its module's classes, scripts and data | — |

The pattern [J]: everything that can be extended is a Java class that
implements an interface and whose name ends in a suffix listed in some
module's `data/ExtensionPoint.manifest`; the class path is scanned at
start-up and every match is instantiated by the subsystem that wants it.
Scripts are the exception: they are source files found in directories and
compiled or interpreted on demand.

## 2. Scripts

### 2.1 The API a script sees
- `GhidraScript extends FlatProgramAPI` [src `BASE/app/script/GhidraScript.java:137`].
  `FlatProgramAPI` has **166 public method overloads under 123 names**;
  `GhidraScript` adds **128 public overloads under 102 names** (three of
  them, `analyzeAll`, `analyzeChanges`, `getProjectRootFolder`, override the
  flat API's) [cmd 6]. Deprecated: 10 in `FlatProgramAPI` (`analyze`, two
  `createSymbol`, a `findBytes`, `getFunction`, a `getSymbolAt`, `getSymbol`,
  two `createFragment`, `openDataTypeArchive`) and 3 in `GhidraScript`
  (`set`, `execute` with a writer, `getDemangled`) [cmd 7].
- The flat API groups [src `BASE/program/flatapi/FlatProgramAPI.java`, read
  in full]: transaction control (`start`, `end`, 140-160); analysis
  (`analyze*`, `disassemble`, `clearListing`); memory blocks; labels,
  symbols, namespaces, classes; entry points; the five comment kinds (get
  and set); byte, text and string search (`find`, `findBytes`,
  `findStrings`, `findPascalStrings`); functions (create, remove, at,
  containing, before, after, first, last, by name); instructions and data
  (at, containing, before, after, first, last, undefined); typed data
  creation (`createByte` … `createUnicodeString`); typed memory reads and
  writes (`getByte` … `setDouble`); references (from, to, create memory,
  external, stack; remove; primary); equates; bookmarks; fragments;
  addresses (`toAddr`, `createAddressSet`, `getAddressFactory`); data types
  and archives; saving and the project folder.
- `GhidraScript` adds [src `GhidraScript.java`, method list at cmd 6]:
  the state fields; output (`println`, `print`, `printf`, `printerr`); 18
  `ask*` dialogs and their `parse*` counterparts; GUI calls (`goTo`,
  `popup`, `show`, selection and highlight, background colours, table
  chooser dialog, status message); running other scripts and commands
  (`runScript`, `runScriptPreserveMyState`, `runCommand`); analysis options
  (13 methods to get, set and reset them by name); programs and projects
  (`importFile`, `importFileAsBinary`, `createProgram`, `openProgram`,
  `closeProgram`, `askProgram`, `askDomainFile`, server credentials);
  languages; rendered comments; `toHexString`; `getScriptArgs`;
  `isRunningHeadless`; `cleanup(success)`.
- `FlatDecompilerAPI` is a 99-line wrapper: `decompile(Function)` and
  `decompile(Function, timeoutSecs)` return C text; `getDecompiler()`
  exposes the `DecompInterface` [src `Features/Decompiler/src/main/java/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.java:47-94`].

### 2.2 State
- Fields every script has: `currentProgram`, `monitor` (from the flat
  API), `currentAddress`, `currentLocation`, `currentSelection`,
  `currentHighlight`, `state`, `writer`, `errorWriter`, `sourceFile`
  [src `GhidraScript.java:142-150`; the PyGhidra provider lists the same
  twelve names as the fields it exposes to Python,
  `PyGhidraScriptProvider.java:94-106`].
- `GhidraState` carries tool, project, program, location, selection,
  highlight and a map of **environment variables** that scripts share
  (`addEnvironmentVar`, `getEnvironmentVar`) [src `BASE/app/script/GhidraState.java:54-242`].
  The script copies the state into its fields before `run` and back after
  (`loadVariablesFromState`, `updateStateFromVariables`) [src `GhidraScript.java:313-317,546-558`],
  so a script that assigns `currentAddress` moves the tool's cursor.
- `runScript(name)` runs another script **with the same state**; changes
  the callee makes to the location or program are seen by the caller
  [src `GhidraScript.java:807-848,898-935`]. `runScriptPreserveMyState`
  gives the callee a copy.
- Values given to `ask*` are remembered per title and message for the
  session (`askMap`, static) and offered as defaults next time
  [src `GhidraScript.java:140`].

### 2.3 Lifecycle and transactions
1. `execute(state, controls)` sets the fields, loads the `.properties`
   file, then either runs normally or as an analysis worker
   [src `GhidraScript.java:286-321`].
2. **Normal run**: `start()` opens a transaction on `currentProgram` named
   after the script class; `run()`; `monitor.checkCancelled()`; and in a
   `finally`, `end(true)` [src `GhidraScript.java:457-466`,
   `FlatProgramAPI.java:140-160`]. **The transaction is committed even
   when `run` throws**: the exception propagates to `RunScriptTask`, which
   reports it [src `BASE/app/plugin/core/script/RunScriptTask.java:41-59`],
   but the program keeps every change made before the exception, as one
   undoable step. `promptToKeepChangesOnException` exists
   [src `GhidraScript.java:478`] but nothing calls it [cmd 8].
3. The whole script is therefore **one undo step** named after the class,
   unless the script itself calls `end(true)`/`start()` to cut it. A script
   started by another script opens its own transaction inside the caller's;
   Ghidra's domain-object transactions nest, so the outer one is the undo
   step [J, from `start()` checking only its own `transactionID`].
4. **Analysis mode** (`getScriptAnalysisMode`, default `ENABLED`): with
   `DISABLED` or `SUSPENDED` the script runs as an `AnalysisWorker` inside
   the auto-analysis manager, which waits for analysis to finish and
   ignores (or defers) change events while the script runs
   [src `GhidraScript.java:168-190,423-455`].
5. `cleanup(success)` is called last [src `GhidraScript.java:365`].
6. Scripts run on a separate thread, as a `Task` with a modal or
   background progress dialog [src `GhidraScript.java:131-132` (class
   comment), `RunScriptTask.java:33`].

### 2.4 Interaction, GUI and headless
- **`ask*` resolution order** [src `GhidraScript.java:1962-2000`]: the next
  script argument if any were given; else the `.properties` file key
  (title and message joined by spaces); else the default value; else, in
  headless mode, `IllegalArgumentException`. In the GUI the dialog is shown
  pre-filled with that value; Cancel throws `CancelledException`
  [src `GhidraScript.java:3165-3190`].
- **GUI calls in headless mode** differ by method: `popup` logs the
  message [src `:1878-1887`]; `goTo` returns `false` (no tool)
  [src `:3653-3665`]; selection and highlight setters only update the
  state [src `:1584-1606`]; `setBackgroundColor`, `clearBackgroundColor`,
  `createTableChooserDialog`, `setToolStatusMessage`, `show` throw
  `ImproperUseException` [src `:1673-1680,1830-1840,3842-3848,3868-3874`].
- `isRunningHeadless()` is `SystemUtilities.isInHeadlessMode()`
  [src `:787-789`]; scripts branch on it.
- Output: `println` goes to the console (GUI) or the log (headless);
  `printerr` to the error writer.

### 2.5 Providers and discovery
- Five `*ScriptProvider` classes [cmd 3]: Java, PyGhidra, Jython,
  Jython stub, unsupported. A provider declares an extension, a
  description, `getScriptInstance` and `createNewScript`
  [src `BASE/app/script/GhidraScriptProvider.java:74-105`].
- Directories: the user's `~/ghidra_scripts` and every module's
  `ghidra_scripts` [src `GhidraScriptUtil.java:43-50,169`]; Java scripts
  are compiled into OSGi bundles by `BundleHost`, which also lets a script
  directory be a bundle with `@importpackage` dependencies
  [src `GhidraScriptUtil.java:76-84`, `ScriptInfo.java:51`].
- Header tags give the Script Manager's category tree, menu path, toolbar
  icon and key binding; scripts with a `@menupath` appear in the tool's
  menus and with `@keybinding` get a shortcut [src `ScriptInfo.java:333-366`].

## 3. Bundled scripts (census)

Classification by regular expressions over each file's text (comments
removed), tool and output in `docs/agents/spec-plugin-experiments/script-census/`
[cmd 2]. A file is a *script* if its class reaches `GhidraScript` or
`HeadlessScript` through superclasses defined in the scanned files, or it
is a `.py` file; other `.java` files are helpers (21, mostly the
`classrecovery/` package of the Decompiler module).

**335 scripts**: 310 Java, 25 Python, in 26 modules [cmd 1, cmd 2].

| What the script touches (flag) | Scripts |
|---|---:|
| program model directly (`currentProgram.getListing()` etc.) | 206 |
| `ask*` methods | 128 |
| flat GUI methods (`goTo`, `popup`, selection, colour, `show`) | 92 |
| tool services, Swing, `PluginTool` (deep GUI) | 70 |
| project, domain files, import, repositories | 62 |
| data types | 56 |
| a feature module (BSim, FID, VT, PDB, DWARF, debugger, Lisa, ML, YARA) | 56 |
| language, registers, context | 48 |
| decompiler (`DecompInterface`, `HighFunction`, tokens) | 24 |
| commands (`runCommand`, `*Cmd`) | 20 |
| binary-format parsers (`ghidra.app.util.bin`) | 19 |
| p-code ops and varnodes | 19 |
| analysis manager or options | 12 |
| assembler | 10 |
| other scripts (`runScript`) | 9 |
| emulator | 7 |
| third-party Java libraries | 22 |

**Tiers** (the column `tier` in `census.tsv`):

| Tier | Meaning | Scripts | Share |
|---|---|---:|---:|
| A | flat API and the core program model only (plus `ask*`, `print*`) | 94 | 28 % |
| B | A plus data types, decompiler, p-code, language, analysis options, commands, assembler, flat GUI methods, other scripts | 85 | 25 % |
| C | needs a Swing tool or tool service, a project or repository, a feature module, a binary-format parser, the emulator or a third-party Java library | 156 | 47 % |

By module [cmd 2]: Base A 70, B 67, C 61; Decompiler A 2 (of its 21
scripts; the other A/B rows are helpers), BSim 18 of 21 in C, FunctionID
17 of 19 in C, VersionTracking and Debugger all C.

How good the regular expressions are [J]: they over-count tier C (one
`getService` call to fetch a `GoToService`, or a `DomainFile` used only to
print a name, makes a script C) and the flags are presence flags, not
counts. The ten scripts read by hand for `plugin-api.md` 4.3 agree with
their tiers, with one miss: `DecompilerStackProblemsFinderScript` is
tier B but refuses to run headless and ends in a table chooser dialog, so
its useful output needs the UI hooks.

## 4. Analyzers

- `Analyzer` interface [src `BASE/app/services/Analyzer.java:39-149`]:
  `getName`, `getAnalysisType`, `getDefaultEnablement(program)`,
  `supportsOneTimeAnalysis`, `getDescription`, `getPriority`,
  `canAnalyze(program)`, `added(program, set, monitor, log)`,
  `removed(program, set, monitor, log)`, `registerOptions(options,
  program)`, `getOptionsUpdater`, `optionsChanged(options, program)`,
  `analysisEnded(program)`, `isPrototype`. `AbstractAnalyzer` supplies the
  plumbing.
- **Types** (which change events feed it): byte, instruction, function,
  function modifiers, function signatures, data
  [src `BASE/app/services/AnalyzerType.java:47-52`].
- **Priorities**: named steps 100 apart — `FORMAT` 100, `BLOCK` 200,
  `DISASSEMBLY` 300, `CODE` 400, `FUNCTION` 500, `REFERENCE` 600, `DATA`
  700, `FUNCTION ID` 800, `DATA TYPE PROPOGATION` 900; plus `HIGHEST` 1 and
  `LOW` 10000; `before()`/`after()` shift by one
  [src `BASE/app/services/AnalysisPriority.java:57-187`]. Lower runs first.
- **Scheduling**: one `AnalysisScheduler` per analyzer accumulates an
  added set and a removed set from change events while enabled, and
  queues one task at the analyzer's priority when either is non-empty
  [src `BASE/app/plugin/core/analysis/AnalysisScheduler.java:68-130`]. The
  manager runs the queue in priority order; a task can yield to
  higher-priority work queued by its own changes [J, from
  `AutoAnalysisManager.java:111` (a priority queue of background
  commands)].
- **Names may not contain a period**: the name is the options key
  [src `AnalysisScheduler.java:42-47`].
- **Options**: registered under the analyzer's name in the program's
  `Analyzers` options; a `.pspec` can override default enablement
  [src `AnalysisScheduler.java:50-60`]. Scripts set them by name
  (`setAnalysisOption`) [src `GhidraScript.java:1412-1460`].
- **One-shot**: `scheduleOneTimeAnalysis(analyzer, set)` copies the
  options of the registered instance and runs once
  [src `AutoAnalysisManager.java:226-237`].
- Discovered by `ClassSearcher.getInstances(Analyzer.class)` and filtered
  by `canAnalyze` per program [src `AutoAnalysisManager.java:169-172`].

## 5. Loaders and opinions

- `Loader` [src `BASE/app/util/opinion/Loader.java:89-298`]:
  `findSupportedLoadSpecs(ByteProvider)` → load specs (loader, image base,
  language/compiler pair or "needs one"); `load(ImporterSettings)` →
  `LoadResults` (one or more programs); `loadInto(program, settings)`;
  `getDefaultOptions`, `validateOptions`; `getName`, `getTier`
  (`SPECIALIZED_TARGET`, `GENERIC_TARGET`, `AMBIGUOUS_TARGET`,
  `UNTARGETED` [src `LoaderTier.java:22-27`]), `getTierPriority`,
  `isFallback`, `getPreferredFileName`, `supportsLoadIntoProgram`,
  `loadsIntoNewFolder`, `getAssociatedFileExtensions`. Ordering is by tier,
  then tier priority, then name [src `Loader.java:293-298`].
- `ImporterSettings` is a record of provider, import name, project, root
  path, layout flag, load spec, options, consumer, `MessageLog` and
  `TaskMonitor` [src `Loader.java:89-91`].
- Implementations extend `AbstractProgramWrapperLoader` and write one
  method, `load(Program, ImporterSettings)`, filling an already created
  program [src `AbstractProgramWrapperLoader.java:40`].
- **Opinions**: `QueryOpinionService.query(loaderName, primaryKey,
  secondaryKey)` reads the processors' `.opinion` files to turn a format's
  machine code into language/compiler pairs [src `QueryOpinionService.java:115`].
  Basilisk already ports this (`bk-lang`, `QueryOpinionServiceTest` ported).

## 6. Exporters

`Exporter` [src `BASE/app/util/exporter/Exporter.java:122-217`]:
`canExportDomainObject(class)`, `supportsAddressRestrictedExport`,
`getOptions`, `setOptions`, `export(file, domainObject, addressSet,
monitor)`; constructed with a name, file extension and help location.
Eight in Base (ASCII, C/C++, binary, Intel hex, XML, SARIF, GZF, …) [cmd 3].

## 7. Plugins, services, events and actions

- A tool (`PluginTool`, 1,669 lines) is a set of plugins
  [src `Framework/Project/src/main/java/ghidra/framework/plugintool/PluginTool.java`];
  a plugin declares in `@PluginInfo` which **services** it provides and
  requires and which **events** it produces and consumes
  [src `PluginInfo.java:104-125`]. The tool wires services by interface
  type and broadcasts events.
- `ProgramPlugin` turns the program and location events into callbacks:
  `programActivated`, `programDeactivated`, `programOpened`,
  `programClosed`, `locationChanged`, `selectionChanged`,
  `highlightChanged` [src `BASE/app/plugin/ProgramPlugin.java:150-232`].
- Actions (`DockingAction`) are created by plugins and registered with
  the tool: menu path, popup path, toolbar icon, key binding,
  enablement by `ActionContext` [J, Docking framework; Basilisk replaces
  it with `bk-ui`'s action registry].
- 237 concrete plugin classes [cmd 3]. ADR-001 rules out a
  plugin/service-locator framework in Basilisk's own structure; this is
  the part of Ghidra's surface Basilisk reproduces least literally.

## 8. Other extension points

Suffixes in `Features/Base/data/ExtensionPoint.manifest` (29): `Analyzer`,
`Demangler`, `Exporter`, `FieldFactory`, `FieldMouseHandler`,
`FileSystem`, `StringHandler`, `Loader`, `SourceLanguage`,
`SourceLanguageDataArchive`, `SourceLanguageSpecExtension`,
`TableRowMapper`, `ScriptProvider`, `Recognizer`,
`BinaryAnalysisCommand`, `CoffRelocationHandler`,
`MachoRelocationHandler`, `ElfRelocationHandler`, `ElfExtension`,
`RelocationFixupHandler`, `CodeComparisonView`, `InstructionSkipper`,
`DataTypeReferenceFinder`, `ChecksumAlgorithm`, `OverviewColorService`,
`DWARFFunctionFixup`, `ElfInfoProducer`, `FSBFileHandler`,
`SearchAndReplaceHandler` [src, the file]. Other modules add `Plugin`,
`ContentHandler`, `RelocationHandler`, `DataType`, `GraphDisplayProvider`,
`ProgramCorrelatorFactory`, debugger opinions, emulator user-op
libraries and more [cmd 4]. Implementation counts for the larger ones
[cmd 3]: `FileSystem` 57, `FieldFactory` 52, `Recognizer` 43,
`ElfRelocationHandler` 22, `ProgramCorrelatorFactory` 14, `ElfExtension`
13, `CoffRelocationHandler` 6, `MachoRelocationHandler` 5, `Demangler` 5.

Which of these a Python user plausibly writes [J]: scripts, analyzers,
loaders, exporters, actions and views first; then file systems,
relocation handlers, ELF extensions, demanglers and correlators. Field
factories, table mappers and the rest are tool internals.

## 9. Discovery and packaging

- **Class discovery**: `ClassSearcher` scans the class path at start-up
  and keeps classes that implement `ExtensionPoint` **and** whose name
  ends in a suffix listed in some module's `data/ExtensionPoint.manifest`
  [src `Framework/Generic/src/main/java/ghidra/util/classfinder/ExtensionPoint.java` (class comment)].
- **Modules**: a directory with `Module.manifest` (114 of them [cmd 5]);
  its keys are mostly `MODULE FILE INFO` (licences of bundled files), with
  `MODULE DEPENDENCY`, `EXCLUDE FROM GHIDRA JAR`, `DATA SEARCH IGNORE DIR`
  [cmd 5].
- **Extensions**: a module plus `extension.properties` with `name`,
  `description`, `author`, `createdOn`, `version` (e.g.
  `Extensions/sample/extension.properties`). Installed from a zip or
  directory into the user settings directory; **the version must equal
  the running Ghidra's version**, otherwise the user is warned and asked
  [src `ExtensionInstaller.java:89,142-161`]. There is no API version
  separate from Ghidra's own release number [J, from the same lines].
- Enabling and disabling: extensions are installed or uninstalled (restart
  needed); plugins are added to or removed from a tool configuration
  (File → Configure) [J, from the `ManagePlugins*Test` names and the
  extension dialog classes].

## 10. Headless

- `analyzeHeadless <project> <name> -import|-process … -preScript …
  -postScript … -scriptPath … -propertiesPath … -noanalysis
  -analysisTimeoutPerFile …` drives `HeadlessAnalyzer`
  [src `BASE/app/util/headless/HeadlessAnalyzer.java`, `HeadlessOptions.java`].
- Per file: import (or open), pre-scripts, then **analysis inside one
  transaction named "Analysis"** committed even on time-out
  [src `HeadlessAnalyzer.java:1054-1098`], then post-scripts, then — if
  the post-scripts changed anything and analysis is on — a second
  analysis in a "Post-Analysis" transaction [src `:1137-1143`].
- `HeadlessScript extends GhidraScript` adds a per-run key/value store
  shared between scripts (`storeHeadlessValue`, `getStoredHeadlessValue`),
  the continuation option (`CONTINUE`, `CONTINUE_THEN_DELETE`, `ABORT`,
  `ABORT_AND_DELETE`) that decides whether processing goes on and whether
  the program is kept, enabling or disabling analysis, the import
  directory, and `analysisTimeoutOccurred` [src `HeadlessScript.java:40-53,151-390`].
- A time-out is a `HeadlessTimedTaskMonitor` that cancels the monitor
  [src `HeadlessAnalyzer.java:1072-1076`]: cancellation is the only
  mechanism for stopping analysis.

## 11. PyGhidra

- **Architecture**: Python is the host process. `pyghidra` (a Python
  package, version 3.3.0) starts a JVM inside CPython through **JPype**
  and runs Ghidra in it; Python scripts in the GUI work only when Ghidra
  was started that way ("Ghidra was not started with PyGhidra. Python is
  not available") [src `Features/PyGhidra/src/main/py/src/pyghidra/__init__.py:16`,
  `PyGhidraScriptProvider.java:71-77`].
- **Launcher**: `support/pyghidra_launcher.py` looks for a Python whose
  version is in `application.python.supported` (3.9–3.15), trying
  `python3.X`, `py -3.X`, `python3`, `python`, `py`; offers to create a
  virtual environment in the user settings directory; respects externally
  managed environments [src `support/pyghidra_launcher.py:84-111,113-133`,
  `Ghidra/application.properties:10`].
- **Script globals**: a PyGhidra script runs as module `__main__` whose
  globals are a dict that falls back to the Java `GhidraScript` instance
  for missing names, so `currentProgram`, `toAddr`, `askString`, `monitor`
  are bare names; assignments to exposed fields (`currentAddress = …`)
  write through to the Java object; `print` goes to the script's writer;
  the builtin `set` wins over `GhidraScript.set`
  [src `pyghidra/script.py:147-208`].
- **Module-level API**: `start`, `open_program`, `program_context`,
  `run_script`, `ghidra_script`, `analyze`, `transaction`,
  `program_loader`, `task_monitor`, `walk_project`, `walk_programs`
  [src `pyghidra/__init__.py:55-75`].
- **`transaction(program, description)` rolls back on exception** — unlike
  `GhidraScript`, which commits [src `pyghidra/api.py:256-275`].
- Objects are JPype proxies of the Java classes: Python sees Ghidra's Java
  API one to one (getters, Java collections, Java exceptions), with JPype
  adding properties for bean getters [J, from `script.py:199-205`].
- Tests: `PythonScriptInfoTest` (JUnit) and a pytest suite of 47 tests in
  `src/main/py/tests` (`test_core` 19, `test_argparser` 21,
  `test_plugin` 4, `test_version` 3) [cmd 9], which the JUnit checklist
  does not list.

## 12. Idioms existing scripts rely on

From the bundled scripts and PyGhidra's exposed fields [J, with cmd 2 for
the counts]:

- Bare globals: `currentProgram`, `currentAddress`, `currentSelection`,
  `currentLocation`, `currentHighlight`, `monitor`, `state`, `writer`.
- Flat calls without a receiver: `toAddr(0x401000)`, `getFunctionAt(a)`,
  `getFirstFunction()` / `getFunctionAfter(f)` loops, `getBytes(a, n)`,
  `createLabel(a, name, True)`, `setEOLComment(a, text)`,
  `getReferencesTo(a)`, `findBytes(start, regex)`, `println(...)`.
- Program-model chains: `currentProgram.getListing().getInstructions(True)`,
  `currentProgram.getFunctionManager().getFunctions(True)`,
  `currentProgram.getSymbolTable()`, `getMemory().getBlocks()`,
  `getReferenceManager().getReferencesTo(a)` (206 scripts) — Java
  iterators used with `while it.hasNext()` or Python `for x in it`.
- Monitor use: `monitor.checkCancelled()` in loops,
  `monitor.setMessage`, `monitor.initialize(n)`, `monitor.incrementProgress(1)`.
- `askString/askInt/askAddress/askChoice/askYesNo/askFile` with
  `.properties` or script arguments for headless runs (128 scripts).
- `getState().getEnvironmentVar(...)` and `runScript(name)` for
  chaining; `isRunningHeadless()` branches.
- `DecompInterface` boilerplate: `openProgram`, `decompileFunction(f,
  timeout, monitor)`, `getDecompiledFunction().getC()`,
  `getHighFunction()` walks (24 scripts).
- Jython-specific: Java imports (`from ghidra.program.model.symbol import
  SourceType`), Java enums (`SourceType.USER_DEFINED`), Java arrays from
  `jarray`, Python 2 syntax (`print x`) in old user scripts.

## 13. Commands

Run from `../ghidra`. `S` is a scratch directory.

1. `find Ghidra GPL -type d -name ghidra_scripts | while read d; do echo "$(find $d -name '*.java' | wc -l) $(find $d -name '*.py' | wc -l) $d"; done`
   — 26 directories, 331 `.java` and 25 `.py` files.
2. `find Ghidra GPL -path '*ghidra_scripts*' \( -name '*.java' -o -name '*.py' \) | LC_ALL=C sort > $S/scripts.lst; perl docs/agents/spec-plugin-experiments/script-census/classify.pl $(cat $S/scripts.lst) > census.tsv`
   (classifier and output in `docs/agents/spec-plugin-experiments/script-census/`).
3. Concrete classes by suffix:
   `find Ghidra -path '*/src/main/java/*' -name '*.java' | tr '\n' '\0' | xargs -0 perl -ne 'if(/^public\s+(final\s+)?class\s+(\w+)/){print "$ARGV\t$2\n"} close ARGV if eof' > $S/concrete.tsv`,
   then `awk -F'\t' '$2 ~ /Analyzer$/' $S/concrete.tsv | wc -l` per suffix
   (abstract classes excluded by the pattern).
4. `find Ghidra -name ExtensionPoint.manifest | xargs cat | sort -u | wc -l`.
5. `ls Ghidra/Extensions`; `find Ghidra -name Module.manifest | wc -l`;
   `find Ghidra -name Module.manifest | xargs cat | cut -d: -f1 | sort | uniq -c`.
6. Public signatures: a Perl one-liner joining multi-line declarations of
   `^\t(public|protected)\s` methods in `FlatProgramAPI.java` and
   `GhidraScript.java`, then `grep -c ' public '` and the distinct names
   (constructors excluded).
7. `perl -ne 'if(/\@Deprecated/){$d=1;next} if($d && /\s(\w+)\s*\(/){print "$1 "; $d=0}'` over the same two files.
8. `grep -rn promptToKeepChangesOnException --include='*.java' Ghidra` — one hit, the declaration.
9. `grep -c "def test" Ghidra/Features/PyGhidra/src/main/py/tests/*.py`.

## 14. Ghidra tests for the extension surface (checklist ids)

From `docs/inventory/tests/` (file in brackets). These are the tests the
plugin tracks port or mark; `plugin-api.md` section 6 assigns them.

Scripts [features-base]: `ghidra.app.script.GhidraScriptTest` (28),
`ghidra.app.script.GhidraScriptAskMethodsTest` (16),
`ghidra.app.script.GhidraScriptRealProgramTest` (11),
`ghidra.app.plugin.core.script.GhidraScriptMgrPlugin1Test` (6),
`…Plugin2Test` (25), `…Plugin3Test` (25),
`ghidra.app.plugin.core.script.JavaScriptInfoTest` (5),
`ghidra.app.plugin.core.script.BundleHostTest` (9),
`ghidra.app.plugin.core.script.BundleStatusManagerTest` (3),
`ghidra.app.plugin.core.interpreter.InterpreterPanelTest` (8);
[test-integrationtest]: `ghidra.app.script.GhidraScriptUtilTest` (7),
`help.screenshot.GhidraScriptMgrPluginScreenShots` (12).

Bundled scripts with their own tests [features-base unless noted]:
`AutoRenameLabelsScriptTest` (2), `DeleteFunctionDefaultPlatesScriptTest`
(2), `EditBytesScriptTest` (17), `ExportFunctionInfoScriptTest` (1),
`FindAndReplaceCommentScriptTest` (9), `FixOffcutInstructionScriptTest`
(1), `PasteCopiedListingBytesScriptTest` (7), all under
`ghidra.app.plugin.core.script.`; `WindowsResourceReferenceScriptTest` (2)
[test-integrationtest].

Python [features-pyghidra, extensions-jython]:
`ghidra.pyghidra.PythonScriptInfoTest` (5),
`ghidra.jython.JythonScriptTest` (2), `JythonInterpreterTest` (4),
`JythonPluginTest` (1), `JythonScriptInfoTest` (5),
`JythonCodeCompletionTest` (3).

Analysis framework [features-base]: `ghidra.app.plugin.core.AutoAnalysisWorkerTest` (9),
`ghidra.app.plugin.core.analysis.AnalysisOptionsTest` (8),
`ghidra.app.plugin.core.analysis.AnalysisOptions2Test` (5);
[test-integrationtest] `help.screenshot.AutoAnalysisPluginScreenShots` (4).

Import and export: `ghidra.plugins.importer.tasks.ImportBatchTaskTest` (4)
[features-base]; `help.screenshot.ImporterPluginScreenShots` (4),
`help.screenshot.ExporterPluginScreenShots` (4) [test-integrationtest];
`ghidra.app.util.opinion.QueryOpinionServiceTest` — already ported
(`crates/bk-lang/tests/ported.rs`).

Discovery, packaging, tool framework:
`ghidra.util.classfinder.ClassSearcherTest` (2) [framework-generic];
`ghidra.framework.project.extensions.ExtensionInstallerTest` (19)
[framework-project]; `ghidra.framework.plugintool.PluginManagerTest` (11)
[test-integrationtest]; `ghidra.framework.plugintool.AutoServiceTest` (5)
[debug-proposedutils]; `ghidra.framework.plugintool.dialog.ManagePluginsTest` (9),
`ManagePlugins2Test` (6), `KeyBindingsTest` (14) [features-base];
`ghidra.framework.plugintool.mgr.BackgroundCommandTaskTest` (4)
[features-base].

Monitors and options: `ghidra.util.task.TimeoutTaskMonitorTest` (2),
`UnknownProgressWrappingTaskMonitorTest` (2) [framework-gui];
`TaskMonitorSplitterTest` (2) [framework-docking];
`ghidra.framework.data.TransactionLockingTaskMonitorTest` (2),
`ghidra.framework.options.OptionsTest` (58) [features-base];
`ghidra.framework.options.AutoOptionsTest` (17) [debug-proposedutils].
