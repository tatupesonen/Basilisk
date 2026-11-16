# Programs port plan (milestones M4 and M5)

Not a feature spec: this is the plan that the feature specs of the
program model, storage, data types, loaders and analysis hang from, in
the shape of `decomp-plan.md`. It says what is ported, the crate split,
the constraints shared by all tracks, how parity with Ghidra is
measured, the tracks and their order, and what the coordinator has to
decide.

**State of this plan (2026-11-16).** M4 is planned to the level needed to
brief specification agents. M5 is a track table only. Parts that were
not derived from the source to the project's standard are marked **to be
planned**, with the Ghidra paths they concern; nothing in them is written
from memory. Figures marked *measured* come from the scripts in
`docs/research/plan-programs/` (its `README.md` has the commands);
`roadmap-check.md` there has the evidence for the order. Ghidra was not
run: no JDK was available to this track.

Path abbreviations: `SM/` =
`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`, `BASE/` =
`Ghidra/Features/Base/src/main/java/ghidra/`, `DB/` =
`Ghidra/Framework/DB/src/main/java/db/`, `PROJ/` =
`Ghidra/Framework/Project/src/main/java/ghidra/framework/`.

## 1. What is being ported

Sizes are Java main lines, measured. Tests are classes and `@Test`
methods from the checklist (`tests-m4-m5.txt`).

| Part | Ghidra code | Size | Tests |
|---|---|---:|---|
| Addresses on the program side | `SM/program/model/address` | 8,875 | 12 / 141 |
| Storage engine | `DB/` — replaced (ADR-003); the program database uses 33 of its 97 classes | 31,606 | 19 / 288 (ported where they describe the table interface) |
| Address map, memory | `SM/program/database/{map,mem}`, `SM/program/model/mem` | 3,785 + 6,780 + 3,588 | 18 / 217 |
| Data types | `SM/program/model/data` (251 files; 132 concrete built-in types, 15,197 lines), `SM/program/database/data`, `dtarchive` on both sides, the C parser (`BASE/app/util/cparser` and its JavaCC grammar) | 40,011 + 28,845 + 3,709 + 8,303 | 61 / 982 |
| Symbols, namespaces, equates, external locations | `SM/program/database/{symbol,external}`, `SM/program/model/symbol` | 12,503 + 1,390 + 7,558 | 11 / 220 |
| Code units, comments, properties, bookmarks, context | `SM/program/database/{code,properties,bookmark,register}`, `SM/program/model/listing` (interfaces for all of the above) | 10,667 + 2,402 + 2,847 + 2,001 + 13,548 | 7 / 95 and part of 28 / 401 |
| References | `SM/program/database/references` | 5,493 | 3 / 52 |
| Functions and variables | `SM/program/database/function` (`oldfunction`, 2,068, is an upgrade path: not applicable) | 7,659 | 4 / 75 |
| Relocation table, source map, program trees | `SM/program/database/{reloc,sourcemap,module}`, `SM/program/model/{reloc,sourcemap}` | 1,519 + 2,158 + 3,453 + 1,016 | part of 28 / 401 |
| The program itself | `SM/program/database/*.java` (23 files; `ProgramDB.java` 2,509), `util`; the domain-object slice of `PROJ/{data,model}` (25 classes, 4,784 lines imported directly) | 8,414 + 3,130 + 4,784 | 17 / 274 |
| Program utilities | `SM/program/util` (114 files: locations, contexts, change records, language translation) | 16,477 | 25 / 407 with `Base`'s |
| Loaders, importer | `BASE/app/util/opinion` (72 files), `BASE/app/util/importer` | 28,250 + 3,147 | 10 / 54 |
| Program-side code of the formats | `BASE/app/util/bin/format/{elf,pe,macho}` (data-type layouts and markup; `bk-elf` already holds ELF parsing) | 11,284; 32,463; 18,530 | 37 / 762 for all of `app.util.bin` |
| Relocation handlers | `Ghidra/Processors/*`: 22 ELF, 5 Mach-O, 6 COFF handlers, 13 ELF extensions | 11,769; 911; 1,249; 3,465 | few (processor modules have 0 to 6 unit tests each) |
| Commands used by loaders | `BASE/app/cmd` (126 files in all) | 19,083 | 24 / 236 |
| M5 (section 9) | disassembler 3,669; analysis manager about 2,900; 133 analyzers 36,582; block models 6,789; symbolic propagation 5,206; byte search 4,590; decompiler interface and result model about 29,000; headless 4,222 | | 9 / 113; 39 / 346 |

Of the 108,301 lines of `SM/program/database`, 25,584 are table adapters
and 15,810 of those are adapters for old schema versions (108 files named
`…AdapterV<n>` or `…NoTable`), which Basilisk does not have (ADR-003).

Four facts shape the plan (evidence in `roadmap-check.md`, section 1):

1. **The model is one import cycle** (41 package groups, 321,000 lines in
   `SoftwareModeling`; 50 groups, 689,000 lines in `Base`). The order
   below comes from what each part calls. Ghidra itself fixes an order
   for its fifteen managers (`SM/program/database/ProgramDB.java:188–204`:
   memory, code, symbol, namespace, function, external, reference, data,
   equate, bookmark, context, property, tree, relocation, source file)
   and a protocol between them: `setProgram`, `programReady`,
   `invalidateCache`, `deleteAddressRange`, `moveAddressRange`
   (`ProgramDB.java:1837–1991` loops over the managers for each).
2. **There are no test binaries in Ghidra's tree and loaders have 54
   tests.** Parity for loaders is measured by the oracle on a corpus the
   project builds; program-model tests need a builder (449 Ghidra test
   files use `ProgramBuilder`).
3. **Several parts need nothing of the others**: data types (memory only
   through `MemBuffer`), format parsers and relocation arithmetic (bytes
   only), the disassembler core (language and bytes only). They run
   beside the store-and-model chain.
4. **`sleigh-language` (M1's open item) is on the path**: code units are
   stored as a prototype id plus flags
   (`SM/program/database/code/InstDBAdapter.java:38`), and register
   values need registers as a model.

## 2. Crate split

ADR-013 and ADR-015: tracks own disjoint crates. The rule that removes
Ghidra's cycle is the decompiler plan's, applied to programs: **each area
crate owns its tables and the rules inside one area; effects that cross
areas are written once, in `bk-program`**, at the points where Ghidra's
managers call each other (the five-method protocol above). An area crate
reaches a neighbour above it only through a small trait that
`bk-program` implements (as `FunctionEnv` does for the IR, ADR-046).

```
basilisk import | dump                (bin)
  bk-headless            import → (analyse) → export pipeline
  bk-export              binary, Intel hex, ASCII, XML exporters (pulled into M4)
  bk-loader-elf, -pe, -macho, -raw    one crate per loader; markup and data-type layouts of the format
  bk-reloc-*             relocation handlers, one crate per processor family
  bk-loader              Loader trait, load specs, tiers, options, library resolution,
  │                      section resolver, importer; the LoadTarget trait and its recording target
  bk-cmd                 commands: operations over a program that loaders and analyzers share
  ├── bk-program         the handle, transactions, undo, events, options, snapshots,
  │                      cross-area rules, the dump writer
  ├── bk-functions       functions, variables and storage, thunks, tags, stack frames
  ├── bk-listing         instructions (prototype table), data, comments, property maps,
  │                      bookmarks, register values, relocation table, source map, program trees
  ├── bk-symbols         symbols, namespaces, labels, dynamic names, equates, external locations
  ├── bk-refs            references in both directions
  ├── bk-datatypes       the type model, the manager, archives      bk-cparser   bk-ghidra-db (read-only .gdt/.fidb)
  ├── bk-memory          address map, blocks, file bytes, byte access
  ├── bk-store           ordered tables, snapshots, one writer, the logical change log
  ├── bk-addr            address sets and ranges, the factory, overlay and segmented spaces
  └── bk-task            the monitor (cancel, progress)
        (all on bk-core; bk-listing and bk-functions on bk-language/bk-sleigh's model types;
         bk-datatypes and bk-functions on bk-cspec; format crates bk-elf, bk-pe, bk-macho on bk-bin only)
```

What each owns in Ghidra's terms is the "Ghidra code" column of section
6. Dependency rules, added to `PLAN.md`'s:

* Arrows point down. `bk-datatypes` does not depend on `bk-memory`: it
  reads values through a `MemBuffer`-like trait in `bk-addr` (Ghidra:
  75 files of `model.data` import `model.mem`, for that interface).
* Format parsers stay on `bk-bin` (existing rule). What Ghidra's format
  classes do to a program — `toDataType()`, markup — moves to the loader
  crate of the format. This is why 156 of the 230 PE files import the
  data-type model in Ghidra and none will in `bk-pe`.
* **Loaders are written against `LoadTarget`, not against
  `bk-program`.** The trait (in `bk-loader`) is the set of operations a
  loader performs: create blocks, write and read back bytes, add symbols,
  relocations, references, data, functions, properties, log messages.
  Two implementations: the program, and an in-memory recording target.
  Loader tracks can then be written and compared with the oracle before
  the model is finished. **Unverified:** that the trait stays small for
  ELF; `ElfProgramBuilder` (3,821 lines) imports the listing, symbol,
  memory, data and relocation packages wholesale. The loader-core
  specification settles it by listing the calls.
* `bk-decomp-symbols`' `ProgramHost` is implemented in a crate above both
  sides (`bk-decomp-host`, M5), and `bk-ui`'s `ProgramSource` in an
  adapter crate above `bk-ui`'s model and `bk-program` (`bk-ui-program`).
  Neither side learns of the other.
* The order memory → references → symbols → code units → functions is
  derived from import counts between the manager packages
  (`deps-edges.tsv`: the managers import each other in 1 to 9 files and
  the model interfaces in dozens). **To confirm in each specification**
  from the method bodies; where it does not hold, the cut is a trait.

## 3. Design constraints shared by all tracks

1. **Typed ids, never reused.** `SymbolId`, `FunctionId`, `VariableId`,
   `DataTypeId`, `NamespaceId`, `BlockId`, `RefId`, `BookmarkId`,
   `TxId` are newtypes. An id is assigned once and is not handed out
   again after its entity is deleted or its creation undone; a lookup by
   a dead id returns a typed `Stale` error (binding constraint 3).
   *Difference from Ghidra:* its keys are "maximum key plus one"
   (`DB/Table.java:605–611`) and the maximum is restored by undo, so an
   id can come to denote another entity. Counters live outside the undo
   state. Variables get an id of their own (Ghidra: variables are
   symbols). Parity is unaffected: the oracle names things by
   reproducible keys (section 4.3), never by ids.
2. **Addresses are `bk-core` addresses everywhere** (constraint 14).
   Table keys are (space, offset) in big-endian, so key order is address
   order in every space. *Difference:* Ghidra packs 4 bits of kind, 28
   of segment index and 32 of offset (`SM/program/database/map/AddressMapDB.java:51–65`),
   so order holds only inside a 4 GiB segment. Ghidra's encoding is
   relative to the image base, which makes rebasing cheap; **the memory
   specification must keep "set image base rewrites no table"** and say
   how.
3. **Transactions** (constraint 13): writes need a transaction token;
   transactions are named, nest, belong to a thread; the outermost is one
   undo step; an inner abort marks the outermost aborted
   (`PROJ/data/DomainObjectDBTransaction.java:151–163`). Reads need none.
4. **Undo is logical and is one mechanism with change notification.**
   Every write appends a record (table, key, old value, new value) to the
   transaction's change log. Undo replays it backwards; the same log is
   the change set analyzers and views are told about (Ghidra keeps these
   apart: page-level undo in `DB/buffers/BufferMgr.java`, events through
   `PROJ/data/DomainObjectChangeSupport.java`, address sets in
   `SM/program/database/ProgramDBChangeSet.java`). *Differences, all
   following from the storage study (section 3.1):* undo history
   survives save; a crash loses at most the batch in progress, not
   everything since the last five-minute snapshot; an analysis run is
   one undo step but many engine commits. Ghidra's 50-step limit
   (`PROJ/data/DomainObjectAdapterDB.java:44`) becomes a default, not a
   property of the engine. **Open:** undo of a bulk step (a whole
   analysis) through the log costs 48 bytes and about a third of the
   insert rate per instruction in the spike's partial numbers; a
   checkpoint-based undo for bulk steps is the alternative. The spike
   decides.
5. **Readers use snapshots and never block.** A reader holds an
   immutable snapshot (`Arc`, `Send + Sync`); there is one writer; a
   reader never sees a half-applied transaction. *Difference:* Ghidra
   takes one read/write lock per call and readers see uncommitted writes
   (`storage-engine.md` 1.4, verified there). Consequences: analysis
   commits in batches so views fill in; **a snapshot is the frozen
   program state ADR-044 asks for**, at no extra cost; the interface
   reads snapshots on worker threads and never waits for a writer
   (ADR-012).
6. **Events are owned records** (constraint 8): kind, address range,
   entity ids, old and new value where Ghidra carries them. Ghidra has
   about a hundred kinds (`SM/program/util/ProgramEvent.java`); each
   becomes an enum variant with Ghidra's meaning. They are delivered
   after commit, never while a lock is held (constraint 9b).
7. **Provenance on every annotation** (constraint 11): names, types,
   comments and signatures carry `bk_core::Provenance`; Ghidra's
   `SourceType` maps onto it. Edits with `Provenance::Model` record an
   origin and the replaced value, and can be listed and removed by
   origin. Provenance takes no part in identity or comparison (ADR-028).
8. **One monitor** (constraint 7): `bk-task::Monitor`, moved out of
   `bk-ui`, taken by every long operation; a distinct `Cancelled` error.
9. **Results are owned and keepable** (constraint 6): an import result,
   an analysis log and a snapshot are `Arc`-held values readable after
   the call. Large collections are counted and paged by key (constraint
   5); no accessor returns everything as a `Vec`.
10. **Errors and hostile input** (ADR-009): `thiserror` enums per crate,
    `#[non_exhaustive]`, with address, name and what was expected. A
    loader does not abort on a damaged file: it returns what it could
    build and a list of typed diagnostics, with Ghidra's message text
    where the oracle's `log` section shows it.
11. **No `unsafe`** in any crate of this plan (ADR-020), with one
    possible exception: `bk-store`, if the chosen engine is
    memory-mapped. Then the mapping sits in one module, the crate is
    listed in `unsafe-crates.txt`, and Miri runs its tests; a C engine
    (LMDB) would need an ADR and sanitizer runs instead (ADR-005).
12. **Layout** (ADR-012): rows of hot tables are fixed-size and small,
    with sizes asserted in tests; names are interned; iteration is by
    cursor over a key, so a walk survives concurrent commits (Ghidra's
    iterators re-seek on a modification count); no allocation per row in
    scans or bulk inserts.
13. **Ghidra's processor and feature data are read in place** (ADR-002,
    extended as proposed in the track report): `.opinion`, pattern files,
    `Ghidra/Features/Base/data` (no-return lists, ordinal tables, the
    string model), and the `.gdt` archives.
14. **Analysis improvements live in a profile**, as the decompiler's do
    (ADR-025). The `ghidra` analysis profile is Ghidra's analyzers in
    Ghidra's order with its sequential semantics, and is what the oracle
    is compared with, permanently. Parallel scheduling and better
    analyzers are another profile, accepted by equal results or by a
    documented difference.

How each crate meets the engineering rules:

| Crate | Data layout | Concurrency | Hot paths and their benchmark |
|---|---|---|---|
| `bk-addr` | Range sets as sorted vectors of (start, end); no tree of boxed nodes | Immutable sets are `Send + Sync` | Union, intersection, "contains" over 1 million ranges |
| `bk-store` | Typed tables over the chosen engine; fixed-size keys | Snapshots for readers, one writer | The six budgets of 3.2 |
| `bk-memory` | Blocks in a sorted vector; bytes in pages | Reads from a snapshot | Byte reads per second through the block lookup; import of a 100 MB image |
| `bk-datatypes` | An arena of types with `DataTypeId` indices; interned names and category paths | The manager's read side is `Send + Sync`; per-function overlays as `bk-decomp-types` has | Resolve (conflict check) of 100,000 types; layout of a 10,000-member structure |
| `bk-refs`, `bk-symbols`, `bk-listing`, `bk-functions` | Rows keyed by address or id, secondary indexes as tables | As the store | "Code unit containing", references to, symbol by name, 10 million inserts |
| `bk-loader*`, `bk-reloc-*` | Parsers borrow the file; relocation tables are static data | A load is single-threaded and deterministic | Import time and peak memory per megabyte |

### 3.1 The storage decision (ADR-003): state and proposal

**What the paused spike has** (`../store-spike`, branch `store-spike`,
read by this track):

* The workload section of `docs/research/storage-engine.md` (182 lines):
  Ghidra's tables and keys, row counts from a real 12.7-million-instruction
  binary, access patterns, and Ghidra's transactions and undo, each
  claim marked measured, read in source, or judgement. Its main
  conclusion holds for every engine: because readers must see analysis
  progress, analysis commits many times, so **undo cannot be the
  engine's rollback; it is a layer above the engine** (constraint 4).
* A benchmark crate (`tools/store-spike/`, about 2,800 lines) that drives five
  engines through one ordered-table interface (`src/engine.rs`): LMDB
  through `heed`, `redb`, SQLite through `rusqlite`, `fjall`, and an
  in-memory `BTreeMap` with a write-ahead log. Phases: bulk load, reopen,
  scan, listing page, point reads, rollback, undo, bulk load with an
  undo log, mixed readers and writer, and a crash test.
* **Results exist only as an uncommitted file** of an aborted first run
  (`tools/store-spike/target/results/aborted-first-run.tsv`, on a Mac
  under load averages of 5 to 8). They are indicative only. At 10 million
  instructions (16.7 million rows): LMDB loads 0.84 to 1.23 million
  instructions a second, file 0.9 to 1.4 GB, resident memory 0.6 to
  1.3 GB, full scan 98 million rows a second, seek plus 100 rows 3.9 µs,
  "function containing" 0.31 µs, a 500-row edit transaction with a full
  flush 6 ms, readers unaffected by a writer (4.7 µs alone, 4.9 µs
  beside commits); `redb` loads 0.21 to 0.43 million a second with
  commits of 1.0 to 2.6 s; the in-memory baseline loads 1.5 million a
  second and uses 3.6 GB. SQLite and `fjall` were not run at this size.
  **This file lies under a build directory, which the disk-cleanup rule
  deletes; it should be copied out and committed.**
* Not done: the full matrix on an idle machine, the crash and
  concurrency experiments, the fit to requirements, the recommendation
  and the ADR-003 revision (its status file lists these as "Next").

**Proposal.**

1. The decision is **two decisions**, and only the first blocks other
   work. (a) The **table interface** of `bk-store`: typed ordered
   tables, point read, "greatest key at or below", range scan in both
   directions, range delete, snapshots, one write transaction, the
   change log. It can be fixed now from the spike's `engine.rs` and
   section 1.3 of the study, and every area crate is written against
   it. (b) The **engine** behind it, decided by the finished spike.
2. The spike is resumed as it is (its agent's context is kept), runs
   its matrix on the build host as well as the Mac, and adds one
   candidate the workload suggests: a store that keeps the hot tables in
   memory in a compact typed form (10 million instructions are 160 MB as
   16-byte rows) with copy-on-write snapshots, a durable log and
   checkpoints. It must say for each candidate whether it meets "memory
   bounded by working set" (ADR-003) at 100 million instructions.
3. Until (b) is decided, tracks test against an in-memory implementation
   of the interface that `bk-store` ships anyway for tests. No area
   track waits for the engine.

### 3.2 Budgets (proposed for `PERF.md`; to be set by the finished spike and the oracle's timings)

| Budget | Proposed figure | Basis |
|---|---|---|
| Bulk insert of 10 million instructions with references (16.7 million rows), durable at the end | 15 s or less, one writer | Spike, partial: LMDB 8.2 to 11.1 s on a loaded Mac |
| Code unit containing an address, warm | 1 µs or less at the median; 1 million lookups a second a thread | Spike, partial: 0.31 µs |
| A listing page (seek and 100 rows) | 10 µs median, 50 µs at the 99th percentile | Spike, partial: 3.9 and 6.6 µs |
| Address-ordered scan | 50 million rows a second | Spike, partial: 98 million |
| References to an address; symbol by name | 2 µs each | Spike, partial: 1.2 to 1.5 µs |
| Undo or redo of a user edit (about 500 row changes), durable | 10 ms | Spike, partial: 6.6 to 7.0 ms |
| Undo of a whole analysis | **Open** (constraint 4) | — |
| Reader latency while a writer commits | Within twice the idle figure at the 99th percentile | Spike, partial: 14 µs idle, 21 µs |
| Import (no analysis): time | No slower than Ghidra's import of the same file on the same host, measured by the oracle run; and 50 MB of mapped bytes a second | The absolute figure is a proposal, not measured |
| Import: peak resident memory | Three times the file size plus 256 MB | A proposal, not measured |
| Stored size | 100 bytes an instruction, all tables | Spike, partial: 90 to 139 |
| Open a 10-million-instruction program and show a listing page | 200 ms and 200 MB resident | A proposal; the spike's reopen phase measures it |

## 4. How parity is measured

Ghidra's loaders have next to no tests, so "the ported tests pass" says
little. As in the decompiler plan, parity is measured at levels and a
track's acceptance names the levels it must pass.

| Level | Compared with Ghidra | Tool | Catches |
|---|---|---|---|
| P0 | Ghidra's unit tests, ported; programs built in test code | `cargo test`, the program builder | A wrong component |
| P1 | **Tables**: pure functions evaluated by Ghidra over many inputs (data-type layout under each data organisation, relocation arithmetic, address-set operations), checked in and replayed | `cargo test` (replay); regeneration needs the oracle | Behaviour no unit test pins |
| P2 | **The program after import** (`-noanalysis`), section by section | program dumps (4.2) | A wrong loader or relocation handler |
| P3 | **State after one analyzer**, starting from Ghidra's state before it | dumps and state loading (4.4) | A wrong analyzer, in isolation |
| P4 | The program after default analysis with a stated set of analyzers switched off in both tools | dumps | Scheduling and interaction of analyzers |
| P5 | The program after Ghidra's default analysis, nothing switched off | dumps | Everything, including the decompiler's analyzers (needs M3) |

### 4.1 The reference: Ghidra headless on the build host (track `ref-headless`, P00)

* **Build.** A copy of the pinned tree is built on the build host with a
  JDK 21 and Ghidra's Gradle wrapper (`decomp-oracle.md` 4.13: fetch
  dependencies, `buildGhidra`; about 10 GB of disk). The unpacked
  distribution goes beside the other reference tools; a stamp records
  the commit and the script hashes. It is not built on the Mac. Nothing
  in `../ghidra` changes.
* **Run.** `support/analyzeHeadless <project dir> <name> -import <file>
  [-processor <id>] [-cspec <id>] [-loader <name>] [-noanalysis]
  -preScript … -postScript BkDumpProgram.java <out dir> -deleteProject
  -max-cpu 1` (options read from
  `BASE/app/util/headless/AnalyzeHeadless.java`). One core, so that
  Ghidra's own thread pool cannot reorder work; every capture is taken
  twice and the two must be identical before it is trusted (the rule of
  `decomp-oracle.md` 4.11).
* **The exporter** is a Ghidra script in Java,
  `tools/reference/ghidra/BkDumpProgram.java`, with
  `BkSetAnalyzers.java` (a pre-script that sets the `Analyzers.<name>`
  options: `BASE/app/plugin/core/analysis/AnalysisScheduler.java:152`,
  `BASE/app/script/GhidraScript.java:1448`) and `BkRunAnalyzer.java`
  (4.4). They use only public API. **Unverified until run:** that
  headless compiles Java scripts with the JDK alone on the host, and the
  time of a run (it starts a JVM per file unless one invocation imports
  a directory, which `-import <dir> -recursive` allows).
* **`bk-testkit`** gets a `GhidraHeadless` tool entry (the enumeration
  was left open for it), a runner that skips with a printed reason when
  the distribution is absent, and typed readers for every section.

### 4.2 The program dump, format version 1

A Basilisk-defined, versioned, line-oriented text format; one file per
section, gzip-compressed (`*.gz` is binary in `.gitattributes`);
documented in `tools/reference/README.md`. Rules: UTF-8 with escapes for
control characters and separators; every section sorted by its key;
**no Ghidra ids, no host paths, no time stamps, no random identifiers**
(data-type universal ids are excluded); addresses printed as
`space:offset`; a header naming the format version, Ghidra's commit, the
language and compiler-spec ids, the loader and its options, and the
analyzers enabled.

| Section | One row per | Key | Fields |
|---|---|---|---|
| `info` | program | — | Executable format, image base, language, compiler spec, address range, the "Program Information" options, hashes of the input file |
| `spaces` | address space | name | Kind, size, overlay base |
| `memory` | block | start | Name, length, permissions, flags (volatile, artificial, overlay), type, initialised, source (file offset, byte- or bit-mapped), comment, SHA-256 of the bytes |
| `bytes` | initialised block | start | The bytes, hex, 32 a line (so a relocation difference shows as a line) |
| `symbols` | symbol | address, namespace path, name | Kind, source, primary, pinned, entry point, external |
| `namespaces` | namespace, class, library | path | Kind, body ranges |
| `externals` | external location | library, label | Address, original import name, kind |
| `relocations` | relocation | address, order | Type, status, values, length, symbol name, original bytes |
| `functions` | function | entry | Name, namespace, body ranges, calling convention, return and parameters with storage, locals with storage and first-use offset, flags (thunk and its target, no return, inline, varargs, custom storage), stack purge, signature source, tags |
| `references` | reference | from, operand, to | Type, source, primary, the stack, register and external forms, associated symbol |
| `datatypes` | data type | category path and name | Kind, length, alignment, members with offsets and bit fields, enum values, base type, signature, settings, source archive name |
| `codeunits` | instruction or defined data | address | Length; for an instruction its bytes, mnemonic and operand text, flow override, fall-through, context value; for data its type path and value text |
| `comments` | comment | address, kind | Text |
| `bookmarks` | bookmark | address, type, category | Comment |
| `equates` | equate | name | Value, the (address, operand) uses |
| `properties` | property value | map name, address | Value |
| `context` | register value range | register, start | End, value |
| `trees` | program-tree node | tree, path | Fragment ranges |
| `sourcemap` | source-map entry | address | File, line, length |
| `options` | option | path | Value (analysis options and the others stored in the program) |
| `log` | import or analysis message | order | Text |

Basilisk writes the same format from its own program (`basilisk dump`;
the writer is `bk-program`'s). Comparison is per section: equal bytes,
or a report of the first differing key and a count per category. The
categories follow Ghidra's own program comparison
(`BASE/program/util/ProgramDiffFilter.java`), so the report can be read
beside Ghidra's Diff tool. A tolerated difference is named in the test
by section and key pattern with its reason (ADR-007); nothing is
tolerated by loosening the comparison.

A second, independent channel once the XML exporter exists (P39):
Basilisk's XML is imported into Ghidra with its `XmlLoader` and dumped.

### 4.3 The corpus (track `corpus`, P01)

Ghidra's tree gives none (fact 2), so the corpus is built, with a
manifest (`fixtures/corpus/MANIFEST.toml`: file, SHA-256, how it was
produced, licence) and a build script per group. Large files are not
committed: the manifest and the build script are, and the build host
keeps the files.

| Group | Source | Covers |
|---|---|---|
| Hello-level programs | `Ghidra/Test/TestResources/src/cpp/{helloWorld,decomp}` and the research corpus's sources, built with GCC and Clang for ELF (static, dynamic, PIE, shared object, relocatable object), MinGW for PE, Clang on the Mac for Mach-O | Each loader's main paths |
| One binary per processor | `Ghidra/Extensions/SleighDevTools/pcodetest/c_src` (6,483 lines of C, Ghidra's own p-code tests) built with cross toolchains on the build host | Every ELF relocation handler and extension; later the 126 emulator tests |
| Damaged files | The eleven damages of the `bin-elf` experiment and the PE ones of `spec-pe`, applied to group 1 | Tolerance: what Ghidra keeps of a broken file |
| Real-world samples | System libraries and tools of the build host's distribution and of the Mac, named by package and version in the manifest, not committed | Scale; the 10-million-instruction budget |
| Ghidra's own archives | The 16 `.gdt` files, in place | Data types (P1 tables) |

**Unverified:** which cross toolchains the build host's distribution
packages (the p-code tests name their own, `pcodetest/defaults.py`);
MSVC-built PE files need a Windows toolchain whose licence allows no
committing (`cargo-xwin` is allowed locally, `DIRECTION.md`). Cost of a
full capture: unknown until P00 runs; the plan assumes minutes per
hundred small files and budgets a nightly slot.

### 4.4 State loading

The dump holds a program's whole analysis state, and Basilisk has the
input file. So **a dump can be loaded**: import the file, then replace
every section's content by the dump's. With that, as in the decompiler
plan, a pass is accepted from Ghidra's state before it:

* `BkRunAnalyzer.java` takes a program in a known state, switches every
  other analyzer off, runs one analyzer once over the whole program
  (`AutoAnalysisManager.scheduleOneTimeAnalysis`,
  `BASE/app/plugin/core/analysis/AutoAnalysisManager.java:226`) and
  dumps before and after.
* Basilisk loads the "before" dump, runs its analyzer, and is compared
  with "after" (level P3).

**Unverified until run:** that one-time analysis with the others off
runs exactly that analyzer and nothing triggered by its changes. The
dump loader is `bk-testkit`'s and is itself checked by a round trip:
load a dump, write it, compare bytes — which also proves the model can
hold everything Ghidra's does.

### 4.5 Where checks run; gate and nightly

Kinds as in `decomp-plan.md` 4.5: **S** self-contained (ported tests,
replays of checked-in tables and small dumps), **G** needs the Ghidra
tree (`.gdt` archives, opinion and pattern files), **L** needs the live
oracle. No track's acceptance rests on L alone. The gate runs S and G;
nightly regenerates the captures twice, requires them identical, and
reports drift against the checked-in ones.

### 4.6 Checked by ported tests only

Transactions, undo and redo, events and their batching, options, the
table interface (Ghidra's `DB` tests where they describe behaviour the
interface has), address sets, data-type conflict resolution: Ghidra's
unit tests cover these well (sections 1's counts) and a dump of a final
state does not show them.

## 5. Improvements over Ghidra proposed here

Each is a difference to record in the feature document or an ADR; the
`ghidra`-visible result stays the oracle's.

| # | Improvement | Ghidra today (source) | Why better | Parity still measured by |
|---|---|---|---|---|
| 1 | Snapshot reads, one writer | One read/write lock per call; readers see uncommitted writes | The interface and parallel decompilation never block or see half a change; ADR-044 comes free | Final-state dumps; ported transaction tests |
| 2 | Logical change log as undo, change set and event source | Three mechanisms (`BufferMgr` page versions, `ProgramDBChangeSet`, `DomainObjectChangeSupport`) | One record of truth; undo survives save; a crash loses a batch, not five minutes or a whole analysis | Ported undo and event tests |
| 3 | Ids never reused | Maximum key plus one, restored by undo (`DB/Table.java:605`) | A stale handle is detected, never aliased (constraint 3) | Not visible in dumps |
| 4 | Address-ordered keys in every space | Order only inside a 4 GiB segment (`AddressMapDB.java:51`) | Range scans need no key-range list; no 16 GiB limit (`SM/program/model/mem/Memory.java:89`) | Dumps |
| 5 | A reference is a row, in both directions | One packed blob per address, rewritten on each add; a table of its own at 1,700 references (`SM/program/database/references/RefList.java:29`) | No rewrite, no threshold; "references to" is a prefix scan | `references` section |
| 6 | Parsers separate from program construction; loaders against `LoadTarget` | Format classes build data types and mark up the program (156 of 230 PE files import the type model) | Parsers fuzzable and reusable; loaders testable without a store | P2 dumps |
| 7 | Typed load diagnostics; a damaged file yields a partial program | Exceptions and a string log | ADR-009; the tolerance rules become testable | `log` section, damaged-file corpus |
| 8 | Analysis profiles; deterministic parallel analysis as a profile | One analysis thread; a shared pool used by some analyzers | Speed without losing the oracle | P4 and P5 on the `ghidra` profile; equal results for the other |
| 9 | State loading from the oracle's dump | Ghidra cannot be handed a state except as its own project file | Analyzers accepted in isolation and in parallel | P3 |
| 10 | The oracle's dump as a public, versioned, diffable text export | XML export omits instructions and is not sorted for comparison | Users can diff two analyses; regression tests of user projects | — |

Not proposed, because the evidence is missing: changes to what loaders
or analyzers *decide*. Those wait for measured parity, as ADR-004 says
for the decompiler.

## 6. Tracks (M4)

Size is Java main lines of the Ghidra code the track ports, measured
unless marked: **S** under 4,000, **M** 4,000–9,000, **L** 9,000–13,000
(the decompiler plan's classes scaled by the 0.8 Java-to-Rust ratio of
`roadmap-check.md` 7). Tracks above L are split or marked to split.
"Oracle" is the highest level the track is accepted at.

| Id | Track | Crates owned | Ghidra code | Size | Needs merged | Oracle |
|---|---|---|---|---|---|---|
| P00 | `ref-headless` | `tools/reference/ghidra/*`, the reference build script's Ghidra target, `bk-testkit` (runner, dump readers) | — (tooling) | M | — (leaf) | — |
| P01 | `corpus` | `fixtures/corpus/`, build scripts, toolchain set-up on the build host | — | S–M | — (leaf) | — |
| P02 | `store-spike` (resumed) | `tools/store-spike/`, `docs/research/storage-engine.md` | `DB/` read for behaviour | — | — (leaf) | — |
| P03 | `task` | `bk-task`; the move out of `bk-ui` | `Framework/Utility/…/task/TaskMonitor.java` | S | — (leaf; touches `bk-ui`) | P0 |
| P04 | `sleigh-language` | `bk-language`, additions to `bk-sleigh` | `features/sleigh-language.md` (a draft) | L (unmeasured) | — (leaf) | its own spec |
| P10 | `addr` | `bk-addr` | `SM/program/model/address` | M (8,875) | — (leaf) | P0, P1 |
| P11 | `store` | `bk-store` | `DB/` (interface behaviour), the change log | L (design, not a port) | P02's interface decision | P0 |
| P12a | `memory-map` | `bk-memory` (address keys, image base, overlay spaces) | `SM/program/database/map`, `OverlaySpaceDBAdapter*` | S (3,785) | P10, P11 | P0 |
| P12b | `memory` | `bk-memory` (blocks, file bytes, byte access), after P12a | `SM/program/database/mem`, `SM/program/model/mem` | L (10,368) | P12a | P0, P2 |
| P13a | `datatypes-builtin` | `bk-datatypes` (the type trait, 132 built-in types, value reading and representation, settings) | `SM/program/model/data/*DataType.java` under `BuiltInDataType` | above L (15,197): **to split by family in its spec** | P10 | P0, P1 |
| P13b | `datatypes-composite` | `bk-datatypes` (structures, unions, packing, bit fields, enums, typedefs, pointers, arrays, function definitions), after P13a | the rest of `SM/program/model/data` (24,814 with interfaces and utilities) | above L: **to be planned** — the split needs per-class sizes not yet measured | P13a | P0, P1 |
| P13c | `datatypes-manager` | `bk-datatypes` (categories, resolution and conflicts, source archives, persistence) | `SM/program/database/data` (28,845 including old adapters), `dtarchive` | above L: **to be planned** as above | P13b, P11 | P0, P2 |
| P13d | `cparser` | `bk-cparser` | `BASE/app/util/cparser` and the JavaCC grammar | M (8,303) | P13b | P0 |
| P13e | `ghidra-db` | `bk-ghidra-db` (read-only reader of packed databases; `.gdt` into `bk-datatypes`) | `DB/` read path, `Ghidra/Framework/FileSystem/…/store/db/PackedDatabase.java`, the current data-type adapters | **to be planned**: needs a reading of the buffer-file and node formats | P13c (reader core: `bk-bin` only) | G: all 16 archives |
| P14 | `refs` | `bk-refs` | `SM/program/database/references` | M (5,493) | P11, P12a | P0, P2 |
| P15a | `symbols` | `bk-symbols` (symbols, namespaces, labels, dynamic names) | `SM/program/database/symbol` without equates, `SM/program/model/symbol` | above L (20,061 with the equate classes, whose share is not measured): **to split in its spec** | P12b, P14 | P0, P2 |
| P15b | `symbols-ext` | `bk-symbols` (equates, external locations and libraries), after P15a | `SM/program/database/external`, the equate classes | S | P15a | P0, P2 |
| P16a | `listing` | `bk-listing` (instructions, data, comments, iteration) | `SM/program/database/code` | L (10,667) | P04, P12b, P13b, P14 | P0, P2 |
| P16b | `listing-maps` | `bk-listing` (property maps, bookmarks, relocation table, source map, program trees), disjoint modules | `SM/program/database/{properties,bookmark,reloc,sourcemap,module}` | L (12,379; simple tables, can be two tracks) | P11, P12a | P0, P2 |
| P16c | `context` | `bk-listing` (register values, the program context) | `SM/program/database/register`, context classes of `SM/program/util` | S | P04, P12a | P0, P2 |
| P17 | `functions` | `bk-functions` | `SM/program/database/function` | M (7,659) | P15a, P16a, P13c, `bk-cspec` | P0, P2 |
| P18a | `program-core` | `bk-program` (handle, transactions, undo, events, options, snapshots) | `PROJ/data/DomainObject*`, the transaction managers, `PROJ/model`, `SM/program/database/ProgramDB.java` | M (about 7,000) | P11, P12b | P0 |
| P18b | `program` | `bk-program` (assembly of the managers, cross-area rules, the dump writer and loader), after P18a | the rest of `SM/program/database/*.java`, `util`, `ProgramDBChangeSet` | M | P14–P17 | round trip of dumps |
| P19 | `program-builder` | `bk-testkit` (builders in the role of `ProgramBuilder` and the sample builders) | `BASE/program/database/ProgramBuilder.java`, `BASE/test` builders | S | grows with P12b–P18b | — |
| P20 | `cmd` | `bk-cmd` (labels, references, data, memory, comments, format markup) | the matching packages of `BASE/app/cmd` | M (about 7,700) | P18b | P0 |
| P30 | `loader-core` | `bk-loader` | `BASE/app/util/opinion/{Loader,LoadSpec,LoaderService,AbstractProgramLoader,AbstractLibrarySupportLoader,MemorySectionResolver,Library*}.java`, `BASE/app/util/importer` | M–L (about 8,500, estimated from the named files) | P10; `bk-lang` (opinions) | P0 |
| P31 | `loader-raw` | `bk-loader-raw` (binary, Intel hex, Motorola hex) | `BinaryLoader`, `IntelHexLoader`, `MotorolaHexLoader` and their record readers | S (1,166 + readers) | P30 | P2 |
| P32 | `loader-elf` | `bk-loader-elf` | `ElfProgramBuilder` (3,821), `ElfLoader`, the data-type layouts of `format.elf` not in `bk-elf`, `relocation` and `extend` base classes | L | P30, P13b; acceptance on the program needs P18b | P2 |
| P33a–c | `reloc-elf-*` | `bk-reloc-*`, three groups of processor families | 22 handlers with their type tables and contexts, 13 extensions | 11,769 + 3,465 in three tracks of M each | tables: `bk-elf` only (leaf); application: P32 | P1, P2 |
| P34 | `pe` | `bk-pe` | `BASE/app/util/bin/format/pe` (parsing share), `mz`, the paused `spec-pe` fact sheets | above L (32,463 with markup): **to split in its spec** | — (leaf) | `bin-elf`'s method: crate oracle, damaged files |
| P35 | `loader-pe` | `bk-loader-pe` | `PeLoader` (1,121), `AbstractPeDebugLoader`, `AbstractOrdinalSupportLoader`, PE markup | L (estimated) | P34, P30, P13b | P2 |
| P36 | `macho` | `bk-macho` | `BASE/app/util/bin/format/macho` (parsing share) | above L (18,530): to split | — (leaf) | as P34 |
| P37 | `loader-macho` | `bk-loader-macho`, `bk-reloc-macho` | `MachoProgramBuilder` (1,846), `MachoLoader` (675), 5 handlers (911) | M | P36, P30, P13b | P2 |
| P38 | `import` | `bk-headless` (import), `basilisk import`, `basilisk dump` | `AutoImporter`, `ProgramLoader`, the import half of `HeadlessAnalyzer` | S | P18b, one loader | P2 on the whole corpus |
| P39 | `export` | `bk-export` | binary, Intel hex, ASCII exporters; `BASE/app/util/xml` | M (about 8,900) | P18b | Round trip; XML through Ghidra |
| P40 | `ui-program` | `bk-ui-program` | — (adapter for `ProgramSource`) | S | P18b | `egui_kittest` on an imported program |

Not in M4: COFF, OMF, NE, MZ, PEF, SOM, XCOFF and a.out loaders, the
DYLD cache (M10, as `PLAN.md` has them; `bk-loader`'s traits are
written for them); the file-system layer beyond what `bk-loader` needs
to open a file (**to be planned**: `BASE/formats/gfilesystem`, 9,252
lines; the importer and 11 of the 31 byte-provider files import it);
language translation of old programs (M8).

### 6.1 Waves

A wave is an ordering, not a head count.

| Wave | Tracks | Why here |
|---|---|---|
| **A — now** | P00, P01, P02, P03, P04, P10, P13a, P34, P36, the table halves of P33a–c | Leaves: they need only what is on `master` |
| B | P11, P13b, P30, P31 (against the recording target) | The store interface is fixed by then; data types continue; loader core needs only addresses |
| C | P12a, P12b, P13d, P16b, P18a, P32 (against the recording target) | Memory; the simple tables; transactions and undo on memory |
| D | P14, P15a, P13c, P16c | References and symbols need memory |
| E | P15b, P16a, P13e | Code units need `sleigh-language`, data types and references |
| F | P17, then P18b, P19 complete | Functions; then the program is whole |
| G | P20, P32/P35/P37 accepted on the program, P33 application, P38, P39, P40 | Everything that needs a whole program |

### 6.2 The critical path and the width

**The long pole is the model chain:** P02 (interface) → P11 → P12a →
P12b → P15a → P16a → P17 → P18b → loader acceptance at P2. Eight tracks
in a row, three of them L. `sleigh-language` (P04) joins it at P16a and
has to be finished by then. More agents do not shorten this chain.

**The width is beside it.** Able to run at once without touching each
other: in wave A ten tracks; from wave B on, the chain (one), data types
(one, sequential inside `bk-datatypes`), loaders against the recording
target (three to four: raw, ELF, PE, Mach-O), relocation families
(three), parsers (two), the simple tables (one or two), the oracle and
corpus (two). So the honest figure is: **the chain uses one slot, and
six to ten more can be used productively through M4** — plus M5's
leaves (section 9) and the readers and demanglers of M6.

What shortens the chain itself: the recording `LoadTarget` (loaders do
not wait for the model), the dump loader (analyzers do not wait for
loaders), and P18a before the managers (transactions and undo are
tested on memory alone).

### 6.3 What can start now

P00, P01, P02 (resume), P03, P04, P10, P13a, P34 (resume `spec-pe`),
P36 and the relocation tables. Specifications needed first, in this
order: `ref-headless` and the dump format (from section 4); `bk-addr`;
the `bk-store` interface; data types (built-ins); `bk-loader` with
`LoadTarget`. `sleigh-language` has a draft whose "to verify" sections
have to be completed.

## 7. Acceptance per track

Stated to the level a specification is written from; each specification
turns these into numbered conditions.

* **P00.** The distribution builds on the build host from a copy and is
  stamped; the three scripts run headless; every section of the dump is
  written for every corpus file with and without analysis; two runs are
  byte-identical (differences found are reported as host or
  order dependence, as D00 did); readers parse every section, with unit
  tests on checked-in samples (S); the format is documented and
  versioned; run time per file and for the corpus is recorded.
* **P01.** A manifest and a build script per group; the build host
  builds groups 1 to 3 from nothing; each file's hash is recorded.
* **P02.** The study's remaining sections, on the build host and the
  Mac; the interface proposal; the ADR-003 revision.
* **P10.** The 12 test classes (141 tests) ported (S); a table of set
  operations from Ghidra over generated range sets (P1); the benchmark
  of section 3.
* **P11.** The interface's behaviour tests, including those of `DB`'s
  17 classes that apply (ADR-003 names which do not); snapshot
  isolation under a writer; crash safety by a kill test; the budgets of
  3.2 measured into `PERF.md`.
* **P12–P17.** The area's Ghidra tests ported with the builder (S),
  each classified by what it checks, not by the checklist's GUI flag;
  its dump sections written and loaded with a round trip of the corpus
  dumps (S subset, L all); its hot-path benchmark.
* **P13a–e.** The 61 classes (982 tests) divided between them; P1
  tables of size, alignment and component offsets for generated
  composites under the data organisation of every `.cspec`, from
  Ghidra; for P13e every type of the 16 archives read and equal to
  Ghidra's dump of the same archive (G replay).
* **P18a.** Ghidra's transaction, undo and option tests (17 classes,
  274 tests in `framework.data`, `options`, `model`), those that apply;
  the binding constraints 3, 6, 7, 9, 11 and 13 each shown by a test.
* **P18b.** Round trip of every corpus dump: load, write, byte-equal.
* **P30–P37.** P2: every section of the dump equal to Ghidra's for
  every corpus file of the format, with named exceptions only; for the
  damaged files, the same partial program and log; fuzz targets and
  "never panics" property tests for whatever parses bytes (ADR-009);
  import time and peak memory against Ghidra's on the same host.
* **P33.** P1: each handler's arithmetic against a table (**to be
  planned**: how the table is produced from Ghidra — by a script that
  drives the handler on synthetic inputs, or only through P2 on the
  per-processor corpus); P2 on group 2 of the corpus.
* **P38.** `basilisk import` then `basilisk dump` equals the oracle for
  the whole corpus in one command, in the nightly run.
* **P39.** Export, re-import, equal dumps; Ghidra imports Basilisk's
  XML and its dump equals Ghidra's own, with named exceptions.
* **P40.** The interface opens an imported program; the listing, memory
  map, symbol tree and references views are fed by snapshots off the
  interface thread.

## 8. Things other tracks and the coordinator must provide

* **The build host** gets a JDK 21, the Ghidra build (10 GB) and cross
  toolchains. Nothing needs root except package installation.
* **`bk-ui`** gives up its monitor to `bk-task` (P03) and, for P40,
  keeps `ProgramSource` as it is.
* **`bk-core`** may need additions for overlay and segmented spaces
  (P10's specification says which); `Provenance` gains the mapping from
  Ghidra's `SourceType`.
* **`bk-elf`** is asked for what the loader needs and it does not
  expose yet (the `bin-elf` report lists GNU build attributes and
  data-type layouts as not ported).
* **The decompiler tracks** are not touched. `bk-decomp-host` (M5) is
  where D06's `ProgramHost` meets the program.
* **The spike's partial results** are copied out of
  `../store-spike/tools/store-spike/target/results/` before any disk
  clean-up.

## 9. M5 at track level

Sizes measured (`roadmap-check.md` section 2); this table is an outline,
**to be planned** in detail when M4's wave C is specified.

| Id | Track | Ghidra code | Size | Needs | Oracle |
|---|---|---|---|---|---|
| A01 | `disasm-core`: flow following into instruction blocks over bytes, context along paths | `SM/program/disassemble` | S (3,669) | P04 only — **can start in M4's wave B** | Ghidra's `pseudoDisassembleBlock` driven by a script on raw bytes; later P3 |
| A02 | `disasm-program`: storing instruction sets, conflicts, bookmarks for bad instructions, the disassemble commands, `basilisk disasm` (ADR-047) | `CodeManager.addInstructions`, `BASE/app/cmd/disassemble` (1,264) | S | A01, P16a | P3 |
| A03 | `blocks`: basic-block and subroutine models | `SM/program/model/block` | M (6,789) | P16a, P14 | P1 tables |
| A04 | `cmd-function`: create function, body, thunks, stack analysis commands | `BASE/app/cmd/function` | M (7,531) | P17, A02, A03 | P3 |
| A05 | `symprop`: symbolic propagation over p-code | `BASE/program/util/{SymbolicPropogator,VarnodeContext}.java` | M (5,206) | P04, P16a | P3 through its analyzers |
| A06 | `analysis`: the manager, scheduling, options, the analyzer trait, analysis profiles (constraint 14, binding constraint 9) | `BASE/app/plugin/core/analysis/{AutoAnalysisManager,AnalysisScheduler,AnalysisTaskList}.java`, `BASE/app/services/Analy*.java` | S (about 2,900) | P18b, P20 | P4 with an empty and a one-analyzer set |
| A07–A1x | analyzers by family, one crate each: entry points and thunks; references (operand, scalar, data, address tables); constant propagation and the 13 processor analyzers built on it; function starts and byte patterns (`BytePatterns`, `bytesearch`); no-return and call fixups; stack; strings; demangler analyzers; GCC exception tables; format analyzers; `ApplyDataArchiveAnalyzer` (needs P13e) | `analyzers.tsv` (133 classes, 36,582 lines) and what they call | each S or M | A06 and the commands; each accepted alone | P3, then P4 |
| A20 | `decomp-host`: `ProgramHost` and `TypeSource` over a snapshot; overlays committed by the writer in a deterministic order (ADR-044) | `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler` (9,292), `SM/program/model/pcode` (18,039) | L, to split | D06, D17, P13c, P15a, P16a, P17 | Decompiler output on programs against Ghidra's `DecompInterface` (the oracle script gains a section) |
| A21 | decompiler analyzers: switch recovery, parameter identification, calling-convention identification | the three analyzers (966) and `DecompilerParameterIdCmd` (in 1,141) | S | A20, D13, D17 | P5 |
| A22 | `analyze`: `basilisk analyze`, whole-program runs | `BASE/app/util/headless` (4,222) | M | A06 | P4, P5 |

**What M5 needs from `sleigh-language`:** registers and register values
(P16c, A05), instruction prototypes with flow type, fall-through,
delay-slot depth and operand classification (A01), p-code under
overrides (A05, A20), compile on demand (import of any language).
**From the decompiler:** switch recovery (D13) and the driver (D17) for
A21; the `paramid` root action for parameter identification; nothing
else in M5 needs M3. Until then P4 runs with `Decompiler Switch
Analysis` and `Call Convention ID` off in both tools.

## 10. For the coordinator

### 10.1 To confirm (proposed ADRs are numbered in the track report)

1. The crate tree of section 2 in place of `PLAN.md`'s `bk-program`,
   `bk-datatypes`, `bk-store`, `bk-loader*`; the rule "area crates own
   tables, `bk-program` owns cross-area effects".
2. The storage decision split into interface (now) and engine (after the
   spike), and the spike's added candidate.
3. Logical change log as undo, change set and events; snapshot reads.
4. The program dump as the oracle's format and as a product feature
   (`basilisk dump`); state loading.
5. Reading Ghidra's packed databases read-only (`.gdt`, `.fidb`), which
   narrows ADR-003's "does not read … packed-database formats".
6. ADR-002 extended to `Ghidra/Features/*/data`.
7. Loaders against `LoadTarget`.
8. Analysis profiles.
9. The size classes for Java used here.

### 10.2 To confirm with the owner

1. **Is reading `.gdt` and `.fidb` acceptable** given "does not read or
   write Ghidra projects"? Without it default analysis differs from
   Ghidra's on every binary that calls a C library.
2. **The corpus**: may real-world binaries from the build host's
   distribution be used by name and hash without committing them? May
   MSVC-built samples be built with `cargo-xwin` and kept on the build
   host only?
3. **A C storage engine** (LMDB) is the fastest candidate in the partial
   numbers; it needs an ADR against "pure Rust". Is it acceptable if the
   finished spike still favours it?
4. **Slots**: the programs side can use six to ten agents productively;
   the cap is three. Which of the leaves of wave A go first is the
   coordinator's call; this plan's suggestion is P00, P04 and P10 or
   P13a.

### 10.3 Not done by this plan

* Per-class sizes inside `model.data`, `database.data` and
  `database.symbol`, so three tracks are marked "to split".
* The `LoadTarget` trait's method list; the cross-area rule table of
  `bk-program` (from `deleteAddressRange`, `moveAddressRange` and the
  managers' calls into each other).
* The file-system layer; `SM/program/util` (16,477 lines) class by
  class: which of it is model, which is view vocabulary.
* The analyzers' own dependency order (which analyzer's output another
  reads); M5's table is by family only.
* Anything that needs Ghidra to run: the dump script, timings, the
  one-time-analysis behaviour, toolchain availability.
