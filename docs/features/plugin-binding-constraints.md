# Plugin binding constraints — a checklist for the other specs

For the authors and reviewers of the program model, storage, loader,
analysis, decompiler-host and UI specs. ADR-014 says core APIs are
"shaped from the start so that binding them is direct". This is what that
means in practice: the rules a Rust API must follow so that `bk-plugin`
(`plugin-api.md`) can expose it to Python through PyO3 without a redesign
or a parallel copy of the model. Each item gives the rule, why, a
conforming and a non-conforming signature, and where Basilisk stands
today (files cited; "spec" means a feature document, not yet code).

Scope: the **plugin surface** — what `plugin-api.md` 4.2 and 4.7 expose:
programs and their contents, data types, languages, analysis, loaders,
exporters, decompiler results, UI context, actions and views. Internal
APIs (passes over the decompiler IR, parser internals) are free to borrow
and be generic; the rules apply where the surface reaches them.

Reviewers: a spec that touches the surface should say, per item, "meets"
or "departs, because …".

---

### 1. No lifetimes in types a plugin holds
**Rule.** Every entity reachable from Python is addressed by a shared,
owned program handle plus a stable id (`ProgramHandle: Clone + Send +
Sync + 'static`, `FunctionId: Copy`). Accessors return owned values or
take a closure. Borrowing iterators and views may exist, but never as the
only way in.
**Why.** A `#[pyclass]` must be `'static`; a Python object outlives every
Rust scope, so it cannot hold `&'a Program` or `FunctionRef<'a>`.
**Conforming.**
`fn function(&self, id: FunctionId) -> Result<FunctionInfo, ProgramError>`;
`fn read<R>(&self, f: impl FnOnce(&ProgramView<'_>) -> R) -> R` *plus* id-based accessors.
**Non-conforming.**
`fn functions<'a>(&'a self) -> impl Iterator<Item = FunctionRef<'a>>` as the only access to functions.
**Today.** `bk-ui` `ProgramSource` returns owned rows and pages
(`crates/bk-ui/src/model/source.rs:92-145`) — meets. `bk-core` `Address`
is a `Copy` value without lifetimes (`crates/bk-core/src/address.rs:71`)
— meets; its display adaptors `RawAddress<'m>` and `RangeBounds<'m>`
borrow the `SpaceManager` (`address.rs:417`, `range.rs:194`), which is
fine as long as the program handle reaches the manager through an `Arc`
so the binding can format an address later. The decompiler IR is borrowed
by passes (`features/decomp-ir.md` 5, "Passes hold `&mut Ssa`") —
internal, allowed; see item 6 for its results.

### 2. `Send + Sync + 'static` for everything a plugin can hold
**Rule.** Handles, ids, values and results on the surface are
`Send + Sync + 'static`; shared mutable state sits behind the program's
own locking, not in `Cell`/`RefCell`/`Rc`.
**Why.** PyO3 0.30 rejects at compile time a `#[pyclass]` that is not
`Send + Sync` (`pyo3` `src/impl_/pyclass/assertions.rs:4-8`); the only
escape, `#[pyclass(unsendable)]`, panics when the object is used from
another thread (`src/impl_/pyclass.rs:1108-1129`). Plugin callbacks run
on analysis workers and the plugin
executor (`plugin-api.md` 4.8); free-threaded Python, if adopted,
removes the GIL as an accidental lock.
**Conforming.** `pub struct ProgramHandle(Arc<ProgramShared>)` where
`ProgramShared: Send + Sync`.
**Non-conforming.** `pub struct Program { cache: RefCell<…> }`;
`Rc<Function>`.
**Today.** `ProgramSource: Send + Sync` (`source.rs:92`) — meets;
`SpaceManager` guards its one mutable table with an `RwLock`
(`crates/bk-core/src/manager/mod.rs:70`) — meets; `ByteProvider: Send +
Sync` (`crates/bk-bin/src/provider/traits.rs:23`) — meets;
`CompilerSpec` is `Send + Sync` once loaded (`features/decomp-cspec.md`
5) — meets. The decompiler's per-function `Ssa` is specified `Send` only
(`features/decomp-ir.md` 5, "An `Ssa` owns everything of one function and
is `Send`") — see item 6.

### 3. Identifiers stable across transactions, undo and redo
**Rule.** An entity's id does not change when unrelated things change,
survives commit, rollback, undo and redo, and is not reused for another
entity while a handle to the old one may exist (or carries a generation
so reuse is detected). Lookup by a dead id returns a typed "stale" error.
**Why.** Python handles are ids (item 1); a renamed function, an undone
edit or a script running across many transactions must not make a handle
point at something else.
**Conforming.** `FunctionId(u32)` assigned once; `fn function(&self, id) ->
Result<_, ProgramError>` with `ProgramError::Stale(id)`.
**Non-conforming.** Identifying a variable by its index in the
function's current variable list; reusing a freed slot without a
generation.
**Today.** The decompiler IR keeps destroyed slots so "a stale id never
aliases a new object" (`features/decomp-plan.md` 3.4) — meets inside a
function. `bk-ui`'s `Referent::Variable { function, index }`
(`crates/bk-ui/src/model/token.rs:65`) — departs: an index shifts when a
variable is added; acceptable in the UI's view model, but the program
model must give variables a stable identity (storage plus first-use
address, as Ghidra identifies high symbols) that the adapter and the
plugin API use. `TypeId`s are stable and independent of other functions'
work (`features/decomp-types.md` 4.10) — meets.

### 4. Errors are typed enums that map onto exception classes
**Rule.** Library errors are `thiserror` enums, `#[non_exhaustive]`, one
variant per condition a caller can act on, with structured fields
(address, name, id) and a message. No `anyhow`, `Box<dyn Error>` or
error strings in the surface; no panics (ADR-009).
**Why.** The binding maps each variant to one Python exception class in
a table with a test per row (`plugin-api.md` 4.2); a string cannot be
mapped, and a panic crossing into Python becomes an opaque
`PanicException`.
**Conforming.**
`#[non_exhaustive] enum ProgramError { NoSuchAddress(Address), DuplicateName { name: String, namespace: NamespaceId }, Stale(EntityId), NoTransaction, Cancelled, … }`.
**Non-conforming.** `Result<T, String>`; `anyhow::Result<T>` in a library;
one `Other(String)` variant for every failure.
**Today.** `bk-lang` (`crates/bk-lang/src/error.rs:37-228`) and `bk-elf`
(`crates/bk-elf/src/error.rs:10-12`) — meet. `bk-ui` `SourceError`
(`source.rs:59-82`) mostly meets; its `Rejected(String)` and
`Unavailable(String)` are string catch-alls — tolerable in a view model,
not to be copied into the program model.

### 5. Large collections are counted, paged and resumable
**Rule.** Anything that can be large is reachable by count, by "at most
*n* items after key *k*" returning owned values, and by key lookup; a
walk resumes from its last key after concurrent changes.
**Why.** Python iterators fetch pages with the GIL released and must not
build ten-million-element lists (`plugin-api.md` 4.2), and must survive a
change made between two pages.
**Conforming.** `fn instructions_after(&self, after: Option<Address>, limit: u32) -> Result<Vec<InstructionInfo>, ProgramError>`.
**Non-conforming.** `fn all_symbols(&self) -> Vec<Symbol>`; an iterator
that holds a read lock for its whole life.
**Today.** `ProgramSource` is paged throughout (`listing_rows(start,
count)`, `TableQuery` windows, search limits; `source.rs:96-138`) —
meets. The decompiler IR uses cursors that resume from a key
(`features/decomp-plan.md` 3.4) — the same pattern.

### 6. Results are owned, immutable and keepable
**Rule.** Decompile results, search results, analysis logs and import
results are owned values a caller can keep after the call (`Arc<…>` if
large), readable without access to the engine's working state; any
program-wide data needed to read them (spaces, types, registers) is
reachable through an `Arc` they hold or that the handle provides.
**Why.** Scripts walk `HighFunction`s after decompiling (24 bundled
scripts use the decompiler; `05-extension-points.md` 3), proposers get
the finished result on another thread (`plugin-api.md` 4.7.7).
**Conforming.** `fn decompile(&self, f: FunctionId, mon: &Monitor) -> Result<Arc<DecompileResult>, DecompileError>`
where `DecompileResult: Send + Sync` holds the output tree, the final IR
read-only and an `Arc` to the architecture data.
**Non-conforming.** A result that borrows the driver's arena
(`DecompileResult<'arena>`); accessors that need `&Architecture` passed
in by the caller with no way to obtain it later.
**Today.** `bk-ui`'s `DecompiledFunction` is owned — meets. The
decompiler spec keeps an `Ssa` per function, `Send`, with program-wide
data "borrowed per call" (`features/decomp-ir.md` 5) — **to settle in
D07/D17**: the final `Ssa` and output tree must be movable into an `Arc`
and readable from several threads (`Sync`: no `Cell`-based liveness
checks in the read path), with the architecture reachable through an
`Arc`.

### 7. One monitor type for cancellation and progress
**Rule.** A single `Monitor` type in a low crate — cancel flag, progress,
maximum, message, indeterminate — shared through an `Arc`, checked
without locks; every long operation takes `&Monitor`, checks it at least
every few milliseconds of work, and returns a distinct `Cancelled` error
variant.
**Why.** A script's Cancel must stop the decompile or analysis it is
waiting on; Python's `Monitor` wraps the same object (`plugin-api.md`
4.8 rule 5); Ghidra passes one `TaskMonitor` everywhere
(`Framework/Utility/.../task/TaskMonitor.java:55-209`).
**Conforming.** `pub struct Monitor { cancelled: AtomicBool, progress: AtomicU64, maximum: AtomicU64, message: Mutex<Arc<str>>, … }` in `bk-core` or a new `bk-task`; `fn run(&self, mon: &Monitor) -> Result<_, Error>`.
**Non-conforming.** Each crate with its own progress callback type; a
`FnMut(f32)` progress closure with no cancel; cancellation only by
dropping a future.
**Today.** `bk-ui`'s `task::Progress` has the right shape (atomic cancel
flag and progress, `crates/bk-ui/src/task.rs:77-110`) but lives in the UI
crate, which library crates may not depend on — **move it** to a low
crate (with message and maximum added) before M4/M5 crates define their
own.

### 8. Extension points are object-safe traits with runtime registration
**Rule.** Analyzers, loaders, exporters (and later file systems,
relocation handlers, demanglers) are object-safe traits whose methods
take handles and owned values; registries hold `Arc<dyn Trait>` added at
run time, attributed to an owner so they can be removed. Program change
notifications (kind, address set, entity ids) are available to
subscribers as owned records.
**Why.** A Python class implements the trait through an adapter holding
`Py<PyAny>` (`plugin-api.md` 5.3); plugins are loaded, reloaded and
removed while Basilisk runs; analyzers are driven by change events
(Ghidra's `AnalysisScheduler`, `05-extension-points.md` 4).
**Conforming.** `pub trait Loader: Send + Sync { fn find_load_specs(&self, p: &dyn ByteProvider) -> Result<Vec<LoadSpec>, LoaderError>; … }`;
`fn register(&self, owner: Owner, l: Arc<dyn Loader>) -> RegistrationId`; `fn unregister(&self, id)`.
**Non-conforming.** A closed `enum LoaderKind { Elf, Pe, … }` as the only
registry; registration only at link time (`inventory`, `linkme`); trait
methods generic over `R: Read`.
**Today.** No registry exists yet; `bk-bin`'s `ByteProvider` is already
object-safe and `Send + Sync` (`traits.rs:23`) — meets, and is what a
Python loader's probe reads through.

### 9. The analysis manager can run plugin code safely
**Rule.** The manager (a) can run a task *exclusively* (no other task
writing the same program meanwhile), (b) never holds a program or storage
lock while it calls an analyzer, (c) supports Ghidra's script analysis
modes — `SUSPENDED` (defer change events until a worker finishes) and
`DISABLED` (ignore them) — through an "analysis worker" entry point, and
(d) records per analyzer the added and removed sets it accumulated, so
tests can assert them.
**Why.** Python callbacks serialise on the GIL; calling one with a lock
held deadlocks against a Python thread waiting for that lock
(`plugin-api.md` 4.8 rule 4); `getScriptAnalysisMode` is part of the
flat layer (`GhidraScript.java:168-190,423-455`).
**Conforming.** `fn schedule(&self, task: Task, priority: Priority, exclusive: bool)`;
`fn run_as_worker(&self, mode: WorkerMode, f: impl FnOnce(&Monitor) -> R) -> R`.
**Non-conforming.** Running every analyzer inside one long write lock;
calling analyzers from inside a storage transaction callback.
**Today.** Not specified yet (M5) — a requirement for the analysis spec.

### 10. The UI accepts actions and views at run time and never runs plugin code on its thread
**Rule.** The action registry holds runtime entries with owned strings
and a namespaced string id next to the built-in ones; enablement is
declarative (scope plus facts the shell computes); views can be added at
run time as declarative tables, token text and trees fed by paged
providers called off the UI thread; the layout persists such views by id.
**Why.** Plugins add actions and views while Basilisk runs and remove
them on reload (`plugin-api.md` 4.6, 4.7.5–4.7.6); the UI thread must
not attach to Python (ADR-012, `plugin-api.md` 4.8 rule 2).
**Conforming.** `enum ActionId { Builtin(BuiltinAction), Plugin(Arc<str>) }`;
`struct ActionRegistry { builtin: &'static [Action], dynamic: Vec<DynamicAction> }`;
`enum ViewKind { …, Plugin(Arc<str>) }`.
**Non-conforming.** A closed `ActionId` enum and a `const ACTIONS:
&[Action]` table as the whole registry; a fixed `ViewKind::ALL`.
**Today.** `bk-ui` — **departs**: `ActionId` is a closed enum
(`crates/bk-ui/src/actions/registry.rs:18`), `Action` has `&'static str`
fields (`:198`), the registry is `pub const ACTIONS: &[Action]` (`:224`),
`Scope` has no plugin facts, and `ViewKind` is a closed set
(`crates/bk-ui/src/views/mod.rs:30`). The change is small and must land
in `bk-ui` (owned by the UI track) before track P6 starts; the
`ProgramSource`/`DataClient` pattern is already what declarative views
need.

### 11. Annotations carry provenance, an origin, and what they replaced
**Rule.** Every name, type, comment and signature the user or a plugin
can set records its `Provenance`; edits with `Provenance::Model` also
record an origin (`"<plugin>/<proposer>"`) and the value they replaced;
the model can list and remove edits by origin, restoring replaced values
that were not changed since. Provenance takes no part in identity or
comparison (ADR-028).
**Why.** ADR-025 item 6: proposals are applied with ordinary operations,
"records their provenance and can remove them"; the rank rule needs the
current value's provenance (`plugin-api.md` 4.7.7).
**Conforming.** `fn rename(&mut self, tx: &Tx, sym: SymbolId, name: &str, prov: Provenance, origin: Option<Origin>) -> Result<(), ProgramError>`;
`fn remove_by_origin(&mut self, tx: &Tx, origin: &Origin, scope: Scope) -> Result<usize, ProgramError>`.
**Non-conforming.** Names without provenance; provenance stored only as
Ghidra's `SourceType` with no origin; a model edit that overwrites with no
record of the old value.
**Today.** `Provenance` exists in `bk-core` with `Model` and a trust rank
(`crates/bk-core/src/provenance.rs:16,43`) — meets; origin and replaced
value are **new requirements for the M4 program-model spec**.

### 12. No Rust-only generics in the surface
**Rule.** Functions plugins need are callable with concrete or `dyn`
types: no generic parameters that a Python-implemented object cannot
satisfy, no `impl Trait` arguments as the only form, no const generics or
associated-type puzzles in public signatures; closed sets are enums
(they become Python enums) and are `#[non_exhaustive]` when they grow.
**Why.** PyO3 binds concrete functions; a generic must be monomorphised
for every type the binding passes, and a Python object is only ever a
`dyn` adapter.
**Conforming.** `fn export(&self, program: &ProgramHandle, out: &mut dyn Write, set: Option<&AddressSet>, mon: &Monitor) -> Result<(), ExportError>`.
**Non-conforming.** `fn export<W: Write + Seek, A: AddressFilter>(&self, w: W, a: A)` with no
`dyn` entry; `fn query<Q: Query<Output = R>, R>(…)`.
**Today.** `bk-core`'s `Decoder<'a>`-generic decode functions
(`crates/bk-core/src/address.rs:348`) are internal and not on the
surface — fine.

### 13. Transactions are named, nestable, thread-owned and undoable
**Rule.** Writes require a transaction token; transactions have a name,
nest (the outermost is one undo step with its name), and an inner abort
marks the outermost aborted (Ghidra,
`Framework/Project/.../data/DomainObjectDBTransaction.java:151-163`); a
transaction belongs to the thread that opened it; reads need no
transaction and never see a half-applied write; undo and redo work on
the stack of outermost transactions and are refused while one is open.
**Why.** Scripts are one undoable step that rolls back on error
(`plugin-api.md` 4.9); handles must stay valid across it (item 3).
**Conforming.** `fn transaction(&self, name: &str) -> Result<Tx<'_>, ProgramError>` *and*
an owned form the binding can hold across calls:
`fn begin(&self, name: &str) -> Result<TxHandle, ProgramError>` (`TxHandle: Send`, ended explicitly).
**Non-conforming.** Writes allowed without a transaction; a transaction
type that only exists as a borrow inside a closure (the binding cannot
keep it open across Python statements); undo granularity per write.
**Today.** Not specified yet; ADR-003 fixes "transactions with undo/redo,
one writer with many readers" — the storage and program-model specs
should add the rest.

### 14. Addresses are fully qualified at the boundary
**Rule.** Addresses on the surface are `bk-core` `Address` values (space
plus offset); text forms are parsed and printed through the program's
spaces (`ram:00401000`, `stack[-0x10]`, overlays `IOMEM::0010`).
**Why.** Scripts address stack, register, external and overlay spaces
(`mark_in_out.py` writes into an overlay; `plugin-api.md` 4.5).
**Conforming.** `fn references_to(&self, to: bk_core::Address, …)`.
**Non-conforming.** `struct Address(pub u64)` meaning "default space".
**Today.** `bk-core` `Address` — meets. `bk-ui`'s `Address(pub u64)`
(`crates/bk-ui/src/model/location.rs:22`) is default-space only — fine
for today's view model, but the adapter over `bk-program` must not drop
spaces when the UI hands a location to a plugin (`basilisk.ui.context()`).

### 15. The application is callable as a library
**Rule.** The `basilisk` crate exposes `run(args) -> ExitCode` in a lib
target; library code never calls `std::process::exit`, never assumes it
owns `main` or the process's signal handlers, and initialises logging and
settings idempotently.
**Why.** In a Python-hosted process the extension module runs the same
application from `python -m basilisk` (`plugin-api.md` 4.1).
**Conforming.** `pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode`.
**Non-conforming.** Logic only in `main.rs`; `process::exit` deep in a
command; a global `tracing` subscriber set unconditionally.
**Today.** `crates/basilisk/src/main.rs` keeps its (small) logic in
`main` — add the lib target when the CLI grows (track P1 does it if
nobody has).
