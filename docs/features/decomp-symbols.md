# Decompiler symbols, scopes and program services (`decomp-symbols`)

Track `decomp-symbols` (D06 of `docs/features/decomp-plan.md`), milestone
M3, wave 2. Format: `docs/LOOP.md`, "Feature documents". Crate:
`bk-decomp-symbols` (new).

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`DT/` = `…/decompile/datatests/`, under `../ghidra` (commit `42db038f3c`);
`REF/` = the reference directory. **(read)** marks a statement taken from
the source (file:line), **(ran)** one checked against the reference build;
the runs are W1–W4 in `docs/research/decomp-wave2/runs.md`, with the
oracle prototypes beside it.

## 1. Purpose

The decompiler's view of the program outside the function being
decompiled: the symbol and scope database (global scope, namespaces,
function-local scopes as a base for `ScopeLocal`), memory properties
(read-only, volatile, incidental copy), comments, the string cache, the
constant pool, the load image, the context and tracked registers, and
per-function overrides — plus **the host trait** through which all of it
can be answered by a program database instead of by in-memory tables
(ADR-004; plan 3 item 10), carrying function summaries and the per-call
"does this return" question (ADR-025 3d) and provenance on every name and
type (3f).

## 2. Ghidra sources

| Source | Lines | What to take |
|---|---|---|
| `CPP/database.hh`, `database.cc` | 1,067 + 3,619 | `SymbolEntry` and its four kinds, `Symbol` and its five subclasses, `Scope`, `ScopeInternal`, `ScopeMapper`, `Database`, `MapIterator`; every method (section 3 says which leave) |
| `CPP/rangemap.hh` | 465 | The interval map behind every per-space entry map and the scope resolve map (4.2) |
| `CPP/partmap.hh` | 233 | The partition map behind the property map (4.3) and the context database |
| `CPP/comment.hh`, `comment.cc` | 255 + 406 | `Comment`, `CommentOrder`, `CommentDatabaseInternal` (4.12); `CommentSorter` goes to D16b |
| `CPP/stringmanage.hh`, `stringmanage.cc` | 97 + 484 | `StringManager`, `StringManagerUnicode` (4.13) |
| `CPP/cpool.hh`, `cpool.cc` | 212 + 248 | `CPoolRecord`, `ConstantPool`, `ConstantPoolInternal` (4.14) |
| `CPP/loadimage.hh`, `loadimage.cc` | 230 + 115 | `LoadImage`, `RawLoadImage`, `DataUnavailError` (4.15) |
| `CPP/loadimage_xml.hh`, `loadimage_xml.cc` | 59 + 298 | `LoadImageXml` (`<binaryimage>`, 4.15) |
| `CPP/globalcontext.hh`, `globalcontext.cc` | 334 + 618 | `ContextBitRange`, `TrackedContext`, `ContextDatabase`, `ContextInternal`, `ContextCache` (4.16; the store itself is `bk-sleigh`'s, ADR-026) |
| `CPP/override.hh`, `override.cc` | 184 + 660 | `Override` and its seven record kinds (4.17) |
| `CPP/architecture.cc` 335–357, 436–447, 813–925, 1160–1415; `sleigh_arch.cc` 241–300; `xml_arch.cc` 66–90 | — | How the architecture builds and fills these: init order, `readLoaderSymbols`, `fillinReadOnlyFromLoader`, `globalify`, `<global>`, the OTHER space, `<readonly>`, `<volatile>`, `<incidentalcopy>`, volatile registers, `<default_symbols>`, `<save_state>` (4.18) |
| `CPP/database_ghidra.*`, `loadimage_ghidra.*`, `comment_ghidra.*`, `cpool_ghidra.*`, `string_ghidra.*`, `ghidra_context.*`, `typegrp_ghidra.*`, `ghidra_arch.*` | 414 + 952 + small | The second implementation of every service: what the decompiler asks its host and how it caches the answers (4.19, 5.4) |
| `CPP/funcdata.cc` 34–80, `varmap.hh` 216–281, `varmap.cc` 507–700 | — | What D07 (function creation) and D11 (`ScopeLocal`) need from this crate (3.3) |

The C++ is authoritative; Ghidra's Java side (`DecompileCallback`,
`HighFunction`) is read only for what the host trait must carry (4.19).

## 3. Scope

### 3.1 In the crate, class by class

* **Entry maps** — `rangemap<SymbolRange>` with `EntrySubsort` (one per
  address space per scope) and `rangemap<ScopeMapper>` (the resolve map):
  ported exactly, including the order of fragments that compare equal
  (4.2). `partmap<Address,uint4>` for the property map (4.3).
* **`SymbolEntry`, `MapEntry`, `MapEntryConflict`, `DynamicEntry`,
  `UnassignedEntry`**: all members. `MapEntryConflict`'s constructor takes
  the varnode's address, size and defining op's `SeqNum` as plain values
  instead of a `Varnode *`; `SymbolEntry::updateType(Varnode *)` is not
  ported (it is `getSizedType` plus `Varnode::updateType`; D07's
  callers do the second half). Reason: no IR in this crate.
* **`Symbol`** and **`FunctionSymbol`, `EquateSymbol`, `UnionFacetSymbol`,
  `LabSymbol`, `ExternRefSymbol`**: all members, except
  `FunctionSymbol::getFunction` (creates a `Funcdata`: D07, which calls
  this crate's `create_function_scope`, 4.9) and the `<function>` element
  of `FunctionSymbol::encode`/`decode` (that is `Funcdata::encode`/
  `decode`, D07; reached through the `FunctionCodec` hook, 5.3). The
  `<functionshell>` form is here.
* **`Scope` and `ScopeInternal`**: every method, with these changes of
  signature: `queryFunction`, `findFunction`, `resolveExternalRefFunction`
  and `queryExternalRefFunction` return the function's `SymbolId`, not a
  `Funcdata *`; `addSymbolWithConflict` and `buildDefaultName` take the
  varnode facts they read (address, size, written, def `SeqNum`; and for
  names the use point, flags and "high is input") as values;
  `restrictScope(Funcdata *)` becomes "this scope belongs to the function
  symbol S" (`ScopeKind::Function`, 5.2). `buildVariableName` is the
  `ScopeInternal` version; `ScopeLocal`'s override is D11's (3.3).
* **`Database`**: all members, plus the operations of `Architecture` that
  fill it (4.18) as functions over a `Database` and already-decoded spec
  data (`bk-cspec`, `bk-lang`), so that D07 only calls them in Ghidra's
  order.
* **`Comment`, `CommentOrder`, `CommentDatabase`,
  `CommentDatabaseInternal`**: all.
* **`StringManager`, `StringManagerUnicode`**: all.
* **`CPoolRecord`, `ConstantPool`, `ConstantPoolInternal`**: all.
* **`LoadImage`** (the trait shape), **`LoadImageXml`**, **`RawLoadImage`**
  over an in-memory byte buffer (file reading stays with the caller), the
  `LoadImageFunc` and `LoadImageSection` records.
* **Context**: the named-variable registry (`ContextBitRange` by name),
  the `<context_points>` encoding and decoding, `TrackedContext` encoding,
  `getTrackedValue`, `getTrackedDefault`/`createSet` — as a layer over
  `bk_sleigh::ContextDb` (4.16).
* **`Override`**: the container, its insertion and query methods,
  `printRaw`, `generateOverrideMessages`, `encode`, `decode`, and the seven
  record kinds as data (4.17).
* **The host trait and both implementations' requirements** (4.19, 5.4):
  the in-memory implementation (Ghidra's `*Internal` classes and
  `LoadImageXml`) and the caching layer a program-database host is used
  through (Ghidra's `ScopeGhidra`, `CommentDatabaseGhidra`,
  `GhidraStringManager`, `ConstantPoolGhidra`, `ContextGhidra`,
  `LoadImageGhidra`), with a test host. The program database itself is M4.
* What `bk-decomp-types` and `bk-cspec` left open for this crate (5.5):
  `SpacebaseScopes`, `TypeSource`, the default model name, `globals()`
  and the OTHER space.

### 3.2 Not in the crate

| What | Where | Why |
|---|---|---|
| `Funcdata` creation, `<function>` encoding/decoding, `SymbolEntry::updateType` | D07 | Need the IR |
| `ScopeLocal`, `MapState`, `RangeHint`, `AliasChecker`, name and type recommendations (`varmap.*`) | D11 (plan row) | Every method but the trivial ones reads varnodes, `Funcdata`, `FuncProto` or `LoadGuard`s; 3.3 lists what D06 leaves open for them |
| `CommentSorter` | D16b | Positions comments by the function's ops and blocks |
| `Override::Record::performOverride`, `applyPrototype`, `applyIndirect`, `applyDeadCodeDelay`, `applyForceGoto` | D09 (flow) / D07 | Edit `Funcdata` and `FuncCallSpecs` |
| `ContextCache`, the decoder's context reads and `globalset` writes | `bk-sleigh` (exists: `ContextSource`, `ContextSink`) | ADR-026: the context store belongs to the SLEIGH runtime |
| `ContextInternal`'s split-point store and `<context_data>` from the `.pspec`/`.cspec` | `bk-sleigh` + `bk-lang` (exist) | Same; D06's image oracle checks them (6.3) |
| `DynamicHash` (`dynamic.*`), finding the varnode of a `DynamicEntry` | D07 (plan row) | Hashes the IR |
| Host queries for p-code, registers, user-op names, injection payloads (`getPcode`, `getRegister`, `getRegisterName`, `getUserOpName`, `getPcodeInject`) | D07's `PcodeSource` and translator traits; D18 | Translation, not program data; the plan's `PcodeSource` (4.4) |
| The pipe protocol (`readToAnyBurst`, packed streams to Java) | M5 | Basilisk's host is in-process; 4.19 keeps only what is asked |
| `TypeFactoryGhidra::findById` | `bk-decomp-types` (`TypeSource`, exists) | This crate's host trait *implements* `TypeSource` (5.5) |
| `BfdArchitecture`, `LoadImageBfd`, `RawBinaryArchitecture` | not M3 (plan 5) | Loaders and the CLI |

### 3.3 What D06 leaves open for `ScopeLocal` (D11) and `Funcdata` (D07)

Read from `varmap.cc` 507–700, 1389–1739 and `funcdata.cc` 34–80; D11 and
D07 must be able to build on these without reaching into private data:

1. **A function scope**: `Database::create_function_scope(function:
   SymbolId) -> ScopeId` attaches a `ScopeInternal` named after the
   function, with Ghidra id = the function symbol's id
   (`Funcdata::Funcdata`, funcdata.cc:58–68: `id = sym->getId()`, or
   `0x57AB12CD << 32 | (addr & 0xffffffff)` without a symbol), as a child
   of the symbol's scope, kind `Function`. It is never in the resolve map
   (`fillResolve` skips scopes with a function, database.cc:3098). A
   duplicate id is `RecovError("Duplicate scope id: <full name>")`
   (database.cc:3151), which `FunctionSymbol::decode` turns into
   `DuplicateFunctionError` (database.cc:676).
2. **An extension slot**: the scope stores no `ScopeLocal` state; D11
   keeps space, recommendations, `minParamOffset`/`maxParamOffset`,
   `stackGrowsNegative`, `rangeLocked`, `overlapProblems`,
   `openParamRefs` in its own struct keyed by `ScopeId`.
3. **The pieces `ScopeLocal` calls**: `find_overlap`, `remove_symbol`,
   `remove_symbol_mappings`, `add_symbol`, `add_map_point`,
   `add_dynamic_symbol`, `rename_symbol`, `set_category`,
   `category_symbol`, `make_name_unique`, the `ScopeInternal`
   `build_variable_name` (D11's override calls it as the fallback,
   varmap.cc:658), `range_tree()` with `longest_fit` (bk-core
   `RangeList::longest_fit`, exists), `Database::set_range`,
   `remove_range`, and **iteration of one space's entry map in record
   order** (`MapState::gatherSymbols(const EntryMap *)`, varmap.hh:209),
   plus `assign_default_names`.
4. **Wrapping attributes**: `decode_scope` accepts a callback for the
   attributes of a wrapper element (`decodeWrappingAttributes`,
   database.hh:792; `ScopeLocal` reads `lock` and `main` of `<localdb>`,
   varmap.cc:554), and `encode_scope` can be called inside a wrapper the
   caller opened (`ScopeLocal::encode`, varmap.cc:537).
5. **Default names from varnodes**: `build_default_name(symbol, base,
   VarnodeFacts)` where `VarnodeFacts { addr, use_point, flags,
   high_is_input, is_constant }` is the caller's reading of the varnode
   (database.cc:1909–1924).

Crate ownership: `crates/bk-decomp-symbols` (new), its line in the root
`[workspace.dependencies]`, `fuzz/` entries for its decoders, its
oracle programs under `crates/bk-decomp-symbols/tests/oracle/`. It
depends on `bk-core`, `bk-marshal`, `bk-decomp-types`, `bk-cspec`,
`bk-lang` and `bk-sleigh` (context only; 5.1 says why).
