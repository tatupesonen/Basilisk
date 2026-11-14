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

## 4. Behaviour

### 4.1 Flags this crate reads and writes

Symbols and entries carry `Varnode` flag bits (read, varnode.hh:79–115);
the ones that matter here: `typelock` 0x100, `namelock` 0x200,
`nolocalalias` 0x400, `volatil` 0x800, `externref` 0x1000, `readonly`
0x2000, `persist` 0x4000, `addrtied` 0x8000, `unaffected` 0x10000,
`mapped` 0x200000, `indirect_creation` 0x400000, `return_address`
0x800000, `precislo` 0x2000000, `precishi` 0x4000000, `indirectstorage`
0x8000000, `hiddenretparm` 0x10000000, `incidental_copy` 0x20000000,
`input` 0x08. The crate defines them as one `bitflags` type with Ghidra's
values (D05 defines the same values for varnodes; the two must agree and
D05's type is not a dependency here, so `bk-decomp-symbols` owns
`VarnodeFlags`' symbol subset and D05 re-exports or mirrors it — the
coordinator decides, open item 10.1).

`Symbol::flags` only ever holds `typelock`, `namelock`, `readonly`,
`volatil`, `externref`, `addrtied`, `persist`, `incidental_copy`,
`nolocalalias`, `indirectstorage`, `hiddenretparm` (comment,
database.hh:254–256; `setAttribute` masks to `typelock | namelock |
readonly | incidental_copy | nolocalalias | volatil | indirectstorage |
hiddenretparm`, database.cc:2352). Display flags (`dispflags`,
database.hh:271–281): the low three bits are the format (`force_hex` 1,
`force_dec` 2, `force_oct` 3, `force_bin` 4, `force_char` 5;
`setDisplayFormat` replaces them, database.hh:334), `size_typelock` 8,
`isolate` 16, `merge_problems` 32, `is_this_ptr` 64. Categories
(database.hh:284–290): `no_category` −1, `function_parameter` 0, `equate`
1, `union_facet` 2, `fake_input` 3.

`checkSizeTypeLock` (database.cc:311): `size_typelock` is set exactly
when the symbol is type-locked and its type's metatype is `TYPE_UNKNOWN`;
recomputed after `retypeSymbol`, `setAttribute`, `clearAttribute`,
`setIsolated(true)` and decoding the body. `setIsolated(true)` also sets
`typelock` (database.cc:340–350); decoding `merge="false"` does the same
(database.cc:509–513).

### 4.2 The entry map (`rangemap`, read rangemap.hh)

One per address space per scope (`maptable`, indexed by space index,
created on first use, database.cc:2003–2007), plus the database's resolve
map. A **record** is one stored item (a `MapEntry`; for the resolve map a
`(scope, first, last)` triple). The map keeps two structures:

* **records**, a list in a defined order (below);
* **fragments**, a sorted multiset that partitions the union of the
  records' ranges into maximal pieces on which the set of covering records
  is constant. Each fragment holds `first`, `last` (its piece), `a`, `b`
  (the whole range of its record), its record's **subsort** and a link to
  the record. Fragments are ordered by `(last, subsort)` only
  (rangemap.hh `AddrRange::operator<`); fragments of different records
  with equal `last` and subsort are *equal* and their relative order is
  defined by the insertion rules below.

Every piece boundary is shared: if two fragments overlap they have the
same `first` and `last` (the partition is refined at every record's
`a - 1|a` and `b|b + 1`).

**Subsort** (database.hh:72–99, database.cc:49–61): a pair `(useindex,
useoffset)` compared lexicographically. For an entry whose symbol is
`addrtied` it is `(0, 0)`; otherwise it is the space index and offset of
the *first* range of the entry's use limit, and an empty use limit there
is the error `Map entry with empty uselimit`. The subsort is computed
when the record is inserted and never updated. Query bounds use
`(0, 0)` as "earliest" and `(0xffff, ·)` as "latest" (the offset of the
latest bound is never initialised in Ghidra, `EntrySubsort(bool)`,
database.hh:84–87, and never compared because no space has index
0xffff); the resolve map's subsort compares nothing (`NullSubsort`), so
all its fragments with equal `last` are equal.

**Multiset insertion order** (C++11 `[associative.reqmts]`; libstdc++
`_M_get_insert_hint_equal_pos` and libc++ `__find_leaf` agree, and the
scope oracle agrees between the two libraries, W3): `insert(t)` places
`t` after every element equal to it. `insert(hint, t)` places `t`
immediately before `hint` when `t <= *hint` (or `hint` is the end) and
`*prev(hint) <= t` (or `hint` is the first element); when `*hint < t` it
places `t` before every element equal to `t`; otherwise (`t <
*prev(hint)`) after every element equal to `t`.

**`insert(record, a, b)`** (rangemap.hh `insert`): let `f = a`, `low` =
the first fragment with key `>= (f, earliest)`.

1. If `low` exists and `low.first < f`, refine at `f - 1` (`unzip(f-1,
   low)`, below).
2. The new record's place in the record list: `spot` = the first
   fragment with key `>= (b, subsort)` (searched after step 1, before any
   new fragment exists); the record is placed **before the record of
   `spot`**, or last if there is none.
3. Walk from `low` while `low.first <= b`: where `f <= low.last` (the
   fragment overlaps what is left): if `f < low.first`, insert a new
   fragment `[f, low.first - 1]` with hint `low` and set `f = low.first`;
   then if `low.last <= b`, insert `[f, low.last]` with hint `low`, stop
   if `low.last == b`, else `f = low.last + 1`; else (`b < low.last`)
   refine at `b` (`unzip(b, low)`) and stop. Advance `low`.
4. If `f <= b` remains, insert `[f, b]` without hint.

All new fragments carry the record's `a`, `b`, subsort and link.

**`unzip(i, iter)`** (refine so that `i` and `i + 1` are in different
pieces): if `iter.last == i` nothing happens. Otherwise, with `hint =
iter` fixed, for each fragment from `iter` on while its `first <= i`:
remember its `first` as `f'`, set its `first = i + 1`, and insert a copy
with `[f', i]` (same `a`, `b`, subsort, link) with hint `hint`.

**`erase(record)`** (rangemap.hh `erase`): with `[a, b]` its range,
`leftsew = rightsew = true`, `leftoverlap = rightoverlap = false`:

1. Walking backwards from the first fragment with key `>= (a,
   earliest)` over fragments whose `last == a - 1`: if one has `b ==
   a - 1` (another record ends there), `leftsew = false`, stop.
2. From that fragment forwards while `first <= b`: erase the fragments of
   this record; for every other fragment, `a' < a` sets `leftoverlap`,
   `a' == a` clears `leftsew`, `b < b'` sets `rightoverlap`, `b' == b`
   clears `rightsew`.
3. If the fragment after the walk has `a' - 1 == b`, `rightsew = false`.
4. If `leftsew && leftoverlap`, merge the pieces at `a - 1|a` (`zip(a-1,
   lower_bound(a-1))`); if `rightsew && rightoverlap`, merge at `b|b+1`.
5. Remove the record from the list.

**`zip(i, iter)`**: erase the fragments whose `last == i` starting at
`iter`, remembering the `first` of the first one as `f`; then for the
following fragments whose `first == i + 1`, set `first = f`.

**Look-ups** (all on fragments):

* `find(p)`: the fragments of the piece containing `p` — from the first
  fragment with key `>= (p, earliest)` (none if its `first > p`) to the
  last with key `<= (last of that fragment, latest)`.
* `find(p, s1, s2)`: the same piece, restricted to subsorts in `[s1,
  s2]`: from the first fragment `>= (p, s1)` (none if its `first > p`) to
  the last `<= (its last, s2)`.
* `find_begin(p)` = first fragment `>= (p, earliest)`; `find_end(p)` =
  first fragment `> (p, latest)`, and if that fragment contains `p`, the
  first fragment `> (its last, latest)`.
* `find_overlap(p, e)`: the first fragment `>= (p, earliest)` if its
  `first <= e`, else none.
* `find_first_after(p)`: from `find_end(p)`, the first fragment whose
  record starts after `p` (`p < a`).
* `find_last_before(p)`: walking backwards from `find_begin(p)`, the first
  fragment whose record ends before `p` (`b < p`); none if the walk reaches
  the start.

The **record list** is what `MapIterator`, `printEntries` and
`gatherSymbols` walk. With the placement rule of step 2 it is ordered by
`(b, subsort)` in the common case, but not always (a record inserted
inside a piece shared by two longer records goes before the record of
whichever fragment of that piece comes first); implement the rule, not
the approximation. Arithmetic is on 64-bit offsets, wrapping, as Ghidra's
`uintb`; `insert` with `a = 0` never computes `a - 1` (the refine step
needs a fragment with `first < 0`).

### 4.3 The property map (`partmap`, read partmap.hh; database.cc 3408–3453)

A sorted map from split points (`Address`, ordered by space index then
offset; address.hh:413) to a `u32` of flags, and a default value (0,
database.cc:3115). `getValue(p)`: the value at the last split point `<=
p`, else the default. `split(p)`: if a split point equals `p` return it;
else create one at `p` holding a copy of the value in force there.
`clearRange(p1, p2)` (used by tracked sets): split at both, erase the
split points strictly between, return the one at `p1`. `bounds(p)`
returns the value and the neighbouring split points with a validity code
(0 both, 1 none before, 2 none after, 3 map empty).

`setPropertyRange(flags, range)`: split at `range.first`, and at the
address one past `range.last` (`getLastAddrOpen`: invalid when the range
reaches the end of its space, then everything from the first split point
on is changed); OR `flags` into every split point in `[first, end)`.
`clearPropertyRange` ANDs with `!flags` likewise. Note that a split point
beyond the end in *another space* is also changed when the open end is
invalid — Ghidra does this (it walks to `flagbase.end()`); reproduce it.
The image oracle shows the result for the 93 data tests (W2: 403 change
points).

### 4.4 Entries (database.cc 49–300)

| Kind | Fields | `getSizedType(addr, sz)` | `printEntry` |
|---|---|---|---|
| `MapEntry` | `addr`; `offset` into the symbol; `size`; use limit; `extraflags` | `getExactPiece(type, addr - entry.addr + offset, sz)` | `<name> : <shortcut><printRaw addr>:<type size> <type printRaw> : <uselimit printBounds>` |
| `MapEntryConflict` | as `MapEntry` plus `uniq` = the def op's `time`; use limit = the def op's address (one point) | as `MapEntry` | as `MapEntry` then ` (conflicts)` |
| `DynamicEntry` | `hash` (64-bit); offset; size; use limit | `getExactPiece(type, offset, sz)` | `<name> : <dynamic>:<type size> <type> : <bounds>` |
| `UnassignedEntry` | size = the symbol's bytes consumed | `getExactPiece(type, offset, sz)` | `<name> : <unassigned>:<type size> <type>` |

`printBounds` of a use limit prints `all` and a newline when empty, else
one `<space>: <first hex>-<last hex>` line per range (address.cc:678).
`inUse(p)`: true for an `addrtied` symbol; false for an invalid `p`;
else the use limit contains `p`. `getFirstUseAddress`: the first range's
first address, or invalid. Property bits: `map_entry` 1,
`conflict_entry` 2, `dynamic_entry` 4, `unassigned_entry` 8, `piece` 16.

**`Scope::addMap(entry)`** (database.cc:1214–1272) — every mapped entry
goes through it:

1. An invalid address makes it an `UnassignedEntry` (`addUnassigned`)
   appended to the symbol's entries and nowhere else; in a global scope
   the symbol becomes `persist` (Ghidra reads the deleted entry here — a
   use after free, 4.21; Basilisk sets `persist` on the symbol).
2. In a global scope the symbol becomes `persist`. If the *global* scope
   owns the entry's first byte (`inScope(addr, 1, invalid)`), the symbol
   becomes `persist` and **the use limit is cleared** (Ghidra's "kludge",
   database.cc:1229–1232), whichever scope the entry is in.
3. `extraflags = mapped`, `offset = 0`, `size = bytes consumed by the
   symbol` (`getBytesConsumed`: the type's size; a function symbol's
   `consumeSize`, 4.5).
4. An empty use limit makes the symbol `addrtied` and ORs in the property
   map's flags at the entry's address (`getProperty`, the first byte
   only).
5. `addMapInternal`: append to the symbol's entries, insert into the
   space's map with `[addr, addr + size - 1]`; **if that wraps the
   space's offset** the error is `Symbol <name> extends beyond the end of
   the address space` — Ghidra raises it *after* appending the entry
   (database.cc:2000, 2010), and `addMapSym`'s handler then erases an
   entry never inserted and crashes (ran, W3; 4.21). Basilisk checks
   before changing anything. An entry whose size equals the type's size
   increments the symbol's `wholeCount`; at 2 the symbol enters
   `multiEntrySet`.
6. A `join`-space address adds one piece entry per join piece that is not
   a constant: pieces taken in endian order (big endian: most significant
   first; else from the last piece), each a `MapEntry` with offset = the
   bytes of the preceding pieces, its own size and address, the whole
   entry's use limit, property `piece`, no `mapped` flag; if the type is
   primitive and whole (`isPrimitiveWhole`), `precishi` on piece 0 (most
   significant), `precislo` on the last, both on the middle ones.

`Scope::addDynamic` (database.cc:1276): global ⇒ `persist`; size = bytes
consumed; `extraflags = mapped`; offset 0; appended to the scope's
dynamic list (insertion order) and the symbol's entries. The direct
builders bypass it: `addDynamicSymbol(nm, ct, caddr, hash)` makes a
`DynamicEntry(mapped, hash, 0, ct->size, use limit = [caddr] or empty)`;
`addEquateSymbol` and `addUnionFacetSymbol` the same with size 1
(database.cc:1821–1881) — no `persist` even in a global scope.

### 4.5 Symbols (database.cc 300–912)

* **Ids.** `ID_BASE = 0x4000000000000000`. A symbol without an id gets
  `ID_BASE + ((scope id & 0xffff) << 40) + nextUniqueId++` when added to a
  `ScopeInternal` (database.cc:1968–1971); `nextUniqueId` starts at 0 and
  is reset by `clear()`. A decoded id whose top byte equals `ID_BASE`'s
  (`0x40`) is dropped and reassigned (database.cc:502). `scope id & 0xffff`
  of a hashed namespace id is its low 16 bits (W3: `0x40d69b…` for
  `ns1`, id `0x27e69aaaa920d69b`).
* **Names.** An empty name becomes `buildUndefinedName()` (4.8); a symbol
  without a type is `<name> symbol created with no type`, a type of size
  < 1 `<name> symbol created with zero size type` (database.cc:1977–1980).
  `isNameUndefined`: length 15 and prefix `$$undef`.
* **Name tree**: ordered by `(name bytes, nameDedup)`
  (`SymbolCompareName`, database.hh:440; byte-wise `std::string::compare`).
  `insertNameTree` (database.cc:2885): `nameDedup = 0`; if taken,
  `nameDedup = (dedup of the last symbol with that name) + 1`; if still
  taken, `Could  not deduplicate symbol: <name>` (two spaces).
* **Categories** (database.cc:1982–1991, 3009–3030): a vector per
  category of symbol slots. Category 0 (`function_parameter`) keeps the
  given `catindex`, padding with empty slots; other categories append
  (`catindex = size`). Removing or recategorising empties the slot and
  pops trailing empty slots.
* **Display name**: equals the name unless decoded from `label=`
  (`decodeHeader`, `ExternRefSymbol::decode`, `functionshell`, scope
  `label`); renaming sets both.
* **`FunctionSymbol`**: type = the factory's `code` type, flags `namelock
  | typelock`; `consumeSize` = the architecture's `min_funcsymbol_size`
  (`translate->getAlignment()` when that is at most 8, else 1;
  architecture.cc:155, 640). Decoding a `<function>` (D07) may raise
  `consumeSize` to the function's size when that is in `2..=8`
  (database.cc:680–683).
* **`EquateSymbol`**: category `equate`, type `getBase(1, TYPE_UNKNOWN)`,
  `dispflags |= format`. `isValueClose(v, size)` (database.cc:726–743):
  equal; else with `mask = calc_mask(size)`, `m = value & mask`: if `m !=
  value` and `value != sign_extend(m, size)`, false; true if `m` equals
  `v`, `~v`, `-v`, `v + 1` or `v - 1` under `mask`.
* **`UnionFacetSymbol`**: category `union_facet`, `fieldNum`
  (−1 = whole), `addrBased`. Decoding checks the type is a union or a
  pointer to one (`<unionfacetsymbol> does not have a union type`) and
  `−1 <= field < numDepend` (`… field attribute is out of bounds`).
* **`LabSymbol`**: type `getBase(1, TYPE_UNKNOWN)`; never a category.
* **`ExternRefSymbol`**: `refaddr`; type = pointer (`refaddr`'s address
  size and word size) to `code`; an empty name becomes
  `<shortcut><printRaw refaddr>_exref` (W3: `r0x00001013_exref`); flags
  `externref | typelock`. `addExternalRef` clears `readonly` after mapping
  (database.cc:1782).
* **`getMapEntry(addr)`**: the first `MapEntry` of the symbol (in entry
  order) in the same space with `0 <= addr - entry.addr < entry.size`.
  **`getFirstWholeMap`**: entry 0 (Ghidra does not check that it is whole),
  error `No mapping for symbol: <name>` without entries.
* **`getMapEntryPosition(entry)`** (database.cc:387–399): Ghidra counts
  `pos += 1` for every preceding entry when *the argument* is whole-sized
  (it tests `entry`, not the loop's `tmp`): the result is the entry's
  index for a whole entry and 0 for any piece. Reproduce (4.21); D00's
  dump writes this number.
* **`getResolutionDepth(useScope)`** (database.cc:409–446): 0 in its own
  scope; with no use scope, the number of ancestors excluding the global
  scope; otherwise via `findDistinguishingScope` (database.cc:1601–1624)
  and one more if `useScope.isNameUsed(distinguishing name, terminating
  scope)`. The result is cached per use scope in the symbol (`depthScope`,
  `depthResolution`); **the cache is never invalidated** by renames or new
  symbols — Ghidra returns the stale value. Basilisk keeps the cache with
  the same lifetime (a symbol field reset only when the use scope
  changes), so printing equals Ghidra's.

### 4.6 Queries (database.cc 999–1182, 1318–1547, 2373–2614)

`stack*` helpers walk from a start scope up the parents, stopping before
a terminating scope (none for the public queries): constants answer
nothing; in each scope try the scope's `find*`; if none, a scope that
owns the range (`inScope`) ends the walk with "discovered here, no
symbol". Exceptions: `stackExternalRef` does no discovery step;
`stackFunction` and `stackCodeLabel` test ownership of one byte with an
invalid use point. Every public query starts at `mapScope(this, addr,
usepoint)`: the scope of the first resolve-map fragment containing
`addr` (fragment order, 4.2), or `this` when the resolve map is empty or
has nothing there (database.cc:3373–3400; the use point is ignored).

| Query | Answer |
|---|---|
| `queryByAddr(addr, use)` | `stackAddr` → the entry of `findAddr` |
| `queryContainer(addr, size, use)` | `stackContainer` → `findContainer` |
| `queryProperties(addr, size, use, &flags)` | as `queryContainer`; flags = the entry's `extraflags | symbol flags`; with only a discovering scope `mapped | addrtied`, plus `persist` if that scope is global, plus the property map at `addr`; with nothing, the property map at `addr` |
| `isReadOnly(addr, size, use)` | `readonly` in `queryProperties`' flags |
| `queryFunction(addr)` | `stackFunction` with an invalid use point → function symbol |
| `queryCodeLabel(addr)` | `stackCodeLabel` → label symbol |
| `queryExternalRefFunction(addr)` | `stackExternalRef`; then the scope where it was found resolves the reference: `queryFunction(refaddr)` from that scope |
| `discoverScope(addr, size, use)` | constants: none; from `mapScope` upwards, the first scope with `inScope` |
| `queryByName(nm)` | `findByName` here; if empty, the parent's `queryByName` |
| `queryFunction(nm)` | the first `FunctionSymbol` of `queryByName` |

`ScopeInternal::find*` on the space's entry map:

* `findAddr(addr, use)`: `find(off, earliest, use invalid ? latest :
  (use space index, use offset))`; walk the result **backwards**; the
  first entry that starts exactly at `addr` and is `inUse(use)`.
* `findContainer(addr, size, use)`: same range, backwards; among entries
  with `last >= addr + size - 1` that are `inUse`, keep the first
  smallest (a strictly smaller size replaces); stop at one of exactly
  `size`.
* `findClosestFit(addr, size, use)`: same range, backwards; `newdiff =
  entry size - size`; take it (if `inUse`) when the previous best was
  negative and `newdiff` is larger, or both are non-negative and
  `newdiff` is smaller (initial best −10000); stop at 0. Only entries with
  `last >= addr` are considered (all are, being in `addr`'s piece).
* `findFunction(addr)` / `findExternalRef(addr)`: `find(off)` (all
  subsorts) **forwards**; the first entry starting exactly at `addr`:
  function — if its symbol is a function symbol (else keep looking);
  external ref — that entry's symbol if it is an `ExternRefSymbol`,
  otherwise **none** (it stops at the first entry starting there).
* `findCodeLabel(addr)`: `find(off, earliest, (addr space, addr off))`
  backwards; the first entry starting at `addr` that is `inUse(addr)`:
  its symbol if a label, else none.
* `findOverlap(addr, size)`: the entry of `find_overlap(off, off + size
  - 1)`.
* `findSymbolBefore(addr, use)`: from `find_last_before(off)` backwards,
  the first entry `inUse(use)`. `findSymbolAfter`: from
  `find_first_after(off)` forwards.
* `findByName(nm)`: every symbol with that name, in dedup order.
* `isNameUsed(nm, stop)` (database.cc:2599): here (name tree lower bound
  with dedup 0); else the parent's, unless the parent is null, equals
  `stop`, or is the global scope (never recurses into the global scope).

### 4.7 Scopes, namespaces, resolution (database.cc 947–985, 1435–1624, 3055–3617)

* A scope has a name, display name, Ghidra id (`u64`), parent, children
  **ordered by id** (`map<uint8,Scope *>`), an owned range list
  (`rangetree`), and an optional function.
* **Database ids** (`idmap`): unique; `attachScope` (database.cc:3132):
  the global scope (parent null) must be the only one and have an empty
  name (`Multiple global scopes`, `Global scope does not have empty
  name`); others must have a name (`Non-global scope has empty name`) and
  a new id (`RecovError("Duplicate scope id: <full name>")`).
* **Hashed ids** (`hashScopeName`, database.cc:970): `reg1 = high 32 bits
  of the parent id`, `reg2 = low 32`; `reg1 = crc(reg1, 0xa9)`, `reg2 =
  crc(reg2, reg1)`; for each byte `c` of the name `reg1 = crc(reg1, c)`,
  `reg2 = crc(reg2, reg1)`; result `reg1 << 32 | reg2`, where `crc(r, v)
  = crc32tab[(r ^ v) & 0xff] ^ (r >> 8)` (crc32.hh:33; only the low byte
  of `v` is used, so the signedness of `char` does not matter).
* **`resolveScope(nm, strategy)`** (database.cc:1435): with `strategy`
  (the database's `idByNameHash`): the child with the hashed id, if its
  name equals `nm`. Without: a name starting with a digit is parsed as an
  integer id with C stream base detection (`0x` hex, leading `0` octal,
  else decimal; `unsetf(dec|hex|oct)`) and looked up among the children;
  otherwise the first child **in id order** with that name.
* **`resolveScopeFromSymbolName(full, &base, start)`** (database.cc:3294):
  splits `full` at the architecture's scope delimiter (`::`), stopping at
  the first delimiter after the first `<` (template arguments are never
  split); an empty first component means "start at the global scope";
  each component is resolved from the current scope; an unknown one gives
  none. `findCreateScopeFromSymbolName` creates missing components with
  hashed ids (error `Scope name hashes not allowed` when the database
  does not hash) through `findCreateScope(id, nm, parent)`, which returns
  an existing scope of that id **whatever its name or parent**
  (database.cc:3260–3269).
* **Ownership ranges and the resolve map**: `setRange`, `addRange`,
  `removeRange` on the database clear the scope's resolve entries
  (`clearResolve`: for each range of the scope, the first resolve
  fragment at the range's first address that belongs to the scope is
  erased), change the range list, and re-insert one resolve record per
  range (`fillResolve`). Neither applies to the global scope or to a
  function scope (database.cc:3058–3059, 3097–3098).
* **`inScope(addr, size, use)`**: the scope's range list contains all
  `size` bytes (`RangeList::inRange`).
* `deleteScope`, `deleteSubScopes`, `clearUnlocked` (recursive over
  children in id order, then the scope), `clearReferences` (recursive,
  removes ids and resolve entries), `adjustCaches` (resize `maptable` to
  the number of spaces).
* `getFullName` (`a::b`, empty for the global scope), `getScopePath`,
  `findDistinguishingScope` (database.cc:1601–1624; first the four quick
  cases, then the first differing element of the two root paths, or
  `this` when the paths are identical).
* `isSubScope(s)`: `s` is this scope or an ancestor.
* `overrideSizeLockType(sym, ct)`: same size and size-locked → replace the
  type; otherwise `Overriding symbol that is not size locked` /
  `Overriding symbol with different type size`. `resetSizeLockType`:
  replace a non-`TYPE_UNKNOWN` type by `getBase(size, TYPE_UNKNOWN)`.

### 4.8 Names (database.cc 1909–1941, 2616–2799, 3035–3050)

* **`buildUndefinedName`**: find the last name `< "$$undefz"`; if it has
  length 15 and starts `$$undef`, parse its eight hex digits, error
  `Error creating undefined name` if they read as `0xffffffff`, else
  return `$$undef` + `uniq + 1` as eight lower-case hex digits; otherwise
  `$$undef00000000`.
* **`makeNameUnique(nm)`**: `nm` if unused. Otherwise walk backwards from
  the lower bound of `(nm + "_x99999", dedup 0xffffffff)` towards the
  first symbol named `nm`; the first name of the form `nm_DD` (exactly two
  decimal digits) or `nm_xDDDDD` (exactly five) gives `uniqid`; the result
  is `nm_` + `uniqid + 1` as two digits when `< 100`, else `x` and five
  digits; with no such name, `nm_00`. If the result is taken, `Unable to
  uniquify name: <result>`. (Only names sorting between `nm` and
  `nm_x99999` are seen, so `nm_100` style names are invisible; Ghidra's
  behaviour.)
* **`buildVariableName(addr, pc, ct, &index, flags)`** (`ScopeInternal`),
  first matching rule; `sz` = the type's size or 1; register names come
  from the translator (`getRegisterName(space, off, sz)`, through the
  `RegisterNames` input of 5.3):
  1. invalid address → `unassigned_`;
  2. `unaffected`: `unaff_retaddr` with `return_address`, else
     `unaff_<register>` or `unaff_<offset, 8 hex digits zero-filled>`;
  3. `persist`: the register name, else type name base +
     capitalised space name + the address in words, hex, zero-filled to
     `2 * addrsize` digits;
  4. `input` with `index < 0`: `in_<register>` or
     `in_<space>_<8 hex digits>`;
  5. `input`: `param_<index>`;
  6. `addrtied`: as rule 3's fallback (type base + Space + words);
  7. `indirect_creation`: `extraout_<register>` or `extraout_var`;
  8. otherwise `<type base>Var<index>` with `index` incremented; if
     taken, up to ten more increments; then fall back.
  Every result except rule 8's first free candidate goes through
  `makeNameUnique`.
* **`buildDefaultName(sym, &base, facts)`**: with varnode facts (not a
  constant): use point = invalid if the varnode is address-tied or there
  is no function, else the facts' use point; parameters (category 0) and
  input highs use `index = catindex + 1` or −1 and `flags | input`; others
  `base`. Without facts: from entry 0 (address of a `MapEntry`, first use
  address, `addrtied` when that is invalid), category 0 adds `input` and
  `index = catindex + 1`.
* **`assignDefaultNames(&base)`**: every symbol whose name is undefined
  (walking from the upper bound of `$$undef`), renamed to its default
  name in name order.

### 4.9 Adding, renaming, retyping, removing (database.cc 1630–1900, 2126–2366)

| Operation | Effect | What it invalidates |
|---|---|---|
| `addSymbol(nm, ct)` | new plain symbol, unmapped (owner scope = the cache owner, 4.19) | — |
| `addSymbol(nm, ct, addr, use)` | `ct` replaced by its stripped form if it has one; `addMapPoint` | — |
| `addMapPoint(sym, addr, use)` | new `MapEntry`; use limit = `[use, use]` when valid; `addMap` | entry maps, multi-entry set |
| `addFunction(addr, nm)` | warning `Function <nm> overlaps object: <name>` when `queryContainer(addr, 1, invalid)` finds an entry; function symbol mapped with no use limit | — |
| `addCodeLabel(addr, nm)` | warning `Codelabel <nm> overlaps object: <name>` when `queryContainer(addr, 1, addr)` finds a non-function entry | — |
| `addExternalRef(addr, ref, nm)` | mapped with no use limit; `readonly` cleared | — |
| `addSymbolWithConflict(nm, ct, facts)` | requires a written varnode (`Conflict symbol created on illegal Varnode`); stripped type; `MapEntryConflict` through `addMap` | — |
| `renameSymbol(sym, nm)` | out of the name tree (and multi-entry set), new name and display name, back in with a new dedup | name order; the depth cache is **not** reset (4.5) |
| `retypeSymbol(sym, ct)` | stripped `ct`; same size or no entries → replace type; one entry that is a `MapEntry` of an `addrtied` symbol → remove it, `wholeCount = 0`, replace type, `addMapPoint(sym, addr, invalid)`; else `RecovError("Unable to retype symbol: <name>")` (W3: 212 cases) | entry maps |
| `setAttribute`/`clearAttribute` | masked (4.1); `checkSizeTypeLock` | — |
| `setDisplayFormat` | low three display bits | — |
| `setCategory(sym, cat, ind)` | 4.5 | categories |
| `removeSymbolMappings(sym)` | out of the multi-entry set if `wholeCount > 1`; every entry out of its map or the dynamic list; `wholeCount = 0` | entry maps |
| `removeSymbol(sym)` | category slot, mappings, name tree | the symbol id is dead |
| `clear()` | remove every symbol in name order; `nextUniqueId = 0` | everything |
| `clearCategory(cat)` | `cat >= 0`: remove every symbol of the category in slot order; else every symbol without a category | — |
| `clearUnlocked()` | in name order: type-locked symbols are kept (an unlocked, defined name is replaced by `buildUndefinedName()`, `nolocalalias` cleared, a size-locked type reset); equates kept; the rest removed | — |
| `clearUnlockedCategory(cat)` | the same over one category (no `nolocalalias` clearing), or over symbols without a category | — |
| `categorySanity()` | a category with an empty slot is dissolved: all its symbols get `no_category` | — |

`clearCategory` and `clearUnlockedCategory` read every slot of the
category including empty ones (database.cc:2175–2177, 2226–2228): an
empty slot is a null dereference in Ghidra (4.21). Basilisk skips empty
slots.

### 4.10 Multi-entry symbols and use-point restrictions

A symbol with two or more whole-sized entries is multi-entry
(`wholeCount > 1`) and listed in `multiEntrySet`, ordered by name and
dedup. Entries are kept in the order added (`mapentry`). The same storage
can hold different symbols at different code points: each such entry has
a use limit, and the queries pick by use point through the subsort
window and `inUse` (4.6). Because the global scope's ranges clear use
limits (4.4 step 2), restrictions survive only in non-global scopes or
outside the global ranges. Entries of one symbol at overlapping storage
are allowed. Overlapping entries of different symbols are allowed too;
which one a query returns follows 4.2's fragment order and 4.6's
direction of walk.

### 4.11 Encoding (database.cc 158–300, 449–912, 2801–2974, 3458–3617)

Through `bk-marshal`'s `Encoder`/`Decoder` (XML and packed). Ids
(database.cc:23–43): attributes `cat` 61, `field` 62, `merge` 63,
`scopeidbyname` 64, `volatile` 65; elements `collision` 67, `db` 68,
`equatesymbol` 69, `externrefsymbol` 70, `facetsymbol` 71,
`functionshell` 72, `hash` 73, `hole` 74, `labelsym` 75, `mapsym` 76,
`parent` 77, `property_changepoint` 78, `rangeequalssymbols` 79, `scope`
80, `symbollist` 81 (and the shared ids of `bk-marshal`).

* **Symbol header** (`encodeHeader`): `name`, `id`, then only when set
  `namelock`, `typelock`, `readonly`, `volatile`, `indirectstorage`,
  `hiddenretparm` (true), `merge="false"` (isolated), `thisptr`, `format`
  (`hex|dec|oct|bin|char`), always `cat`, and `index` when `cat >= 0`.
  The display name is **not** written (decoded from `label`). Decoding
  (`decodeHeader`) accepts the same, any order, unknown attributes
  ignored; `index` is read only for category 0 (other categories get
  index 0 and are re-indexed when added).
* `<symbol>` = header + type reference; `<equatesymbol>` = header +
  `<value>value</value>` (type rebuilt as `undefined1`-like base);
  `<facetsymbol>` = header + `field` + `addrtied="true"` + type (but
  `ScopeInternal::encode` skips union-facet symbols); `<labelsym>` =
  header; `<externrefsymbol name=…>` + address (only the name is
  written; decode reads `name` and `label`); `<functionshell name id>`
  (id only when non-zero; decode reads `name`, `id`, `label`).
* **Entries** after the symbol inside `<mapsym>`: `MapEntry` = address
  element + `<rangelist>`; pieces write nothing; `DynamicEntry` = `<hash
  val=…>` + `<rangelist>`; `MapEntryConflict` = `<hash val="0x0">` +
  `<rangelist>` (an incomplete dynamic entry); `UnassignedEntry` = empty
  `<addr/>` + `<rangelist>`.
* **`<scope name id>`** + `<parent id>` (not for the global scope) +
  the scope's `<rangelist>` + `<symbollist>` (only if the name tree is
  non-empty) of `<mapsym>` in name-tree order. W3 shows the exact text
  (two-space indentation from `XmlEncode`).
* **Decoding a scope** (`ScopeInternal::decode`): optional `<parent>`
  skipped; then `<rangelist>` (becomes the scope's ranges through
  `setRange`) or `<rangeequalssymbols/>` (each decoded symbol's first
  entry's range is added); then `<symbollist>` of `<mapsym>`, `<hole>`
  (`range` attributes plus `readonly`/`volatile` booleans → property
  ranges), `<collision name>` (adds an unmapped `int` of size 1 named so,
  if absent); anything else `Unknown symbollist tag`. After each
  `<mapsym>`: a `readonly`/`volatile` symbol puts those properties over
  its first entry's range. Finally `categorySanity`.
* **`addMapSym`**: the symbol element decides the kind (`symbol`,
  `equatesymbol`, `function`, `functionshell`, `labelsym`,
  `externrefsymbol`, `facetsymbol`; else `Unknown symbol type`); then
  entries until the end: `<hash>` → dynamic, else map entry (an empty
  address → unassigned). A failure while adding entries prints the warning
  `Throwing out symbol with invalid mapping: <name>`, removes the symbol
  and yields none.
* **`<db scopeidbyname="true">`**: `<property_changepoint space offset
  val>` per property split point, then the global scope and every
  descendant that is not a function scope (`encodeRecursive(…, true)`:
  pre-order, children in id order). Decoding: attribute, property change
  points (`split(addr) = val`), then each `<scope name id label>` with an
  optional `<parent id>` (`Could not find scope matching id`), through
  `findCreateScope`.
* `decodeScope(dec, scope)`: a `<scope>` element, or a wrapper element
  whose attributes go to the scope (`decodeWrappingAttributes`) around
  one. `decodeScopePath`: `<parent>` with a skipped root element then
  `<val id label>name</val>` elements, each created or found
  (`Missing name and id in scope` without an id).

### 4.12 Comments (comment.cc)

* `Comment { type, uniq, funcaddr, addr, text, emitted }`; types (one
  bit each): `user1` 1, `user2` 2, `user3` 4, `header` 8, `warning` 16,
  `warningheader` 32; names as written (unknown name: `Unknown comment
  type: <name>`; encoding a combined or unknown value: `Unknown comment
  type`).
* **Order**: `(funcaddr, addr, uniq)` (`CommentOrder`; addresses by space
  index then offset; the invalid address sorts first).
* `addComment(tp, fad, ad, txt)`: `uniq` = 1 + the `uniq` of the last
  comment before `(fad, ad, 65535)` if that comment has the same `fad` and
  `ad`, else 0. `addCommentNoDuplicate`: walk backwards over the comments
  at `(fad, ad)`: equal text → not added (returns false); otherwise `uniq`
  = the first (highest) one's `uniq + 1`. A key that already exists makes
  the set refuse the comment silently (possible only past 65,535 comments
  at one address; Basilisk returns an error there, 4.21).
* `clearType(fad, mask)`: remove the function's comments whose type has a
  bit of `mask`. `beginComment`/`endComment(fad)`: the range `[(fad,
  minimal, 0), (fad, maximal, 65535))`. `deleteComment`.
* `<commentdb>` of `<comment type>` with two address elements (function,
  then comment address) and an optional `<text>content</text>`; decoding
  goes through `addComment`, so `uniq`s are renumbered.

### 4.13 Strings (stringmanage.cc)

* Cache: `Address → { isTruncated, bytes }`, ordered; `maximumChars` =
  2048 in both architectures (sleigh_arch.cc:247, ghidra_arch.cc:357).
* **`getStringData(addr, charType)`** (in-memory version,
  stringmanage.cc:434): a cached answer is returned as it is. Otherwise an
  empty entry is created (so a failure is cached too). An opaque string
  type answers empty. Bytes are read 32 at a time (the last read cut to
  `maximumChars` bytes; when no room is left, the empty answer) until a
  read contains a terminator (`charsize` zero bytes at a multiple of
  `charsize` *within that read*); a `DataUnavailError` answers empty.
  `checkCharacters` over all bytes read: invalid encoding → empty. Then
  `assignStringData`: for `charsize` 1 with fewer than `maximumChars`
  characters, **the whole buffer read**, including bytes after the
  terminator up to the end of the last 32-byte read; otherwise transcode
  to UTF-8 (stopping at the terminator or `maximumChars` characters) and
  append one NUL. `isTruncated = characters >= maximumChars` — never true
  here, because the terminator lies within `maximumChars` bytes.
* `getCodepoint` (stringmanage.cc:348): UTF-16 with surrogate pairs (a
  lone trail or a bad trail is invalid), UTF-8 of 1–4 bytes with
  continuation checks (overlong forms are accepted), UTF-32 by
  endianness; any other `charsize` invalid; results `> 0x10ffff` or in
  `0xd800..=0xdfff` invalid. `writeUtf8` encodes by the number of
  significant bits (`< 12` two bytes, `< 17` three, else four; more than
  21 bits is `Bad unicode codepoint`).
* `registerInternalStringData(addr, buf, charType)`: hash = CRC over the
  bytes from `0x7b7c66a9` (`crc_update`), `addr.offset ^ (hash << 32)`;
  stored under the constant-space address of that value; returns the hash
  or 0 for an invalid encoding. Unlimited length, so this path can
  truncate.
* `isString` = non-empty answer.
* `<stringmanage>` of `<string>` + address + `<bytes trunc>` with the
  bytes as hex, two digits each, a newline after every 20th byte followed
  by two spaces, the whole content starting and ending with a newline.
  Decoding reads pairs of characters after skipping white space between
  pairs (4.15 gives the exact digit rule).

### 4.14 The constant pool (cpool.cc)

* Record kinds (tags): `primitive` 0, `string_literal` 1,
  `class_reference` 2, `pointer_method` 3, `pointer_field` 4,
  `array_length` 5, `instance_of` 6, `check_cast` 7; flags
  `is_constructor` 1, `is_destructor` 2. Fields: token, value, type,
  byte data (string literals).
* `ConstantPoolInternal` keys by the first two reference integers `(a,
  b)` (`b = 0` when there is one); more references are ignored; an empty
  reference list is undefined behaviour in Ghidra (`refs[0]`; 4.21) —
  Basilisk's key needs at least one and returns an error otherwise.
  `createRecord` on an existing key: `Creating duplicate entry in
  constant pool: <token>`.
* `putRecord(refs, tag, tok, ct)` sets only tag, token and type; Ghidra
  leaves `flags` and `value` uninitialised (4.21); Basilisk sets 0.
* **`<cpoolrec tag constructor destructor>`**: tag names `method`,
  `field`, `instanceof`, `arraylength`, `checkcast`, `string`,
  `classref`, else `primitive` (an unknown name decodes as `primitive`);
  `primitive` first has `<value>`; then `<token>content</token>` or
  `<data length>` with that many hex bytes separated by white space
  (length must be in `0..0x100000`, `Bad constant pool record: bad <data>
  size`; a string literal without data is `… missing <data>`); then the
  type, decoded with the constructor/destructor flags as code flags when
  either is set. `<constantpool>` of `<ref a b>` + `<cpoolrec>` pairs in
  key order.
* `CPoolRecord::encode` writes each byte with `operator<<` of an
  `unsigned char`, i.e. as the character itself, zero-padded to two
  columns (cpool.cc:67) — not hex, so Ghidra cannot read its own encoding
  of a string literal (4.21). Basilisk writes two hex digits (what the
  decoder reads) and records the difference.

### 4.15 Load images (loadimage.cc, loadimage_xml.cc)

* A load image answers `loadFill(buf, size, addr)` or fails with
  `DataUnavailError`; lists symbols (`LoadImageFunc { address, name }`),
  sections, read-only ranges; has an architecture string and
  `adjustVma`.
* **`<binaryimage arch>`** (`LoadImageXml::open`): children `<symbol
  space offset name>` (later duplicates of an address replace earlier
  ones) and `<bytechunk space offset readonly>`content`</bytechunk>`
  (a repeated address replaces the earlier chunk's bytes; `readonly`
  read as a boolean, the address added to the read-only set and never
  removed); anything else `Unknown LoadImageXml tag`. The root must be
  `binaryimage` (`Missing binaryimage tag in <file>`).
* **Hex content** (loadimage_xml.cc:111–135, same code in
  stringmanage.cc:242–266): skip white space; take two characters `c1`,
  `c2`; continue while both are positive as signed `char`s — so the loop
  ends at the end of the text, at a NUL, or at any byte `>= 0x80`; map
  each with `c <= '9' → c - '0'`, `c <= 'F' → c + 10 - 'A'`, else `c + 10
  - 'a'`, in 8-bit signed arithmetic, and store `(c1 * 16 + c2) & 0xff`;
  skip white space again. There is no validation: white space *inside* a
  pair or a non-hex letter gives a byte computed by that arithmetic. With
  unsigned `char` (Linux AArch64 without `-fsigned-char`) the end of text
  reads as 255 and the loop never ends (4.21). Basilisk computes exactly
  the signed-`char` result for every input (ADR-021) and stops; an odd
  final character is dropped. All 181 chunks of the 93 data tests are
  well formed (image oracle, W2).
* **`pad()`** (loadimage_xml.cc:154–201): (1) in address order, a chunk
  whose last byte is not beyond the last byte of the most recent kept
  chunk in the same space is removed; (2) after each chunk (unless it
  ends exactly at the end of its space, where the end address wraps) a
  zero chunk is added at its end address of `min(512, bytes left in the
  space, distance to the next chunk in the same space)` bytes, and none
  when the next chunk starts at or before that end. Offsets and lengths
  are in address units with one byte per unit (word size is ignored).
  Pad chunks are real chunks: `encode` writes them (it skips only empty
  vectors), they are not read-only. W2: 181 chunks become 349.
* **`loadFill`**: start at the last chunk starting at or before `addr`;
  copy while the current address lies inside the chunk
  (`Address::overlap`), moving to the next chunk only when it continues
  exactly where the copy stands; when the request is not satisfied, fail
  with `Bytes at <printRaw of the first unsatisfied address> are not
  mapped` — the bytes already copied stay in the buffer. W2: 1,744 probes,
  432 failures, identical on both hosts.
* `getReadonly`: one range per read-only chunk `[start, start + size -
  1]`. `getNextSymbol`: the symbols in address order. `adjustVma(adj)`:
  every chunk and symbol moves by `addressToByte(adj, wordsize)` truncated
  to `int4` (loadimage_xml.cc:284), so adjustments outside ±2³¹ are
  undefined in Ghidra; Basilisk uses the full 64-bit wrapping sum and
  rejects nothing.
* `encode`: `<binaryimage arch>` + `<bytechunk space offset
  [readonly="true"]>` (hex, two digits per byte, newline after every
  20th, content starting and ending with a newline) + `<symbol space
  offset name>`.
* **`RawLoadImage`** over bytes and a `vma`: an address before the image
  or at/after its end in the first step fails (`Unable to load <n> bytes
  at <addr>`); a read that starts inside and runs past the end is filled
  with zeros. Ghidra opens the file in text mode (loadimage.cc:60); the
  caller hands Basilisk the file's bytes unchanged. `adjustVma(adj)` adds
  `addressToByte(adj)`.

### 4.16 Context and tracked registers (globalcontext.cc)

The store is `bk_sleigh::ContextDb` (ADR-026), which already ports
`ContextInternal`'s blobs, value-and-mask words, split copies that clear
the mask, change points, regions and tracked sets. This crate adds:

* **Named variables** (`ContextBitRange`, globalcontext.cc:33–41,
  368–383): a name maps to `(word, startbit, endbit, shift, mask)` with
  `word = sbit / 32`, `shift = 31 - endbit` within the word, `mask = ~0 >>
  (startbit + shift)`; registering after the first split point is
  `Cannot register new context variables after database is initialized`;
  a range across two words `Context variable does not fit in one word`;
  an unknown name `Non-existent context variable: <name>`. Variables are
  kept in name order (`map<string,…>`), which is the order of `<set>`
  elements on encoding.
* **`<context_points>`** (globalcontext.cc:478–529): per split point (in
  address order) `<context_pointset space offset>` with one `<set name
  val>` per variable (every variable, its value at that point); then per
  tracked split point with a non-empty set `<tracked_pointset space
  offset>` of `<set space offset size val>`. Nothing at all when both
  stores are empty; `<context_points/>` when only empty tracked sets
  exist (and decoding that creates nothing, W4). Decoding: a
  `<context_pointset>` with attributes sets each named variable from that
  address to the end (`getRegionForSet(addr, invalid)`, marking the mask);
  **without attributes it sets the default — and Ghidra zeroes the whole
  default blob before every `<set>`** (globalcontext.cc:355–358), so only
  the last variable of such an element survives (4.21; Basilisk zeroes
  once per element, recorded as a difference; nothing Ghidra writes has
  such an element); `<tracked_pointset>` replaces the tracked set at a
  split of its address; anything else `Bad <context_points> tag`.
* **`getTrackedValue(mem, point)`** (globalcontext.cc:224–251): the first
  tracked register at `point` that contains `mem` (same space, starts at
  or before, ends at or after); shift by the byte distance from the
  register's most significant end (big endian) or least significant end
  (little endian), mask to `mem.size`; 0 when none. `bk_sleigh::
  TrackedValue::extract` implements one entry of this; the context oracle
  checks the whole look-up (W4: 32,000 rows).
* `createSet(a1, a2)` = `clearRange(a1, a2)` on the tracked map, emptied;
  `getTrackedDefault` = the tracked default set.

### 4.17 Overrides (override.cc)

Per function (`Funcdata::localoverride`; D07 owns the instance):

* `forcegoto: Address → Address`, `deadcodedelay: per space index, −1 =
  none`, `deindirect: Address → Address`, `protoover: Address →
  FuncProto` (`bk-cspec`'s; inserting marks it as an override and
  replaces an earlier one), `multistagejump: Vec<Address>` (duplicates
  kept), `pcodeover: Address → Record`.
* Records: flow kinds `branch`, `call`, `callreturn`, `return`
  (`Unknown flow override name: <n>`) and destination kinds
  `callother_call`, `callother_branch`, `call_call` with a destination
  (`Unknown call destination override name: <n>`). Inserting at an
  address replaces.
* `hasDeadcodeDelay(space)`: a set delay that differs from the space's own
  default. `queryMultistageJumptable(addr)`, `getPCodeOverride(addr)`.
* `printRaw` lines, in this order: `force goto at <a> jumping to <b>`;
  `dead code delay on <space> set to <n>`; `override indirect at <a> to
  call directly to <b>`; per record (`override CALL, CALLIND, or RETURN
  at <a> to a BRANCH`, `override BRANCH, BRANCHIND, or RETURN at <a> to a
  CALL`, `… to a CALL followed by a RETURN`, `override BRANCHIND or
  CALLIND at <a> to a RETURN`, `override CALLOTHER at <a> to CALL
  directly to <b>`, `override CALLOTHER at <a> to BRANCH directly to
  <b>`, `override CALL at <a> to call to a new address <b>`); `override
  prototype at <a> to <FuncProto::printRaw("func")>`. Addresses print
  with `operator<<` (bk-core's display of `Address`).
  `generateOverrideMessages`: `Restarted to delay deadcode elimination for
  space: <name>` per set delay.
* `<override>` (nothing when all are empty): `<forcegoto>` (two
  addresses), `<deadcodedelay space delay>`, `<protooverride>` (address +
  prototype), `<multistagejump>` (address), then records: `<flow
  type>` + address, `<calldest type>` + two addresses. Decoding: a
  negative delay is `Bad deadcodedelay tag`; an invalid flow address `Bad
  flow override address`; invalid destination addresses `Bad destination
  override address`; **unknown children are skipped silently**
  (override.cc:400). Element ids `deadcodedelay` 218, `flow` 219,
  `forcegoto` 220, `calldest` 221, `multistagejump` 222, `override` 223,
  `protooverride` 224.
* `<flowoverridelist>` in a saved architecture (`decodeFlowOverride`,
  architecture.cc:449–476) names the function by address and adds to that
  function's overrides; this crate decodes the records into `(function
  address, record)` pairs and D07 delivers them. (Ghidra closes the
  element twice at the end, architecture.cc:475–476; the second close
  consumes the enclosing element's end — a latent decoding defect, 4.21.)

### 4.18 What the architecture puts in (architecture.cc, sleigh_arch.cc, xml_arch.cc)

The order of `Architecture::init` (architecture.cc:1392–1415), as it
concerns this crate: load image built; context, comment database, string
manager (2048), constant pool, database (`idByNameHash = true`, an
empty-named global `ScopeInternal` of id 0) built; the specs read
(`restoreFromSpec`), during which **pspec** `<volatile>` ranges and
`<register_data>` volatile registers set `volatil`, `<incidentalcopy>`
sets `incidental_copy`, `<context_data>` fills the context; **cspec**
`<readonly>` sets `readonly`, `<context_data>`, `<global>` ranges are
collected and, after the whole cspec and its extensions, each added to
the global scope (and to every overlay of an overlaid space;
`addToGlobalScope`), then **the OTHER space and its overlays**
(`addOtherSpace`); `adjustCaches`; then **pspec `<default_symbols>`**
(`SleighArchitecture::buildSymbols`, sleigh_arch.cc:265–300): per
`<symbol name address [size] [volatile]>`, `address="next"` meaning the
previous symbol's address plus its size, size 0 meaning the space's word
size; `volatile` true/false sets or clears `volatil` over the symbol, so a
default symbol can override a pspec `<volatile>` range
(`DecompilerPspecVolatilityTest`); and every default symbol is added to
the global scope as `getBase(size, TYPE_UNKNOWN)` with no use limit; then
`fillinReadOnlyFromLoader` (each read-only range of the image sets
`readonly`). `readLoaderSymbols` (architecture.cc:345–358; run by the
data-test loader, testfunction.cc:159): each image symbol creates its
namespace path (`findCreateScopeFromSymbolName`) and a function there.
`globalify` (architecture.cc:436): every processor or spacebase space
wholly into the global scope (the console's `global spaces`).

This crate provides each of these as a function over a `Database` and
decoded data, named after Ghidra's; D07 calls them in this order. The
image oracle (W2) checks the result for the 93 data tests: property
change points, global bounds and entries (default symbols of the 8051,
ARM, AARCH64, 68000, MIPS and PowerPC pspecs, loader functions).

`ArchitectureGhidra::buildSymbols` (ghidra_arch.cc:375–431) differs: it
only applies `volatile` (symbols come from the host), and it updates the
"previous symbol" for `next` only after a symbol with `volatile` — so
`next` after a symbol without the attribute is computed from an older
one (4.21). The host-backed implementation follows the standalone rule.

### 4.19 The host trait: what the decompiler asks

Ghidra answers every service twice: from in-memory tables (the standalone
console and the data tests) and from the Java program database through
the `ghidra_*` classes, which cache what they receive. What is asked
(read, ghidra_arch.cc:494–931 and the classes):

| Ghidra call | Asked when | Answer | Cached where |
|---|---|---|---|
| `getMappedSymbolsXML(addr)` | `ScopeGhidra::findAddr`, `findContainer`, `findFunction`, `findExternalRef` miss the cache and `addr`'s space has a global range and `addr` is not in `holes` | a `<hole>` (range; `readonly`, `volatile`) or a `<mapsym>` inside an element whose `id` names the symbol's scope | the hole into `holes` (and property ranges, marking the cache dirty); the symbol into the scope `reresolveScope(id)` gives (the global cache for id 0, else the namespace, fetched by `getNamespacePath` if unknown); a namespace symbol's range also into `holes` |
| `getExternalRef(addr)` | `resolveExternalRefFunction` when the referenced function is not cached | a function `<mapsym>` | as above |
| `getNamespacePath(id)` | an unknown scope id in a reply | `<parent>` with `<val id label>name</val>` per level | `decodeScopePath` creates the namespaces (`ScopeGhidraNamespace`: every entry added extends its ownership range, database_ghidra.cc:398–402) |
| `isNameUsed(nm, startId, stopId)` | `ScopeGhidraNamespace::isNameUsed`, except names of the form `FUN_…`/`DAT_…` (assumed unused) | bool | no |
| `getCodeLabel(addr)` | `findCodeLabel` misses and no cached entry starts at `addr` | a name or empty | added as a label |
| `getDataType(name, id)` | `TypeFactoryGhidra::findById` misses | a type | the factory |
| `getComments(fad, mask)` | the first `beginComment` after `clear()` (one fill per clear, whatever the function), with `mask` = the printer's header and instruction comment types | `<commentdb>` | the internal database |
| `getBytes(addr, size)` | `loadFill` | bytes or "no data" (`GHIDRA has no data in the loadimage at <addr>`) | no |
| `getStringData(addr, type name, type id, maxBytes)` | `getStringData` miss | bytes and a truncation flag, or nothing (empty answer) | the string cache |
| `getCPoolRef(refs)` | `getRecord` miss | `<cpoolrec>`, or failure (`Could not retrieve constant pool record for reference: 0x<refs[0]>`) | the internal pool |
| `getTrackedRegisters(addr)` | every `getTrackedSet` | `<tracked_pointset>` | no (one buffer, overwritten) |

The cache layer's observable rules (database_ghidra.cc): `findAddr` asks
only when no cached entry *contains* `addr` (`findContainer(addr, 1,
invalid)` empty) and returns an entry only if it starts exactly at
`addr`; `findContainer` uses the cache's `findClosestFit` and asks on a
miss; `findSymbolBefore`/`findSymbolAfter` probe at 8-byte aligned
offsets around the container; `addSymbol` only adds to the cache (the
host is not told); `clear()` empties the cache and holes and restores the
property map to the defaults saved by `lockDefaultProperties` when
replies changed it; `findClosestFit`, `findOverlap`, `findByName`,
`isNameUsed`, iteration, `encode`, `decode` and every mutation except
attributes and display format are `… unimplemented` errors on the
host-backed global scope (they are answered by its cache only where the
table above says).

Basilisk's trait (5.4) carries the same questions as typed values, plus
ADR-025 3d (`function_summary`, `call_returns`) and 3f (provenance on
every symbol, name and type in both directions). The in-memory host is
the database itself; a program-database host (M4) plugs in below the
same cache layer.

### 4.20 Order sources (ADR-040, ADR-042)

No `std::sort` in this track's files (`grep` over `database.*`,
`comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*`,
`globalcontext.*`, `override.*`, `partmap.hh`, `rangemap.hh`: only a
commented-out call in `loadimage_bfd.cc`). Pointer-valued containers
exist (`set<Symbol *,SymbolCompareName>`, `set<Comment *,CommentOrder>`,
`map<Address,Record *>`) but none is *keyed* by a pointer: their orders
are names, dedup numbers, addresses and integers. The only order not
spelled out by a comparator is the order of equal fragments in an entry
map (4.2), which is fixed by the C++ standard's insertion rules and is
the same with libc++ and libstdc++ (W3). None of the 17 unclassified
sites of `docs/research/decomp-wave1/sorts.md` is in D06's files.

### 4.21 Defects, undefined behaviour and limits (for `docs/GHIDRA-BUGS.md`)

| # | Where | What | Status | Basilisk |
|---|---|---|---|---|
| 1 | `Scope::addMapSym` + `ScopeInternal::addMapInternal`, database.cc:2000, 2010–2015, 1727–1730 | An entry that runs past the end of its space is appended to the symbol before the check throws; the handler's `removeSymbol` erases the never-inserted entry through an indeterminate iterator | confirmed: SIGSEGV in `rangemap::erase` (W3) | checks first, changes nothing, returns the error |
| 2 | `ScopeInternal::encode` → `FunctionSymbol::encode` → `FuncProto::encode`, fspec.cc:4569 | An instantiated function without a prototype model encodes `model->getName()` of a null model | confirmed: SIGSEGV (W3) | D07's concern (`<function>`); noted for D07 |
| 3 | `Scope::addUnassigned`, database.cc:1294–1297 | Reads `entry->symbol` after `delete entry` | read | sets `persist` on the symbol |
| 4 | `Symbol::getMapEntryPosition`, database.cc:395 | Tests the argument's size instead of each entry's | read | reproduced (D00's dump and printing use it) |
| 5 | `ScopeInternal::clearCategory`/`clearUnlockedCategory`, database.cc:2175, 2226 | Dereference empty category slots | read | skips empty slots |
| 6 | `Symbol::getResolutionDepth`, database.cc:422–424 | Per-use-scope cache never invalidated by renames | read | reproduced |
| 7 | `LoadImageXml::open`, loadimage_xml.cc:115–135; `StringManager::decode`, stringmanage.cc:246–266 | Hex loop ends on a non-positive `char`; with unsigned `char` the end of text is 255 and the loop never ends; no validation of digits | read (the reference build adds `-fsigned-char` because of it, PROGRESS 2026-11-12) | signed-`char` result, always terminates |
| 8 | `CPoolRecord::encode`, cpool.cc:67 | Bytes written as characters, not hex | read | writes hex |
| 9 | `ConstantPool::putRecord`, cpool.cc:160 | `flags`, `value` (and `byteDataLen`) uninitialised | read | zero |
| 10 | `CheapSorter(refs)`, cpool.hh:182 | `refs[0]` of an empty list | read | error |
| 11 | `CPoolRecord::decode`, cpool.cc:141–145 | Fewer hex tokens than `length` leaves bytes indeterminate | read | error |
| 12 | `ContextInternal::decodeContext`, globalcontext.cc:355–358 | Zeroes the whole default before each `<set>` | read | zeroes once per element |
| 13 | `ArchitectureGhidra::buildSymbols`, ghidra_arch.cc:405–429 | `next` resolved from the last *volatile* symbol | read | standalone rule |
| 14 | `RawLoadImage::open`, loadimage.cc:60 | `ifstream` in text mode: CR LF translation on Windows | read | bytes as given |
| 15 | `LoadImageXml::adjustVma`, loadimage_xml.cc:284 | Offset truncated to `int4` | read | 64-bit wrapping |
| 16 | `Architecture::decodeFlowOverride`, architecture.cc:475–476 | `closeElement` called twice | read | closes once |
| 17 | `CommentDatabaseInternal::addComment`, comment.cc:182–193 | Past 65,535 comments at one address the new comment's key exists; the set refuses it and the object leaks | read | error |
| 18 | `StringManagerUnicode::getStringData`, stringmanage.cc:466–468 | Checks for a terminator only within each 32-byte read at multiples of `charsize`; a read cut short by `maximumChars` that is not a multiple of `charsize` reads past it (unreachable with 2048) | read | bounded reads |

Limits (ADR-009), all with typed errors: a namespace path of at most 64
components and a scope tree of at most 1,024 levels (recursion in
`encodeRecursive`, `clearReferences`, `deleteScope` becomes iteration);
names of at most 64 KiB; a string read of at most `maximumChars` bytes;
`<data>` of at most 1 MiB (Ghidra's `MAX_STRING_SIZE`); at most 2³²−1
symbols per scope (`nextUniqueId` and `catindex` are 32-bit in Basilisk,
Ghidra uses `uint8`/`uint2` — `catindex` above 65,535 wraps in Ghidra,
read database.hh:259; Basilisk errors); context of at most 64 words.
