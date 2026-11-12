# Language definitions and registry (`bk-lang`)

Track `lang`, wave 1, milestone M0. Format of this document:
`docs/LOOP.md`, "Feature documents".

Path abbreviations: `SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/`,
`RXG/` = `Ghidra/Framework/SoftwareModeling/data/languages/`,
`BASE/` = `Ghidra/Features/Base/src/main/java/`,
`P/` = `Ghidra/Processors/`, all under `../ghidra`.

## 1. Purpose

Ghidra describes each processor language with data files beside its SLEIGH
spec. `bk-lang` reads them into typed models and provides the registry
that answers "which languages exist", "what is `x86:LE:64:default`" and
"which language and compiler should load this file" — the first thing
every tool needs before it can touch a binary.

## 2. Ghidra sources

| Source | What to take from it |
|---|---|
| `RXG/language_definitions.rxg`, `processor_spec.rxg`, `format_opinions.rxg`, `language_common.rxg` | The RELAX NG schemas: the authoritative grammar of `.ldefs`, `.pspec` and `.opinion` files (`compiler_spec.rxg` is for M3) |
| `SM/ghidra/app/plugin/processors/sleigh/SleighLanguageProvider.java`, `SleighLanguageDescription.java`, `SleighCompilerSpecDescription.java`, `SleighLanguageValidator.java` | How `.ldefs` files are found and read; defaults; validation; deprecated languages; `truncate_space` |
| `SM/ghidra/program/model/lang/` — `LanguageID`, `CompilerSpecID`, `LanguageCompilerSpecPair`, `Endian`, `Processor`, `LanguageDescription`, `BasicLanguageDescription`, `CompilerSpecDescription`, `LanguageCompilerSpecQuery`, `ExternalLanguageCompilerSpecQuery`, `LanguageService`, `GhidraLanguagePropertyKeys` | The identity types, the description model, the query model, the property keys |
| `SM/ghidra/program/util/DefaultLanguageService.java` | The registry: discovery, lookup, queries, external-name lookup |
| `SM/ghidra/app/plugin/processors/sleigh/SleighLanguage.java` — the `.pspec` reading (`readInitialDescription`, `read(XmlPullParser)` and the methods it calls, `parseSegmentOp`, register and context handling) | What each `.pspec` element means on the Java side |
| `Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc` — `parseProcessorConfig` and the `decode*` methods it calls | What the decompiler takes from the same `.pspec` (some elements are read only here) |
| `BASE/ghidra/app/util/opinion/QueryOpinionService.java`, `QueryOpinionServiceHandler.java`, `QueryResult.java`, and `LoadSpec.java` | `.opinion` files: nesting, attribute inheritance, lookup by loader name and primary/secondary key, the preferred flag |
| `P/*/data/languages/*.ldefs` (51 files, 194 languages), `*.pspec` (88), `*.opinion` (29) | The corpus |

## 3. Scope

**In:** `.ldefs`, `.pspec` and `.opinion` readers; identity types; the
language registry; opinion queries. **Crate owned:** `bk-lang`. It has
**no dependency on other `bk-*` crates** in this wave: read XML with
`roxmltree` directly (ADR-011) — the files are plain attribute-and-element
XML — and represent register names, space names and addresses as the
strings and integers the files contain. Resolving them against a loaded
SLEIGH language is M1's job.

**Not in this track:** `.cspec` (compiler specs: M3, with the decompiler's
prototype models); loading `.sla` files or anything that needs registers
resolved; the old-language translators (`data/languages/old/*.lang` and
`*.trans`, used to upgrade programs saved with older language versions —
there are no old basilisk programs; revisit in M8 and record it as a gap);
`.dwarf` register mappings (M6); pattern files (M5).

## 4. Behaviour

### 4.1 Identity types
- `LanguageID`: a non-empty string, conventionally
  `processor:endian:size:variant`; equality and ordering by string. Ghidra
  does not parse it into fields and neither should basilisk — the fields
  come from the description.
- `CompilerSpecID`: a string; `default` has no special lookup meaning
  except what `SleighLanguageDescription` gives it — check
  `getCompilerSpecDescriptionByID` and the fallback behaviour when an id
  is not found.
- `LanguageCompilerSpecPair`, `Endian` (`big`/`little`, and the display
  and parse forms Ghidra accepts), `Processor` (a name; Ghidra keeps a
  global registry of names — basilisk interns them in the registry
  instead).

### 4.2 `.ldefs`
`language_definitions` holds `language` elements with attributes
`processor`, `endian`, `size`, `variant`, `version` (`major.minor`),
`slafile`, `processorspec`, `manualindexfile` (optional), `id`,
`instructionEndian` (optional), `deprecated` (optional), and children:
`description` (text), `compiler` (`name`, `spec`, `id`; repeated),
`external_name` (`tool`, `name`; repeated; several names per tool),
`truncate_space` (`space`, `size`). Take every attribute, default and
validation rule from the schema and `SleighLanguageProvider.read`: which
are required, how versions are parsed and compared, how file names
resolve relative to the `.ldefs` file's directory, what happens on a
duplicate language id (Ghidra reports and keeps one — match which) and on
a missing `.slaspec`/`.sla`/`.pspec` file.

### 4.3 `.pspec`
`processor_spec` and all of its children, as typed data. From the corpus
these occur: `properties`/`property` (`key`, `value`; the keys Ghidra
understands are in `GhidraLanguagePropertyKeys`, but unknown keys are kept),
`programcounter`, `data_space`, `context_data` with `context_set` and
`tracked_set` (each over a `space` and optional `first`/`last` range, with
`set` children giving `name`, `val` and optional `description`),
`register_data`/`register` (`name`, `group`, `hidden`, `rename`, `alias`,
`vector_lane_sizes`), `default_symbols`/`symbol` (`name`, `address`,
`entry`, `type`), `default_memory_blocks`/`memory_block` (`name`,
`start_address`, `length`, `mode`, `initialized`, `bit_mapped_address`,
`byte_mapped_address`), `volatile` with `range` and `register` children
(and the `outputop`/`inputop` attributes), `incidentalcopy`,
`inferptrbounds`, `segmented_address`, `segmentop` (with its `pcode`,
`body`, `input`, `output`, `constresolve`), `jumpassist` (with
`case_pcode`, `addr_pcode`, `default_pcode`, `size_pcode`). The schema is
the complete list — model every element and attribute in it, including
those no shipped file uses.

Addresses in these files are written as `space:offset` or a bare offset in
the default space, sometimes with a register name; keep them in a parsed
but unresolved form (space name optional, offset, as written) with a
resolver hook for later. P-code bodies (`segmentop`, `jumpassist`) are kept
as source text with their declared inputs and outputs.

### 4.4 `.opinion`
`opinions` holds nested `constraint` elements. A constraint may give
`loader`, `compilerSpecID`, `primary`, `secondary`, `processor`, `endian`,
`size`, `variant`; children inherit and may override their ancestors'
attributes; a leaf with a complete set yields one entry. Lookup is by
loader name, primary key and optional secondary key and returns the
matching language/compiler pairs with their preferred flag. Reproduce
`QueryOpinionService` exactly: how `primary` values are compared (they are
strings; loaders pass decimal machine numbers), how `secondary` is matched
(read the code — it is not plain equality in every case), how a query with
missing fields widens, the ordering of results, and how entries map to
languages in the registry (by processor, endian, size, variant against the
language descriptions, not by id).

### 4.5 Registry
Built from a spec root: scan `Ghidra/Processors/*/data/languages/*.ldefs`
under `BASILISK_GHIDRA_DIR` (default `../ghidra`), and additional roots
the caller adds (a user's own processor module; the `../reference` overlay
that holds compiled `.sla` files, see `features/reference-tools.md`). It
provides: all language descriptions; lookup by `LanguageID`; lookup of a
compiler spec description; the default language for a processor;
`LanguageCompilerSpecQuery` matching (processor, endian, size, variant,
compiler — each optional) with Ghidra's result ordering;
`ExternalLanguageCompilerSpecQuery` (by external tool name); resolved
paths of the `.slaspec`, `.sla`, `.pspec` and `.cspec` files; and lazy,
cached loading of the parsed `.pspec`. Loading is lazy and the registry is
immutable and `Send + Sync` once built: scanning 51 small files must not
parse 88 processor specs.

## 5. Design

- Modules: `id`, `endian`, `ldefs/{model, read}`, `pspec/{model, read,
  context, registers, symbols, memory, segment}`, `opinion/{model, read,
  query}`, `registry/{scan, query, paths}`, `error`.
- Readers are strict by default — an element or attribute the schema does
  not allow is an error naming the file and position — with a lenient
  mode that collects warnings instead, for user-supplied modules.
- Errors: `thiserror` enums carrying file path, line and what was
  expected. No panics on any file content (ADR-009).
- No global state: a `LanguageRegistry` value is passed where needed.

## 6. Tests

- **Port** `ghidra.app.util.opinion.QueryOpinionServiceTest` (4) and mark
  it in `docs/inventory/tests/features-base.md`.
- **Port what applies** of
  `ghidra.app.plugin.processors.sleigh.SleighLanguageProviderTest` (4,
  slow): it exercises `.ldefs` discovery and error handling together with
  `.sla` compilation; port the discovery and description parts, and in
  the checklist note which assertions wait for M1/M2. Look through
  `docs/inventory/tests/framework-softwaremodeling.md` and
  `features-base.md` for other tests of the classes in section 2 that need
  no program or `.sla` (`LanguageID`, `CompilerSpecID`, `Endian`,
  `LanguageCompilerSpecPair`, query classes) and port those too.
- **Corpus tests** (skip when `../ghidra` is absent): every `.ldefs`,
  `.pspec` and `.opinion` under `P/` reads in strict mode; the registry
  holds exactly 194 languages from 51 files, with no duplicate ids; every
  file a description names exists (allowing `.sla` to be absent); every
  `.opinion` entry maps to at least one language. Any corpus file that
  violates its schema is recorded in the status section, and strict mode
  is adjusted to the documented reality.
- **Golden tests:** the parsed model of `x86.ldefs`, `x86.pspec`,
  `x86.opinion` and one small processor, as snapshots.
- **Derived tests:** each `.pspec` element form; opinion inheritance and
  override; query ordering; lenient-mode warnings; error messages with
  positions; version comparison.
- **Property test / fuzz target:** the three readers never panic on
  arbitrary bytes.
- **Benchmark:** registry scan of the full spec root (target: under
  50 ms); numbers in `PERF.md`.

## 7. Acceptance

1. The listed Ghidra tests pass in ported form and are marked.
2. The corpus tests pass over all 39 processor modules.
3. Every element and attribute in the three schemas is modelled, and a
   test asserts this against the `.rxg` files (for example by walking the
   schema and checking each name is handled).
4. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- No global `Processor` registry or language-service singleton; the
  registry is a value.
- `.pspec` is read once into a complete typed model shared by all
  consumers, where Ghidra reads it separately in Java and in the C++
  decompiler.
- Old-language translators are not read (gap, see Scope).

(The implementing agent appends further differences here.)

## 9. Status

Not implemented yet.
