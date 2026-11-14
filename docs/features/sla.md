# The compiled-language file: model, reader, writer (`bk-sla`)

Track `sla`, milestone M1 (first SLEIGH track; everything else in M1 and M2
builds on it). Format of this document: `docs/LOOP.md`, "Feature
documents". Background that this spec relies on and does not repeat:
`docs/inventory/01-sleigh.md` sections 1 (the model), 2 (the format,
element by element) and 12 (corpus facts).

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`, under
`../ghidra`; `REF` = `../reference`.

## 1. Purpose

A `.sla` file is a processor specification compiled by SLEIGH: symbols,
constructors, decision trees and p-code templates. `bk-sla` is the one
place that knows this file: an in-memory model of exactly what the file
holds, laid out for instruction decoding; a reader that validates
untrusted input; and writers that reproduce Ghidra's bytes. The SLEIGH
runtime (`bk-sleigh`) decodes instructions straight from this model; the
SLEIGH compiler (`bk-sleigh-compiler`) produces it.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/slaformat.hh`, `slaformat.cc` | Header, format version 4, the format-scope element and attribute ids, `FormatEncode`/`FormatDecode` (zlib container) |
| `CPP/sleighbase.cc` | `SleighBase::encode`/`decode`, `encodeSlaSpace`/`decodeSlaSpace(s)`, `SourceFileIndexer::encode`/`decode` |
| `CPP/slghsymbol.cc` | `SymbolTable::encode`/`decode`/`decodeSymbolHeader` and every symbol's, `Constructor`'s, `DecisionNode`'s, `ContextOp`'s, `ContextCommit`'s `encode`/`decode` |
| `CPP/slghpattern.cc` | `PatternBlock`, `InstructionPattern`, `ContextPattern`, `CombinePattern` `encode`/`decode`, `DisjointPattern::decodeDisjoint`, `PatternBlock::normalize` |
| `CPP/slghpatexpress.cc` | `PatternExpression::decodeExpression` and each expression's `encode`/`decode` |
| `CPP/semantics.cc` | `ConstTpl`, `VarnodeTpl`, `HandleTpl`, `OpTpl`, `ConstructTpl` `encode`/`decode` |
| `SM/pcode/utils/SlaFormat.java`, `SM/app/plugin/processors/sleigh/**` | The Java twin; cross-check only |

**C++ is authoritative.** The reference files in `REF` are written by it.

## 3. Scope

**In.** Crate **`bk-sla`** (new, owned by this track):
the format-scope id table; the model; reading the container and the packed
stream; reading the XML (`sleigh -y`) form; validation and limits; writing
the packed stream, the container and the XML form; a builder for
producers; a structural diff of two models; construction of the address
spaces a file declares.

**Not in.** Anything that *uses* the model: decoding instructions,
evaluating expressions, printing, p-code (`sleigh-decode`, `sleigh-pcode`);
derived tables such as the register map (`sleigh-decode`); producing a
model from source (`sleigh-compiler-*`). No dependency on `bk-lang`,
`bk-sleigh-syntax` or `bk-testkit` (the last is a dev-dependency).

Dependencies: `bk-marshal` (packed and XML encoders/decoders, `IdTable`),
`bk-core` (`Space`, `SpaceManager`, `SpaceId`), `bk-pcode` (`OpCode`),
`flate2` with the `zlib-rs` backend (ADR-011), `thiserror`.

## 4. Behaviour

### 4.1 What a file contains
Inventory section 2 is the normative grammar: element names and ids,
attribute names, ids, order and value types, and the "details that are
easy to get wrong". The model holds every value in that grammar, including
the ones the runtime does not use (decision `number`, the attributes of
`space_unique` and `space_other`, constructor `source`/`line`, operand and
subtable names), because the writer must reproduce them.

### 4.2 Reading
`read(bytes)`: check the four header bytes (`s`,`l`,`a`,`4`); inflate the
rest; decode the packed `<sleigh>` element; validate. `decode_packed`
(an already inflated stream) and `decode_xml` (the text `sleigh -y`
writes) give the same model for the same document. Ghidra itself reads
only the packed form; the XML reader exists for fixtures, tools and tests.

Reading follows the C++ decoder where it is tolerant, so that every file
Ghidra loads loads here:

* attributes of `sleigh`, the space elements, `context_sym`, `operand_sym`
  and `construct_tpl` may come in any order, and unknown attributes on
  them are skipped; elsewhere attributes are looked up by id;
* symbol bodies may come in any order and are matched by `id`; a symbol
  with a head and no body keeps its kind with empty content only for
  kinds that have none (`start_sym`, `end_sym`, `next2_sym`,
  `epsilon_sym`); otherwise it is an error (the C++ would leave it
  half-initialised and crash later);
* `pat_block` is normalised on read exactly as `PatternBlock::normalize`
  does (inventory section 10, b.1);
* `nametab` without `name` is an unusable entry; a `name` of `_` or a
  single tab is also read as unusable (`NameSymbol::checkTableFill`);
* the `version` attribute must be 4, as must the header byte.

### 4.3 Validation
The file is untrusted (ADR-009). After decoding, and before the model is
handed out, all of the following hold or `read` fails with an error that
names the element path, the symbol or constructor concerned and, for the
packed form, the byte offset. A model that passes can be used by the
runtime with unchecked-by-construction indices.

1. Every id refers to an existing object of the right kind: scope parents;
   symbol scopes; `subsym` → a value, value-map, name, varnode, context,
   varnode-list, start, end, next2, epsilon or subtable symbol;
   `context_sym.varnode` and `var.id` → varnode symbols; `oper.id` →
   operand symbols, each owned by exactly one constructor; `commit.id` →
   any symbol that has a fixed handle (every kind except subtable and
   user op); `operand_exp.table` → a subtable and `ct` < its `numct`;
   `pair.id` < the table's `numct`; `constructor.parent` = the enclosing
   subtable; space references → a declared space or the constant space.
2. Shapes: `numct` equals the number of `constructor` children; a subtable
   has exactly one `decision`; a decision node has `size` in 0..=8, no
   children when `size` is 0, exactly `2^size` children and no pairs
   otherwise; a constructor has at most one main template and at most one
   template per section number, each section number < `numsections`;
   `first` is between −1 and the number of print pieces inclusive (it
   equals the number of pieces when the white space it pointed at was the
   trailing piece the compiler removed — [run] 39,921 shipped
   constructors); `opprint.id` and every
   `const_handle.val`, `BUILD` operand index and `operand_exp.index` is <
   the number of operands of the constructor it belongs to; `operand.index`
   equals the operand's position in its constructor; `operand.base` is −1
   or < `operand.index`; label numbers (`LABEL`, `const_relative`) are <
   the template's `labels`; `const_handle.s` is 0..=3; an operand has a
   defining symbol or a defining expression, not both and not neither.
3. Value ranges: `off`, `minlen`, `length`, `delay` ≥ 0 and below the
   instruction limit of 4.4; `tokenfield`: 0 ≤ `startbit` ≤ `endbit`,
   `startbyte` ≤ `endbyte`, at most 8 bytes, `shift` in 0..=7, and the
   field fits the bytes read; `contextfield`: likewise, at most 32 bits;
   `context_op.i`, `commit.number` ≥ 0 and below the context size the
   file's context fields imply plus a small margin (4.4); `shift` in
   0..=31; opcodes are valid `OpCode` values; a directive op has the
   inputs inventory section 1.7 lists; varnode-symbol sizes > 0.
4. No operand's defining expression depends on itself through
   `operand_exp` references (a cycle would recurse forever at decode
   time), and no subtable's flow-through printing chain is infinite by
   construction of the file alone (a constructor flowing through to its
   own table is legal — recursion is bounded by the bytes at run time —
   so this is *not* rejected; the runtime bounds depth).
5. Spaces: indices unique and non-zero; `defaultspace` names a declared
   space; at most one `space_unique` and one `space_other`.
6. Symbol names are valid UTF-8 (the packed decoder already requires it);
   two global symbols may not share a name; exactly one global symbol is
   named `instruction` and it is a subtable.

Checks 1–6 pass on all 150 reference files (acceptance 1; the operand
rules of check 2 — position equals `index`, `base` below `index`, exactly
one of defining symbol and expression, the first child naming the operand
itself, one owning constructor — were confirmed on the 338,715 shipped
operands when this spec was written). Where Ghidra
accepts a file that these checks reject, that is a deliberate difference
(section 8), except that no shipped or compiler-produced file may be
rejected.

### 4.4 Limits
All configurable through a `Limits` value with these defaults; exceeding
one is an error, never a panic or an unbounded allocation.

| Limit | Default | Ghidra |
|---|---|---|
| Inflated size | 1 GiB | Java: 2 GiB; C++: none |
| Scopes / symbols | 0x100000 / 0x1000000 | same (`SymbolTable::MAX_TABLES`, `MAX_SYMBOLS`) |
| Element nesting | 256 | none (corpus maximum: 27) |
| Expression nesting | 64 | none |
| Decision-tree depth | 64 | none (corpus maximum: 19) |
| Operands per constructor | 255 | none in the file (corpus maximum: 27) |
| Inputs per op template | 255 | none (corpus maximum: 10) |
| Byte quantities (`off`, `minlen`, `length`, `delay`) | 65,535 | none |
| Context words addressed | 1,024 | none |

Memory the reader allocates is bounded by a constant multiple of the
inflated size: no count read from the stream (`scopesize`, `symbolsize`,
`numct`, a decision node's `2^size`) is trusted for allocation beyond what
the remaining input could hold.

### 4.5 Writing
* `encode_packed(&model)` writes the stream exactly as the C++ `encode`
  methods do — element order, attribute order, attribute value types and
  the conditions under which optional attributes appear (inventory section
  2). For a model read from a reference file the output equals the
  inflated input **byte for byte**.
* `write(&model)` = the header and the stream deflated in zlib format at
  the default level. Compressed bytes are not required to equal Ghidra's
  (ADR-011) and nothing may depend on them; the stream inside is.
* `encode_xml(&model)` writes the text `sleigh -y` writes: `bk-marshal`'s
  XML encoder in formatted mode, element and attribute names of the format
  scope, spaces by name, opcodes by `OpCode::name()`.
* `decode(encode(m)) == m` for every model the builder can produce, in
  both forms.

### 4.6 Address spaces
`spaces(&model) -> SpaceManager`-building follows `decodeSlaSpaces`: the
constant space first; then each declared space in file order through
`bk_core`'s constructors — `space_unique` → the unique space at the given
index with the language's endianness; `space_other` → the OTHER space;
`space` → a processor space with the file's name, size, word size, delay
(dead-code delay equal to it) and `physical` flag, endianness of the
language; then the default code space by name. The reader needs space
references resolved while it reads the rest of the document, so the spaces
element is decoded first and the decoder is created on the manager's
`directory()` (see `docs/agents/core-marshal.md`, "Decoding `.sla`
spaces").

### 4.7 Platforms (ADR-022)
Files are read whole with `std::fs::read` and written with a temporary
file renamed into place; no memory mapping, no file locking, nothing
Unix-only. Paths are `Path`s, never strings with `/`. The crate's tests
run on Windows, macOS and Linux; the tests that need `REF` skip where it
is absent.

## 5. Design

### 5.1 Layout: serve decoding first
The model is the runtime's working data, so its layout is chosen for the
decode loop (ADR-012), with the writer as the second client:

* One `Sla` value owning flat arenas; everything else is typed `u32`
  indices and ranges into them (`SymbolId`, `ScopeId`, `ConstructorId`,
  `ExprId`, `TemplateId`, `DecisionId`, `PatternId`, `StrId`, …). No `Box`,
  `Rc` or per-object `Vec` in the steady-state structures. `Sla` is
  immutable after construction, `Send + Sync`, and shared as `Arc<Sla>`.
* Symbols: `Vec<Symbol>` indexed by id, `Symbol { name, scope, kind }`
  with `kind` an enum over the kinds of inventory section 1.2. A subtable
  holds a contiguous `ConstructorId` range (its constructor `i` is
  `first + i`) and its root `DecisionId`.
* Constructors: one arena; each holds ranges into shared arenas for its
  operand ids, print pieces, context changes, and its templates (main
  first, then by section), plus the scalars.
* Decision nodes: one arena; a node's children are a contiguous run so
  that the child for field value `v` is `first_child + v` with no search
  and no second table. (The file nests children depth-first; allocate the
  run when the node's `size` is known and fill it as the children are
  read, or renumber breadth-first after reading — but see 4.4 on not
  trusting `2^size` before the children are seen.) Leaf pairs are a range
  into a pair arena; patterns hold up to two block ids; blocks hold a
  range into one `(mask, value)` word arena.
* Templates: op templates in one arena, each a range into one
  `VarnodeTpl` arena (output slot first, a flag for "no output");
  `VarnodeTpl` is three `ConstTpl`; `ConstTpl` is a `Copy` enum of at most
  16 bytes. Handle templates in their own arena.
* Expressions: one arena of small nodes with child `ExprId`s; token and
  context fields are stored inline or in a side arena, whichever keeps the
  node at 16 bytes or less.
* Strings (symbol names, print pieces, name tables, source files): one
  byte arena with `(offset, length)` handles; borrowed out as `&str`.
* Sizes are asserted in tests: `ConstTpl` ≤ 16 bytes, `VarnodeTpl` ≤ 48,
  `Expr` ≤ 16, decision node ≤ 24, pattern block header ≤ 16.

### 5.2 API sketch
```
Sla::read(bytes, &Limits) / read_file(path, &Limits)      -> Result<Sla, SlaError>
Sla::decode_packed(stream, &Limits) / decode_xml(text, &Limits)
sla.write() -> Vec<u8>;  sla.encode_packed() -> Vec<u8>;  sla.encode_xml() -> String
sla.header(), source_files(), space_records(), build_spaces() -> Result<SpaceManager, _>
sla.symbols(), symbol(id), global(name) -> Option<SymbolId>, root() -> SymbolId
sla.constructor(id), operands(ctor), print_pieces(ctor), context_changes(ctor),
    main_template(ctor), section_template(ctor, n)
sla.decision(id), children(id), pairs(id), pattern(id), block(id)
sla.expr(id), template(id), ops(template), inputs(op), output(op), handle(template)
SlaBuilder  — the producer's interface: add scopes, symbols, constructors,
              templates, patterns, decision nodes; `finish()` runs the same
              validation as the reader and returns an `Sla`
diff(&a, &b) -> Vec<Difference>   — structural, with a path for each difference
              ("table `instruction` constructor 12 (ia.sinc:155) main op 3
              input 1 offset: const_real 0x10 ≠ const_real 0x20"), capped
```
A template can also live outside a file: `Template` is an owned value
with the same `ConstTpl`/`VarnodeTpl`/op/handle types and its own small
arenas, with `encode_xml`/`encode_packed`/`decode` of a lone
`construct_tpl` element. P-code snippets compiled for injection
(`features/sleigh-snippet.md`) are such templates, and the runtime builds
p-code from either kind through one borrowed view (`TemplateRef`).

`SlaError` (`thiserror`) distinguishes container errors (header, zlib,
size), stream errors (from `bk-marshal`, with offset), structure errors
(validation 1–6) and limit errors.

### 5.3 Performance
Reading is on the language-load path, whose budget is Ghidra's own load
time (`PERF.md`: x86-64 in 41–48 ms including `.ldefs` and `.pspec`;
`Sleigh::initialize` alone 32–43 ms, inventory section 8a). `bk-sla` gets
most of that budget: see the benchmark in section 6.

`bk-marshal`'s generic `Decoder` re-scans attributes for lookups by id
(`PERF.md`, "bk-marshal"); read attributes in stream order on the frequent
elements (`const_real`, `varnode_tpl`, `const_spaceid`, `const_handle`,
`op_tpl`, `mask_word`, `pat_block`, `print`, `decision`, `operand_*`,
`pair` — [census] 95 % of all elements). If the generic decoder still
cannot meet the budget, the crate may read the packed stream with its own
cursor over the `&[u8]` (the format has five header forms), keeping the
generic path for XML; acceptance 1–3 then run through both paths and
compare the models.

## 6. Tests

**Ghidra tests to port.** None targets the file format on its own (the
format is exercised through language loading; those tests belong to
`sleigh-decode` and `sleigh-language`). Stated so the checklist is not
searched again.

**Differential against Ghidra (need `REF`; skip without it, ADR-007):**

1. *Round trip, packed.* For each of the 150 reference `.sla` files:
   `encode_packed(read(file))` equals the inflated file, byte for byte.
2. *XML text.* For each of the 150 `.slaspec` files: run `REF/bin/sleigh
   -y` with the module's options (through `bk-testkit`'s `sleigh()`
   wrapper; the tool appends `.sla` to the output name) and compare its
   output text with `encode_xml(read(reference .sla))` — equal, byte for
   byte. This checks the reader's understanding of every value against a
   second rendering Ghidra produced itself.
3. *XML reader and validation.* `decode_xml(that text)` equals the model
   from the packed file, and every file passes validation.
4. *Mutation check* (the track proves the tests can fail): flipping one
   attribute value in a decoded model makes 1 and 2 fail; listed in the
   status report with the mutations tried.

**Derived tests:** one hand-written fixture per element kind and per
optional attribute (including the kinds the corpus never contains:
`epsilon_sym`, `next2_exp`, `const_flowref`/`flowdest` and their sizes),
built with `SlaBuilder` and through XML; each validation rule of 4.3 with
a fixture that violates exactly it; each limit of 4.4; header errors;
truncated zlib stream; trailing bytes after the stream.

**Property tests (`proptest`):** generated models round-trip through both
forms; arbitrary bytes never panic in `read`, `decode_packed`,
`decode_xml`.

**Fuzz targets** (shared `fuzz/` crate): `bk_sla_read` (container) and
`bk_sla_decode_packed` (stream, so the fuzzer is not fighting zlib); each
also re-encodes what decoded and checks `decode(encode(m)) == m`. Seeds:
the smallest reference files. Sixty seconds each without a finding;
regressions replayed by a normal test.

**Benchmarks** (`#[ignore]` release tests, numbers in `PERF.md`):
`read_file` of `x86-64.sla`, of `AARCH64BE.sla` (the largest), and of all
150 in sequence; the same for `encode_packed`; heap size of the x86-64
model (`dhat`, as `bk-elf` does).

## 7. Acceptance

1. Differential tests 1–3 pass for all 150 languages; 4 is reported.
2. Every validation rule and limit has a failing fixture and a passing
   corpus; no panic on any input; both fuzz targets run 60 s clean.
3. `read_file("x86-64.sla")` (file read, inflate, decode, validate) takes
   at most 25 ms on the machine of `PERF.md`, measured in the same session
   as a fresh run of the reference loader (command in
   `docs/agents/spec-sleigh.md`), and in any case is not slower than that
   run; all 150 files load in under 1 s on one thread. The x86-64 model's
   heap is at most 8× the inflated stream (36 MB); the figure is recorded.
4. Struct sizes of 5.1 are asserted. `Sla: Send + Sync` is asserted.
5. Gate green on macOS; `cargo check --target x86_64-pc-windows-msvc`
   passes; the tests that do not need `REF` pass on all three systems in
   CI.

## 8. Differences from Ghidra

* Validation (4.3) and limits (4.4): Ghidra checks a handful of ids and
  crashes or misbehaves on the rest; Basilisk rejects the file. In
  particular decision nodes wider than 8 bits, operand `base` not below
  its own index, and operand-expression cycles are rejected.
* An XML form can be read (Ghidra only writes it).
* `next2_exp` is read (the C++ decoder has no case for it and fails; the
  Java reads it: `SM/app/plugin/processors/sleigh/expression/PatternExpression.java`
  handles `ELEM_NEXT2_EXP`).
* The model is one immutable arena value, not a graph of objects.

(The implementing track appends.)

Appended by the `sla` track (2026-11-14):

* **Values that do not fit the C++ field are rejected**, not truncated:
  an attribute Ghidra stores in `int4`/`uint4`/`uintm` (most of them; mask
  words, masks, `uniqbase`) must fit 32 bits, a handle index or pair id must
  not be negative. Truncation would make the round trip lossy.
* **Strings containing NUL are rejected** (reader and builder): the packed
  form cannot hold them (`bk-marshal` refuses to encode them), so such a
  model could not be written back. Found by the `bk_sla_decode_packed`
  fuzzer; the input is kept in `fuzz/regressions/bk_sla_decode_packed/`.
* **Stricter grammar where Ghidra guesses**: a symbol body must be of the
  kind its head announced; an unknown element inside `<spaces>` (Ghidra
  makes it a processor space), inside `varlist_sym` (Ghidra reads it as an
  unusable entry) or inside a constructor (Ghidra reads it as a template)
  is an error; `or_pat` in a pair is an error (the C++ would misread it as
  `combine_pat`); a subtable without a decision tree is an error (the C++
  silently omits such a subtable's body when writing); source-file indices
  must be dense from 0 (the C++ writer would throw on a gap); bytes after
  the zlib stream and data after `</sleigh>` are errors.
* **Extra validation** beyond 4.3, each true of all 150 reference files:
  the field of a value, value-map, name or varnode-list symbol is a value
  expression (the C++ casts it to `PatternValue`); a context symbol's field
  is a context field; varnode-symbol sizes are positive; an operand's
  defining symbol is not an operand or user op; pattern-block offsets are
  byte quantities; expression children precede their parents (so trees are
  acyclic and their depth is checked in one pass).
* **The context-word margin of 4.3 rule 3 is zero**: `context_op.i` and
  `commit.number` must be below `Sla::context_words()` (the largest
  `endbit / 32 + 1` over all context fields). Every compiler-produced change
  derives from a context field, so no shipped file is affected; the runtime
  sizes its context array from `context_words()`.
* **Space attributes are kept per space**, including each space's
  `bigendian` (the C++ processor space takes its own; unique and other spaces
  ignore it) and the ignored attributes of `space_unique`/`space_other`. A
  unique or other space missing an attribute gets the value the C++ loader's
  object would write (`unique`/4 bytes/physical, `OTHER`/8 bytes).
* **Space references are resolved against the file's own space records**,
  not through a `SpaceManager` built while reading (4.6 suggested the
  manager's directory). The model stores space indices; `build_spaces()`
  builds the manager on demand. Same accepted files, no manager needed to
  read.
* **Duplicate attributes**: the last occurrence wins (Ghidra's lookup by id
  takes the first). Malformed either way; no file has one.
* **Model equality is structural** (`PartialEq` goes through `diff`), so
  models read from differently ordered but equivalent documents compare
  equal.

Note of 2026-11-14 (track `sleigh-fixups`): **label numbers are no longer
checked when reading.** The rule of 4.3 item 2 "label numbers (`LABEL`,
`const_relative`) are < the template's `labels`" is now a separate,
explicit check, `Template::check_labels` and `Sla::check_labels`, which
also requires every branch to a label (an op whose first input is a
`const_relative`) to name a label the same template places. Ghidra's
decoders (`ConstructTpl::decode`/`OpTpl::decode`, `semantics.cc`; Java
`ConstructTpl.decode`) do not check labels, and its snippet compiler
produces a branch to a label that is never placed; such a template fails
only when p-code is built from it (`PcodeCacher::resolveRelatives`,
`sleigh.cc` 96-110: "Reference to non-existant sleigh label"), which
`bk-sleigh` reproduces as `LiftError::MissingLabel`, bounded and without
allocating per label number. All 150 reference files pass the check.

## 9. Status

Done (track `sla`, 2026-11-14). Crate `crates/bk-sla`:

* `ids` (format-scope table), `model` (arenas, typed ids, struct sizes
  asserted, `Sla: Send + Sync` asserted), `read` (container with size limit,
  this crate's packed cursor, `bk-marshal` packed and XML adapters, one
  generic model decoder), `validate` (4.3 and 4.4), `write` (packed,
  container through a temporary file, XML), `builder` (`SlaBuilder`),
  `diff` (structural, capped, with paths), `spaces` (`build_spaces`),
  `template_codec` (standalone `Template` with `SpaceTable`).
* Differential tests 1–3 pass for all 150 reference languages; test 1 also
  runs through `bk-marshal`'s packed decoder and compares models. Test 4:
  twelve single-attribute model mutations each fail tests 1 and 2; three of
  four code mutations of the writer/reader are caught by tests 1–2, the
  fourth (skipping `PatternBlock::normalize` on read) only by the unit and
  fixture tests, because the reference files are already normalised.
* Fixtures: one model with every element kind and optional attribute
  (including `epsilon_sym`, `next2_exp`, `const_flowref*`); one violating
  fixture per validation rule and per limit; header, truncated zlib and
  trailing-byte errors. Property tests and two fuzz targets (60 s each,
  clean after the NUL fix).
* Performance (`PERF.md`): `read_file("x86-64.sla")` 17.9 ms against the
  reference loader's 30.8 ms in the same session; all 150 in 415 ms; x86-64
  model heap 3.0x the stream.

Gaps: none against section 7, except that acceptance 5's "tests pass on all
three systems in CI" rests on CI (Windows checked locally with
`cargo clippy --target x86_64-pc-windows-msvc` only).
