# Decompiler type system (`bk-decomp-types`)

Track `decomp-types` (D02 of `docs/features/decomp-plan.md`), milestone
M3, wave 1. Format of this document: `docs/LOOP.md`, "Feature documents".
Leaf track: it depends on no other decompiler crate.

Path abbreviations: `CPP/` =
`Ghidra/Features/Decompiler/src/decompile/cpp/`, `UT/` =
`…/decompile/unittests/`, `P/` = `Ghidra/Processors/`, under `../ghidra`.

## 1. Purpose

The data types the decompiler reasons with: integers, floats, pointers,
arrays, structures with bitfields, unions, enumerations, function types and
the partial types that describe pieces of them; the factory that interns
them and holds the compiler's data organisation; the two orderings every
type-propagation decision rests on; their XML form; and the small C
declaration parser the console and the tests use to create them. This is
the decompiler's type model, not the program database's (`bk-datatypes`,
M4), as in Ghidra the C++ `Datatype` is distinct from the Java `DataType`.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/type.hh`, `CPP/type.cc` | `Datatype` and its 16 subclasses, `TypeField`, `TypeBitField`, `BitFieldTriple`, `DatatypeCompare`, `DatatypeNameCompare`, `TypeFactory`. **Authoritative** |
| `CPP/metatype.hh`, `CPP/metatype.cc` | `type_metatype`, `metatype2string`, `string2metatype` |
| `CPP/grammar.y` (`grammar.cc` is its bison output), `CPP/grammar.hh` | `GrammarLexer`, `CParse`, `TypeDeclarator` and the modifiers, `parse_type`, `parse_protopieces`, `parse_C`. Not the console's `parse_machaddr`, `parse_varnode`, `parse_op`, `parse_toseparator` (they arrive with the data-test runner, D09) |
| `CPP/sleigh_arch.cc`, `SleighArchitecture::buildCoreTypes` | The default core types |
| `CPP/architecture.cc`, `parseCompilerConfig` | Where `<data_organization>` and `<enum>` are handed to the factory, and `setupSizes` is called |
| `UT/testtypes.cc` | Tests `type_ordering`, `enum_matching`, `enum_matching2` (the other five need the IR and belong to D08) |
| `P/*/data/languages/*.cspec` | 107 files; 70 have `<data_organization>` |
| Java: `ghidra.program.model.pcode.{PcodeDataTypeManager, …}` in `Framework/SoftwareModeling` | The other end of the XML form (what a host sends for `getDataType`); read to confirm element and attribute use, not ported here |

## 3. Scope

**In:**
1. Metatypes, sub-metatypes, type classes and their names.
2. Every type kind of `type.hh` and every method on them that does not
   need the IR (section 4.8 lists the ones that do).
3. `TypeFactory`: interning, lookup by name and id, base types and the
   caches, pointers (plain, with a space, relative, truncated, resized),
   arrays, structures, unions, enumerations, typedefs, partial types,
   function types, spacebase types, `concretize`, `getExactPiece`,
   `resizeInteger`, `destroyType`, `dependentOrder`, warnings,
   incomplete-type handling, the data organisation and its XML, the core
   types, encode and decode of types and of the whole factory.
4. The C declaration parser, producing types and prototype descriptions.
5. ADR-025: provenance on every named type (3f) and the per-function
   overlay that holds inferred types (3e).

**Crate owned:** `bk-decomp-types`. Dependencies: `bk-core`, `bk-marshal`.

**Not in this track:**
- Union and structure-field resolution in data-flow: `resolveInFlow`,
  `findResolve`, `findCompatibleResolve`, `findTruncation`,
  `resolveTruncation`, `TypeStruct::scoreSingleComponent` and the
  `needs_resolution` machinery's users. The flag and the declarations of
  which types need resolution **are** here; the algorithms come with the
  IR (D08).
- `TypeSpacebase`'s look-ups (`getMap`, `getSubType`, `getAddress`,
  `nearestArrayedComponent*`): they query a symbol scope. The type itself
  (space, scope id), its comparison and its XML are here; the look-ups are
  a trait this crate declares and D06 implements.
- The prototype behind a function type. Ghidra's `TypeCode` owns a
  `FuncProto` with assigned storage; here a function type carries a
  **signature** (section 4.7) and D07 attaches storage.
- Printing type declarations (`print C types`): D16b.
- `print_data` (hex dump helper in `type.cc`): with the console (D09).

## 4. Behaviour

Port `type.cc` method by method. This section fixes what the port must
decide, and records what is easy to get wrong; statements about Ghidra are
from reading the cited functions.

### 4.1 Metatypes
`type_metatype` values are **part of the behaviour**: they index
`Datatype::base2sub` and are compared numerically (`isPieceStructured` is
`metatype <= TYPE_ARRAY`; `getBase` indexes its cache with `m -
TYPE_FLOAT`): `PARTIALUNION` 0, `PARTIALSTRUCT` 1, `PARTIALENUM` 2,
`UNION` 3, `STRUCT` 4, `ENUM_INT` 5, `ENUM_UINT` 6, `ARRAY` 7, `PTRREL` 8,
`PTR` 9, `FLOAT` 10, `CODE` 11, `BOOL` 12, `UINT` 13, `INT` 14, `UNKNOWN`
15, `SPACEBASE` 16, `VOID` 17. The 24 `sub_metatype` values (`type.hh`)
order types in `compare`; `base2sub` maps each metatype to its default.
`type_class` (`GENERAL` 0, `FLOAT` 1, `PTR` 2, `HIDDENRET` 3, `VECTOR` 4,
`CLASS1`–`CLASS4` 100–103) with `string2typeclass` and
`metatype2typeclass` is used by `bk-cspec` through its type-query trait.
Use Rust enums with explicit discriminants; `metatype2string` and
`string2metatype` give the XML names (read the tables: `TYPE_ENUM_INT`,
`TYPE_PTRREL` and the partial types have their own spellings).

### 4.2 A type's common part
`id` (64-bit; 0 means anonymous), `size`, `flags`, `name`, `displayName`,
`metatype`, `submeta`, `typedefImm`, `alignment`, `alignSize`
(`Datatype`). Rules:

* **A named type must have a non-zero id** (`findAdd` throws "Datatype
  must have a valid id"); `hashName` makes one from the name:
  start 123; per byte rotate left 8, add the byte, and if the result is
  even XOR `0xfeabfeab`; finally OR `0xC000000000000000`. The byte is
  added as a **signed** `char` on x86-64 (`res += (uint8)nm[i]`), so a
  byte ≥ 0x80 adds a sign-extended value; take that (ADR-021) and test it
  with a non-ASCII name. `hashSize(id, size)` XORs `size *
  0x98251033aecbabaf` into an id (variable-length structures;
  `getUnsizedId` undoes it).
* `alignment` −1 means "not yet computed": `findAdd` fills `alignSize`
  and `alignment` from the factory's alignment map for primitive types.
  `calcAlignSize` rounds a size up to a multiple of the alignment.
* Display format is three bits of `flags` (`force_format`, 0 none, 1 hex,
  2 dec, 3 oct, 4 bin, 5 char) with `encodeIntegerFormat` /
  `decodeIntegerFormat` for the names.
* Flag inheritance: `inheritForPointer` (`coretype | warning_issued`),
  `inheritForPartial` (`warning_issued`).

### 4.3 The two orderings
* `compare(other, level)` — **propagation order**: negative means `self`
  is the more specific, preferred type. The base rule is by `submeta`,
  then larger size first (`op.size - size`); pointers, arrays, structures,
  unions, enumerations, function types, partial types and relative
  pointers refine it, recursing into components with `level - 1` and
  stopping at `level < 0`. `typeOrder` is `compare(op, 10)` with a
  pointer-equality short cut; `typeOrderFormal` adds two special cases
  (partial unions last, `bool` after integers).
* `compareDependency(other)` — **identity order** used by the factory's
  set. Where the C++ compares component pointers ("Compare absolute
  pointers": `TypePointer`, `TypeArray`, `TypePointerRel`,
  `TypePartialStruct`, `TypePartialUnion`, `TypePartialEnum`,
  `TypeCode`'s parameters) Basilisk compares the components' **`TypeId`s**.
  This changes no equality (two types are identical exactly when Ghidra's
  are) and replaces an order that follows heap addresses with one that
  follows creation; it is the one deliberate difference in this section
  and affects only the order in which `dependentOrder` lists unrelated
  types.
* `DatatypeCompare` = `compareDependency`, then `id`;
  `DatatypeNameCompare` = name, then `id`.

`UT/testtypes.cc`'s `type_ordering` pins seventeen relations (unsigned
before signed, `char` after `int1`, wide characters before plain integers,
enumerations before integers, larger before smaller, `bool` before
`uint1`, pointer order following pointee order, pointer to `void` last
but for pointer to unknown, typedefs and same-shape structures distinct
but `compareDependency`-equal). The oracle table of section 6 pins the
rest.

### 4.4 The factory
* **Interning.** `findAdd`: a named type is looked up by (name, id) and
  must be `compareDependency`-equal to the existing one ("Trying to alter
  definition of type"); an anonymous type is looked up structurally
  (`findNoName`); otherwise a clone is inserted. `insert` refuses two
  types that are equal in both `compareDependency` and id ("Shared type
  id"). Named types are also in the name index; lookup by name with id 0
  returns the first type of that name (`findByIdLocal`).
* **Base types.** `getBase(size, meta)` reads a cache for sizes below 9
  and metatypes from `FLOAT` up, and for 10- and 16-byte floats; a size
  above `max_basetype_size` (an architecture setting, default 10) yields
  an **array of 1-byte unknowns** of that size; otherwise an anonymous
  `TypeBase`. `getBase(size, meta, name)` creates a named base with
  `hashName(name)`. `getBaseNoChar`, `getTypeChar(size)`, `getTypeVoid`,
  `getTypeCode()` as written. `cacheCoreTypes` fills the caches from the
  names `SleighArchitecture::buildCoreTypes` registers; the default core
  types are `void`, `bool`, `uint1/2/4/8`, `int1/2/4/8`, `float4/8/10/16`,
  `xunknown1/2/4/8`, `code` (size 1), and the character types `char` (1),
  `wchar2`, `wchar4` (`setCoreType(name, size, meta, chartp)`).
* **Typedefs.** `getTypedef(ct, name, id, format)`: a clone of `ct` with
  the new name and id (hashed from the name when 0), `coretype` cleared,
  `typedefImm = ct`; an existing type of that name must already be a
  typedef of `ct`. Incomplete typedefs are remembered and re-resolved when
  the underlying type is completed (`resolveIncompleteTypedefs`).
  `setName` renames in place (re-indexing).
* **Pointers.** `getTypePointer(size, pointee, wordsize)` (and with a
  name), `getTypePointerStripArray` (pointer to array becomes pointer to
  element), `getTypePointerWithSpace`, `getTypePointerRel` (two forms; the
  unnamed one is *ephemeral* and has a stripped form), `resizePointer`.
  A pointer's sub-metatype depends on what it points to (`calcSubmeta`:
  a structure gives `SUB_PTR_STRUCT`, unless the structure needs
  resolution, which gives `SUB_PTR`; a union gives `SUB_PTR_STRUCT`; an
  array sets `pointer_to_array`; `needs_resolution` is inherited from the
  pointee unless the pointee is itself a pointer) and must be recomputed
  when a structure is completed (`recalcPointerSubmeta`). Relative
  pointers have `SUB_PTRREL` (and `SUB_PTRREL_UNK` where the source sets
  it). `calcTruncate` attaches a truncated form of the pointer where the
  source does (segmented spaces).
* **Composites.** `getTypeStruct(name)`/`getTypeUnion(name)` create an
  incomplete stub (so a definition can refer to itself); `setFields`
  completes it. `assignRawFields` lays out fields that have no offsets
  yet: `TypeStruct::assignFieldOffsets` (each field at the next multiple
  of its type's alignment, with `ident` set to the offset; a `void` field
  is the error "Illegal field void in structure"; total size rounded up
  to the largest alignment; each run of bitfields is placed before the
  field whose index its `ident` names by `assignContiguousBitfields`,
  with big- or little-endian bit numbering by the data space; a bitfield
  list that is not consumed is "Malformed bitfield description") and
  `TypeUnion::assignFieldOffsets`. A structure with bitfields, or with a
  field that has them, gets `has_bitfields`. Field lookup by offset is
  binary search over fields sorted by offset (`getFieldIter`,
  `getLowerBoundField`); `getSubType`, `getHoleSize`,
  `nearestArrayedComponentForward/Backward`, `findSmallestContainer`,
  `collectBitFields`, `findMatchingBitField` as written.
* **Arrays.** Size is `n * element.alignSize`, alignment the element's.
  An array of one element is still an array type but is flagged
  `needs_resolution` ("should generally always be treated as the element
  data-type").
* **Enumerations.** `getTypeEnum(name)` uses the factory's enumeration
  size and signedness (`<enum size= signed=>` of the `.cspec`, default:
  the default data size, unsigned) and `hashName(name)` as id.
  `TypeEnum::assignValues` first enters the explicitly valued names
  (value masked to the enumeration's size; a repeated value is the error
  `Enum "<type>": "<name>" is a duplicate value`), then gives each
  remaining name the next value above the largest seen so far that is
  not taken. `setEnumValues` installs the map (re-keying the entry).
  `getMatches(value)` writes a value as an OR of names: repeatedly take
  the named value that matches the most significant remaining bits
  (`upper_bound` then step back; `coveringmask` of the difference),
  trying the value and then its complement within the enum's size; zero
  matches only a name for zero; no match gives an empty list. The two
  `enum_matching` tests pin the order of names (`FOUR`, `ONE` for 5;
  `EIGHT` with complement for `~8`; `SIX`, `ONE` for 7 when 6 is named).
  `TypePartialEnum` (a byte range of an enumeration) has its own
  `hasNamedValue`/`getMatches`.
* **Partial types.** `getTypePartialStruct(container, offset, size)`,
  `getTypePartialUnion`, `getTypePartialEnum`: each carries a *stripped*
  type (an undefined of the same size) used where a formal type is
  needed. `getExactPiece(type, offset, size)` finds or makes the type of
  a byte range of a composite. `concretize` replaces partial unions by a
  concrete type.
* **Removal.** `destroyType` removes a non-core type from both indexes;
  `clear`, `clearNoncore`.
* `dependentOrder` lists types so that each follows the types it depends
  on (depth-first over `getDepend`, in the set's order).

### 4.5 Data organisation
Fields: `sizeOfInt`, `sizeOfLong`, `sizeOfChar`, `sizeOfWChar`,
`sizeOfPointer`, `sizeOfAltPointer`, `enumsize`, `enumtype`, and
`alignMap` (alignment by size).

* `decodeDataOrganization` reads **only** `<integer_size>`, `<long_size>`,
  `<pointer_size>`, `<char_size>`, `<wchar_size>` and
  `<size_alignment_map>`; every other child (`<short_size>`,
  `<float_size>`, `<double_size>`, `<long_double_size>`,
  `<long_long_size>`, `<machine_alignment>`, `<default_alignment>`,
  `<default_pointer_alignment>`, `<absolute_max_alignment>`,
  `<bitfield_packing>`, `<pointer_shift>`, `<char_type>`, …) is skipped —
  those are for the Java side. `decodeAlignmentMap`: entries `(size,
  alignment)`; sizes without an entry take the alignment of the nearest
  smaller size that has one; index 0 is 1; an empty map is an error;
  `getAlignment(size)` beyond the map returns the last entry.
* `setupSizes` supplies what the file did not: `sizeOfInt` from the stack
  pointer register's size, capped at 4 (1 if there is no stack space);
  `sizeOfLong` 8 if `int` is 4, else `sizeOfInt`; `char` 1; `wchar` 2;
  pointer size from the default data space, or from a segment op with far
  pointers (inner size, and `sizeOfAltPointer` = inner + base size); the
  default alignment map `[1,1,2,2,4,4,4,4,8]`; enumeration size = the
  default size, unsigned.
* The factory needs these facts from outside, as plain data given at
  construction (a `TypeEnv`): `max_basetype_size`; the default data
  space (id, address size, word size, endianness); the stack pointer's
  size if there is a stack space; the default code-space address size;
  the segment op's inner and base sizes if the data space has far
  pointers. No `Architecture` object.

### 4.6 XML
Element and attribute ids declared in `type.cc` (`ATTRIB_ALIGNMENT` 47
onward; `ELEM_TYPE`, `ELEM_TYPEREF`, `ELEM_TYPEGRP`, `ELEM_CORETYPES`,
`ELEM_DEF`, `ELEM_FIELD`, `ELEM_BITFIELD`, `ELEM_DATA_ORGANIZATION`,
`ELEM_SIZE_ALIGNMENT_MAP`, `ELEM_ENTRY`, `ELEM_ENUM`, the size elements):
take every name and number from the source into this crate's id table
(`bk_marshal::IdTable` contribution).

* `encode` writes a full definition, `encodeRef` a `<typeref>` by name and
  id for named types (anonymous types are always written in full),
  `encodeTypedef` a `<def>`. `decodeType` handles `<typeref>` itself (the
  id is optional and defaults to `hashName(name)`; a `size` attribute
  marks a variable-length base; an unresolvable reference is "Unable to
  resolve type: <name>") and passes everything else to `decodeTypeNoRef`,
  which dispatches on the element and its `metatype` attribute to the
  per-kind decoders (`decodeTypedef`, `decodeStruct`, `decodeUnion`,
  `decodeEnum`, `decodeCode`, and the kinds' own `decode` methods);
  `decodeTypeWithCodeFlags` passes constructor/destructor flags to a
  function type. Structures decode fields with or without explicit
  offsets and collect a **warning** text when a field is out of order,
  overlaps or exceeds the size (`FieldAccum`); the warning is stored in
  the factory's warning table against the type, not thrown.
* `encode` of the factory: `<typegrp>` with the size attributes and all
  types in dependency order; `encodeCoreTypes`/`decodeCoreTypes` for
  `<coretypes>`.
* A reference to an unknown type calls `findById(name, id, size)`, which
  in the base class looks in the factory only; it is the hook through
  which a host supplies types on demand (`TypeFactoryGhidra`). Provide it
  as a trait object the factory can be given (`TypeSource`), returning an
  XML-decodable definition or a ready type description.

### 4.7 Function types
`TypeCode` in Ghidra owns a `FuncProto`. Here it holds an optional
**`CodeSignature`**: model name (or none), the comparable flags
(`dotdotdot`, `is_constructor`, `is_destructor`, `has_thisptr` — exactly
`FuncProto::getComparableFlags`), the return `TypeId`, the parameter
`TypeId`s and names, and the first-vararg slot. That is everything
`compareBasic`, `compare`, `compareDependency` and `printRaw` read
(`compareBasic`: no prototype sorts last; no model after a model; model
names lexicographically; **more** parameters first; then flags; result 2
means "continue with parameter types"). `getTypeCode(signature)` interns
it. The XML of a function type embeds a `<prototype>` element; this crate
decodes and encodes the parts that the signature covers and passes the
element through a hook (`PrototypeCodec`) for the storage parts, which
`bk-cspec`'s `FuncProto` implements later. With no hook installed,
decoding keeps the signature and drops storage, and says so in the
result.

### 4.8 What needs the IR (declared here, implemented in D08)
`needs_resolution` is set at five places in `type.cc` — unions, partial
unions, arrays of one element, pointers (inherited from the pointee as
above) and structures in the case `TypeStruct::setFields` marks; set it
exactly there. The resolution methods take a
`(PcodeOp, slot)` edge and consult the function's `unionMap`; this crate
exposes what they need — `TypeUnion::getField`, field iteration,
`findTruncation`'s pure part (the field at an offset and size) — and
nothing op-shaped.

### 4.9 The C declaration parser
`grammar.y` is a subset of the C declaration grammar: declaration
specifiers (storage class `typedef extern static auto register`,
qualifiers `const restrict volatile`, `inline`, a type name, `struct`/
`union`/`enum` specifiers with or without a body), declarators (pointers
with qualifiers, arrays with an integer size, function parameter lists
with `...`, parenthesised declarators, abstract declarators, `::` scope
resolution in identifiers), structure members with optional bit widths
(`int4 flag:3;`), enumerators with optional values. Behaviour to keep:

* **Type names are whatever the factory knows** (`lookupIdentifier`:
  keyword, else `findByName`, else a prototype-model name →
  function specifier, else identifier). There is no built-in `int` or
  `unsigned`; the tests write `int4`, `uint8`, `float4`, `xunknown4`,
  `char`, `bool`, `void`. Model names (`__stdcall`, …) come from a
  callback (`fn(&str) -> bool`), because models belong to `bk-cspec`.
* `parse_type(text)` parses one parameter-style declaration and returns
  the type and the declared identifier; errors "Did not parse a
  datatype", "Parsed multiple declarations", "Parsed type is invalid".
* `parse_protopieces(text)` parses one declaration that must be a
  function declarator and returns `PrototypePieces`: model **name** (the
  function specifier if it names a model, else "use the default"), name,
  input types and names, first-vararg slot (the number of fixed
  parameters when `...` is present, else −1), and the return type (the
  base type with every modifier but the function one applied).
* `parse_C(text)` parses one declaration and acts on it: with `extern`,
  it is a function prototype — return it to the caller as a declaration
  to register (Ghidra calls `Architecture::setPrototype`); with
  `typedef`, define the name (a structure is **renamed** with `setName`,
  anything else gets `getTypedef(type, name, 0, 0)`; no identifier is
  the error "Missing identifier for typedef"); a bare structure, union or
  enumeration definition has already been added by parsing it; anything
  else is "Not sure what to do with this type".
* Pointer declarators use the default data space's address size and word
  size; arrays need a positive size; a structure body builds fields in
  order and calls `assignRawFields` (so layout follows 4.4); on an error
  inside a body the stub type is destroyed again.
* The lexer (`GrammarLexer`): identifiers, decimal/hex/octal integers,
  character constants, punctuation, `...`, `::`, C comments, with line and
  column tracking for error messages; input is limited to a buffer size
  in Ghidra (4,096 bytes per call) — keep a limit and make it an error,
  not a truncation.

ADR-011: `lang-c` and a tree-sitter C grammar were considered as the
candidates to evaluate. Both parse standard C with a fixed notion of type
names; this grammar's identifiers become type names or calling-convention
specifiers by asking the factory at lex time, it must reject what Ghidra
rejects with Ghidra's messages, and it is about 35 productions. A
hand-written recursive-descent parser is the expected outcome; record the
evaluation (download counts, what failed) in section 8 before writing it.
tree-sitter would also add a C dependency (ADR-005).

### 4.10 ADR-025: provenance and inferred types
* **Provenance (3f).** Every entry in the factory carries a
  `bk_core::Provenance` (user, debug information, import, library
  signature, analysis, model, default). It is set by whoever creates the
  type (the decoder's caller, the parser's caller, the engine), is kept
  through typedef and rename, is written and read across the
  `TypeSource` hook, and **takes no part in `compare`,
  `compareDependency`, hashing or interning**. Two requests for the same
  structural type with different provenance return the same `TypeId`; the
  stored provenance is the higher-priority one (Ghidra's `SourceType`
  order: default < analysis = model < import < user; debug information
  and library signature rank with import).
* **Inferred types (3e).** A factory can be **forked**: a child that
  reads through to a frozen parent and takes all new entries itself.
  One child per function decompilation. Types the engine creates while
  decompiling — pointers, arrays, partial types, anything from type
  recovery — land in the child and are thereby the category of inferred
  types: enumerable, discardable (drop the child), and marked by where
  they live plus `Provenance::Analysis`. `TypeId` encodes which layer an
  entry is in (one bit) so ids are stable and independent of what other
  functions create; a parent is `Send + Sync` while frozen. In the
  `ghidra` profile this changes nothing observable: lookups and
  orderings give the same answers as one flat factory (property test in
  section 6).

## 5. Design

* **Arena with typed ids** (ADR-012): `TypeId(u32)`; a type is an entry
  `{ common part, kind }` with `kind` an enum over the kinds of section
  4 (no trait objects); components refer to other types by `TypeId`.
  Names are interned (`string-interner` is already in the workspace;
  check it, else a local interner). Assert the entry's size in a test.
* **Indexes**: two ordered maps keyed by small key structs that implement
  the two comparators (identity: sub-metatype, size, kind-specific
  component ids, then id; name: interned name order must be **string**
  order, not interner order, then id). Lookups take a borrowed candidate
  description, never allocate a throw-away type as the C++ does.
* **Mutation.** Completing a stub (`setFields`, `setEnumValues`,
  `setPrototype`), renaming and re-keying on completion are the only
  in-place changes; each removes the entry from the indexes, changes it
  and re-inserts, inside the factory. Nothing outside the factory can
  change a field that is part of an index key.
* **Errors**: `thiserror` enum `TypeError` with Ghidra's messages where a
  test or the console shows them. No panics on any XML or C text
  (ADR-009): depth limit for nested declarators and nested type
  definitions, size arithmetic checked (array size × element size,
  structure sizes), self-reference only through an incomplete stub.
* **Modules** (each under 600 lines): `meta`, `ids`, `entry` (common
  part, flags), `kinds/{base, pointer, array, enumeration, structure,
  bitfield, union, partial, code, spacebase}`, `compare/{propagation,
  identity}`, `factory/{intern, base, pointer, composite, enumeration,
  typedef, partial, overlay, order}`, `org` (data organisation), `xml/
  {ids, encode, decode}`, `cdecl/{lexer, ast, parser, build}`, `error`.
* **Performance**: `getBase` and `getTypePointer` are called constantly
  during propagation — both must be a cache hit or one ordered-map lookup
  without allocation. Benchmark: intern one million pointer/array/base
  requests with 90 % repeats.
* **Public API sketch**: `TypeFactory::new(env)`, `fork()`,
  `freeze()`; `base(size, meta)`, `named_base(…)`, `pointer(…)`,
  `array(…)`, `structure_stub(name)`, `set_fields(…)`, …; `get(id) ->
  &TypeEntry`; `compare(a, b, level) -> Ordering`-like `i32` semantic
  (keep Ghidra's sign convention behind an enum), `compare_dependency`;
  `decode_type`, `encode_type`, `encode_ref`; `parse_type`,
  `parse_prototype`, `parse_declaration`. `bk-cspec`'s type-query trait
  is implemented for `TypeFactory` in a later track, not here (this crate
  does not depend on `bk-cspec`).

## 6. Tests

Kinds: **S** self-contained; **G** needs the spec root; **L** needs the
live reference tools (`decomp-plan.md` 4.5).

1. **Port from `UT/testtypes.cc`** (S): `type_ordering`,
   `enum_matching`, `enum_matching2`, with a factory built from a
   `TypeEnv` equal to `x86:LE:64:default:gcc`'s facts (8-byte pointers,
   word size 1, little endian, 8-byte stack pointer, `max_basetype_size`
   10) and that `.cspec`'s data organisation written in the test, the
   default core types, and the C parser. Mark those three in
   `docs/inventory/tests/decompiler-cpp.md` by annotating the
   `unittests/testtypes.cc` line (3 of 8 here, 5 in `decomp-typeop`); the
   line is ticked by D08.
2. **Oracle tables** (S replay, L regeneration): a C++ program under
   `crates/bk-decomp-types/tests/oracle/` linked with the reference
   build's objects, creating an `Architecture` for a language as the unit
   tests do, and printing:
   * for a fixed list of about 300 C declarations (all core types;
     pointers and arrays of them to depth 3; structures with padding,
     nested structures, bitfields, trailing arrays; unions; enumerations
     signed and unsigned; typedefs; function pointers), for each of
     `x86:LE:64:default:gcc`, `x86:LE:32:default:gcc`,
     `ARM:LE:32:v8:default`, `PowerPC:BE:32:default:default`,
     `AARCH64:LE:64:v8A:default`, `8051:BE:16:default:default`: size,
     alignment, aligned size, metatype, sub-metatype, flags, id, and for
     composites every field's offset and every bitfield's range;
   * the full matrices of `compare(a, b, 10)` (sign only) and
     `compareDependency(a, b)` (zero or not) over those types;
   * `getMatches` for every value 0–1,023 and a sample of 64-bit values
     over six enumerations;
   * `hashName` for 1,000 names including non-ASCII bytes (generated on
     the x86-64 reference; the AArch64 result differs for bytes ≥ 0x80
     and is listed);
   * `encode` of every type and of the whole factory, as text;
   * `getExactPiece`, `getSubType`, `getHoleSize`,
     `nearestArrayedComponent`, `findSmallestContainer`, `resizeInteger`,
     `concretize`, `getTypePointerStripArray`, `getTypePointerRel` over a
     grid of offsets and sizes;
   * the data organisation (five sizes, enumeration size and signedness,
     the alignment map to size 32) after `setupSizes` for **every**
     language/compiler pair of the 107 `.cspec` files.
   The declarations are the table's input, so the Rust replay also tests
   the C parser against Ghidra's on the same text. Tables are checked in
   compressed with `regen.sh`.
3. **Data organisation from the real files** (G): decode
   `<data_organization>` and `<enum>` of all 107 files and compare with
   the table (the table gives the answer; the file gives the input).
4. **XML round trips** (S): encode → decode → encode is stable for every
   table type; decode of the oracle's `encode` text reproduces a factory
   whose own `encode` equals it; decoding a structure with overlapping or
   out-of-order fields yields Ghidra's warning text (from the oracle).
5. **C parser** (S): every declaration form of 4.9; every error message;
   the declarations used by Ghidra's data tests (`parse line` commands —
   232 of them; extract at test time, G) all parse.
6. **Properties** (`proptest`, S): interning is idempotent; `compare` is
   antisymmetric and `compareDependency` is a strict weak order on
   generated types; `dependentOrder` lists dependencies first; a forked
   factory answers every query as a flat factory holding the same types
   does, in the same order, and dropping it leaves the parent's `encode`
   output unchanged; changing only provenance changes no id, order or
   encoding. Decoders and the parser never panic on arbitrary input.
7. **Fuzz targets** in the root `fuzz/` crate: `bk_decomp_types_xml`
   (decode a type group), `bk_decomp_types_cdecl` (parse declarations).
8. **Benchmarks**: interning (above); decode of a 10,000-type group;
   numbers in `PERF.md`.

## 7. Acceptance

1. The three ported tests pass on Windows, macOS and Linux (S).
2. Every oracle table replays without a differing row, except rows
   attributable to the deliberate differences of section 8 (pointer-order
   in `dependentOrder` only), each listed (S). The tables come from
   Ghidra's compiled code; `regen.sh` reproduces them (L), and the
   x86-64 container build is the reference for `hashName`.
3. All 107 files' data organisation equals the table (G).
4. The 232 `parse line` declarations of the data tests parse (G).
5. Property tests at 1,024 cases or more each; both fuzz targets run 60 s
   without a finding.
6. ADR-025: provenance and the fork/overlay exist with the tests of item
   6; no test of items 1–4 changes result when either is exercised.
7. No `unsafe`, no panic on input, gate green, files within the size
   limit, public items documented with the Ghidra function they
   correspond to.

## 8. Differences from Ghidra

- Types are arena entries referred to by `TypeId`; identity ordering
  compares component ids where Ghidra compares pointers (4.3).
- A function type holds a signature, not a `FuncProto` (4.7).
- The factory takes a `TypeEnv` of facts, not an `Architecture` (4.5).
- `hashName` sign-extends bytes on every host (ADR-021).
- Provenance on entries; forkable factory (ADR-025).
- Errors are values; structure-layout warnings are returned and stored.
- The C parser returns declarations instead of calling into the
  architecture, and takes model names from a callback.

(The implementing agent appends further differences here.)

Appended by the implementing track (D02):

- **Indexes are hash maps, not ordered sets.** Ghidra's name set is only
  searched, never walked; its identity set is walked only by
  `dependentOrder`, `encodeCoreTypes` and `cacheCoreTypes`, which sort on
  demand here (`sorted_ids`, same order: `compareDependency`, then id).
  Exact look-ups hash exactly what the comparator compares and confirm
  through the arena, so a look-up allocates no throw-away type. Names are
  owned strings per entry, not interned: a forked factory would need a
  layered interner, and no ordered walk needs interner order.
  `recalcPointerSubmeta` uses a pointee → pointers index instead of a range
  of the set (same pointers).
- **Undefined casts get a defined order.** Where two kinds share a
  sub-metatype (Ghidra never creates this, hostile XML can, e.g.
  `getBase(8, TYPE_PTR)`), Ghidra casts to the wrong class; here
  `compareDependency` orders by kind family and `compare` returns 0 when one
  side is a plain base type.
- `compare`'s `level` is clamped to 64 (Ghidra always passes 10).
- `destroyType` keeps the slot as a tombstone; a stale `TypeId` never names
  a new type.
- **Forks.** A fork that changes a parent entry (completes a stub, renames
  it, raises its provenance, destroys it) copies the entry into its own
  layer under the **same `TypeId`** and masks the parent's index entries for
  it (copy on write), so it answers exactly as a flat factory would, where
  Ghidra changes the one entry in place; the parent is never changed
  (`shadowed_ids` lists such entries, `overlay_ids` the new ones). A fork
  of a fork is refused. New entries get `Provenance::Analysis` unless
  the caller sets another. Provenance is set through the factory's current
  provenance (`set_provenance`); a type found again keeps the more trusted
  of the two.
- **Function types.** The signature is the declared parameters. Ghidra's
  `TypeCode` comparison reads `FuncProto` after the model has assigned
  storage, which can add a hidden-return parameter or, when assignment
  fails (8051 in the oracle table), leave no parameters at all; those
  comparisons need `bk-cspec` (11 oracle records, listed by the replay).
  Without a `PrototypeCodec` the `<prototype>` written is reduced (model,
  `extrapop="unknown"`, flags, `<returnsym>` and `<internallist>` with empty
  `<addr/>`), so `encode` of a function type is not Ghidra's text (48
  oracle records). Ghidra's `FunctionModifier::modType` looks for a varargs
  marker that `newFunc` already removed, so function *types* built by the
  parser never have `...` (reproduced; `parse_prototype` does report it).
- `parse_declaration` returns an `extern` prototype to the caller (Ghidra's
  `parse_C` calls `Architecture::setPrototype`, which fails with "Unknown
  function name" when no function of that name exists).
- **Lexer.** A token ended by a newline: Ghidra's `bumpLine` clears the
  buffer before the token's text is taken (reading out of bounds); here the
  text is kept. Integer constants saturate as C++11 `num_get` does; a
  token of type 0 at end of input is end of input, as bison treats it.
  Input over 1 MiB, declarators nested over 128 deep and type definitions
  nested over 200 deep are errors, not truncations or stack overflows.
- `decodeTypeWithCodeFlags` opens the function type's own element; Ghidra
  reads its attributes from the pointer element again and fails with "Bad
  size for type".
- **Reproduced Ghidra quirks** (tested): `<bitfield>` is written without
  the `id` its decoder requires, so a structure with bitfields does not
  survive encode → decode; `partenum` is written but not read
  (`string2metatype`); `struct name` and `enum name` for an existing name
  is a syntax error (the lexer returns a type name); character constants
  take their value from wherever the line buffer's token start is; `int4
  int4` parses as `int4`.
- `getBase` above `max_basetype_size` creates `xunknown1` when no core
  types are cached (Ghidra dereferences null); `getAlignment` on an empty
  map gives 1 (Ghidra throws; never reached after `setup_sizes`).
- `TypeSpacebase` look-ups go through the `SpacebaseScopes` hook (D06);
  without it the scope id is 0, `getSubType` finds nothing, and the frame
  address is written as `<addr/>`.
- `<data_organization>` and `<enum>` are read from a `.cspec` by
  `DataOrganization::from_cspec` in this crate (no `bk-cspec` yet).

## 9. Status

Built (track D02, 2026-11-14): crate `bk-decomp-types` — metatypes, every
kind of `type.hh` as `TypeKind`, the factory (interning, base types and
caches, core types, pointers of every form, arrays, structures with
bitfield layout, unions, enumerations with `getMatches`, typedefs, rename,
partial types, `getExactPiece`, `concretize`, `resizeInteger`, function
types from a signature, `destroyType`, `clear`, `clearNoncore`, warnings,
incomplete typedefs, `dependentOrder`), the IR-free queries (`getSubType`,
`getHoleSize`, nearest arrayed components, `findSmallestContainer`,
bitfield collection, `downChain`, `isPtrsubMatching`, `isOffsetValid`,
`printRaw`), both orderings, data organisation, XML encode/decode of types,
the factory and core types (with `TypeSource`, `SpacebaseScopes`,
`PrototypeCodec` hooks), the C declaration parser, provenance and the
forked factory.

Evidence: the three `testtypes.cc` tests (S); the oracle table of 197,330
records over six languages replays with only the listed differences
(prototype encoding 48, function-signature storage 11, `<typegrp>` order
1) (S); 1,000 `hashName` values (S); data organisation of all 294
language/compiler pairs (106 `.cspec` files referenced by `.ldefs`) equal
(G); all 232 `parse line` declarations of the data tests parse (G); 9
property tests at 1,024 cases; both fuzz targets ran 60 s without a
finding; benchmarks in `PERF.md`.

Gaps: the storage half of function prototypes (D03, through
`PrototypeCodec`); spacebase look-ups (D06, through `SpacebaseScopes`);
the `testtypes.cc` checklist line stays open for the five `cast_*` tests
(D08); the oracle tables were generated on macOS AArch64 only (the
reference build's `-fsigned-char` makes `hashName` x86-64's; only the
heap-address order of `<typegrp>` can differ on another host).
