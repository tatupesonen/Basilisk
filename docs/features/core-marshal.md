# Core types and marshalling (`bk-marshal`, `bk-core`)

Track `core-marshal`, wave 1, milestone M0. Format of this document:
`docs/LOOP.md`, "Feature documents".

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`UT/` = `Ghidra/Features/Decompiler/src/decompile/unittests/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/`, all under
`../ghidra`.

## 1. Purpose

The bottom of the stack. `bk-marshal` reads and writes Ghidra's two
serialisation forms — XML and the packed binary form — which carry every
spec file, every compiled `.sla` and all decompiler input and output.
`bk-core` holds the address model everything else speaks: address spaces,
addresses, ranges, varnode data and the bit arithmetic helpers.

## 2. Ghidra sources

| Source | What to take from it |
|---|---|
| `CPP/marshal.hh`, `CPP/marshal.cc` | `AttributeId`, `ElementId`, `Decoder`, `Encoder`, `XmlDecode`, `XmlEncode`, `PackedDecode`, `PackedEncode`, the `PackedFormat` constants. **Authoritative.** |
| `CPP/xml.hh`, `CPP/xml.y` (`xml.cc` is its bison output) | Ghidra's XML reader and DOM, `xml_escape`, attribute handling |
| `CPP/space.hh`, `CPP/space.cc` | `AddrSpace` and its kinds (`ConstantSpace`, `OtherSpace`, `UniqueSpace`, `JoinSpace`, `OverlaySpace`), space types `IPTR_*`, flags, `printRaw`, `read`, encode/decode |
| `CPP/address.hh`, `CPP/address.cc` | `Address`, `SeqNum`, `Range`, `RangeProperties`, `RangeList`, and the free bit functions (`calc_mask`, `sign_extend`, `zero_extend`, `byte_swap`, `leastsigbit_set`, `mostsigbit_set`, `popcount`, `count_leading_zeros`, `coveringmask`, `bit_transitions`, `signbit_negative`, `uintb_negate`, `pcode_right`, `pcode_left`, `minimalmask`, …) |
| `CPP/pcoderaw.hh`, `CPP/pcoderaw.cc` | `VarnodeData` only (`PcodeOpRaw` waits for wave 2) |
| `CPP/translate.hh`, `CPP/translate.cc` | `AddrSpaceManager` (space registration and lookup, default code and data spaces, constant/unique/join/stack/iop/fspec spaces, `JoinRecord` and `constructJoinAddress`, `constructFloatExtensionAddress`, `SpacebaseSpace`, truncations, `resolveConstant` hooks), `TruncationTag`. The `Translate` interface itself waits for M1 |
| `CPP/error.hh` | `LowlevelError`, `DecoderError` → typed errors |
| `UT/testmarshal.cc` | The 18 marshal tests |
| `SM/ghidra/program/model/pcode/` (`PackedDecode`, `PackedEncode`, `XmlEncode`, `AttributeId`, `ElementId`, `Encoder`, `Decoder`, `PatchPackedEncode`, …) | The Java twin; use it to cross-check behaviour and to find tests in `docs/inventory/tests/framework-softwaremodeling.md` |

## 3. Scope

**In:** everything in the table. **Crates owned:** `bk-marshal`, `bk-core`.

**Not in this track:**
- Opcode attributes (`readOpcode`/`writeOpcode`): they need `OpCode`, which
  the `pcode` track is writing in `bk-pcode` in the same wave. Do **not**
  depend on `bk-pcode`. *As built: `bk-marshal` offers generic
  `read_enum`/`write_enum` (the name in XML, a non-negative integer in the
  packed form), which `bk-pcode` uses for `OpCode` — no later glue needed.*
- The SLEIGH-format element and attribute ids (`CPP/slaformat.cc`): they
  belong to `bk-sleigh` (M1). But the id machinery must support them: they
  live in a separate id scope (`FORMAT_SCOPE`) with their own numbering.
- The decompiler's element and attribute ids defined in other `.cc` files:
  each later crate defines its own. Define here only the ids declared in
  `marshal.cc`, `space.cc`, `address.cc`, `translate.cc` and `pcoderaw.cc`.
- `Translate`, `PcodeEmit`, `AssemblyEmit` (M1), `ContextDatabase` (M1),
  `FloatFormat` (the `pcode` track).

## 4. Behaviour

### 4.1 Element and attribute ids
An id is a name plus a number; the XML form uses the name and the packed
form the number, so **both must equal Ghidra's**. Numbers are unique within
a scope; the default scope and the SLEIGH format scope are numbered
independently. `ATTRIB_UNKNOWN` (id 161) and `ELEM_UNKNOWN` (id 292) are
returned for names or numbers not registered; id 0 is not an id at all and
only means "nothing left" (no more attributes, no next element).
`ATTRIB_CONTENT` (id 1) stands for an element's text content in XML and is
an ordinary attribute in the packed form.

Ghidra registers ids through global static constructors. basilisk must not
use global mutable state: design an id table that is built once, immutable
afterwards, and lets each crate contribute its ids (for example a `const`
id type plus per-crate static slices combined into a lookup table when a
decoder for that scope is created). Name → id lookup is on the XML decode
path and must be a hash lookup, not a scan.

### 4.2 Decoder
One decoder interface with XML and packed implementations, giving the same
results for the same logical document. Operations (names are Ghidra's;
choose Rust names): `peekElement`, `openElement` (any / expecting a given
id, which fails if a different element is next), `closeElement` (Ghidra
never checks for unread attributes, and its XML decoder checks for unread
children only in debug builds — match the release behaviour and document
it),
`closeElementSkipping`, `getNextAttributeId` (returns 0 when exhausted),
`getIndexedAttributeId`, `rewindAttributes`, and typed reads of the current
attribute or of a named attribute: `readBool`, `readSignedInteger`,
`readSignedIntegerExpectString` (accepts one given string as a stand-in for
a given value), `readUnsignedInteger`, `readString`, `readSpace`. Reading a
named attribute searches the current element's attributes and fails with
Ghidra's error if absent. Reproduce the integer and boolean text forms the
XML decoder accepts (decimal, `0x` hex, octal by C rules; `true`/`1`/`y`
and so on — read `xml_readbool` and the `istringstream` flag handling).

### 4.3 Encoder
`openElement`, `closeElement`, `writeBool`, `writeSignedInteger`,
`writeUnsignedInteger`, `writeString`, `writeStringIndexed`, `writeSpace`.
The XML encoder's output must match Ghidra's text exactly — attribute
order as written, unsigned integers as `0x…` hex, signed as decimal,
escaping by `xml_escape`, where the `>` of an open tag is emitted, and the
optional newline behaviour (`XmlEncode(s, doFormat)`: read the indentation
logic) — because expected outputs elsewhere are compared as text.

### 4.4 Packed format
Byte-exact with `PackedFormat`: a header byte whose top two bits select
element start (`0x40`), element end (`0x80`) or attribute (`0xc0`); five id
bits in the header with an extension byte when bit `0x20` is set; attribute
values introduced by a type byte (type code in the high nibble: boolean 1,
positive signed 2, negative signed 3, unsigned 4, address space 5, special
space 6, string 7; length code in the low nibble); integers in 7-bit
groups, most significant first, each byte with the high bit set; strings as
a length integer followed by raw bytes; special space codes stack 0, join
1, fspec 2, iop 3, spacebase 4. Reproduce the decoder's error behaviour on
truncated and malformed input as typed errors, never panics (ADR-009).

Ghidra's packed decoder reads through a chain of 1,024-byte buffers with
padding because it ingests a stream. basilisk decodes from a contiguous
`&[u8]` with zero copies (strings are borrowed). `marshal_bufferpad` tests
buffer-boundary handling; port what it checks — values that span chunk
boundaries decode correctly — against whatever incremental-ingest API
basilisk offers, and if there is none, record the test as covered by the
contiguous design under "Differences from Ghidra".

### 4.5 XML reading
*Outcome (2026-11-12): the check below was done; `roxmltree` failed the
value check on three corpus elements and `quick-xml` was adopted instead
(ADR-011). The original instruction is kept for the record.*

ADR-011 adopts `roxmltree` provisionally. Verify it first: parse every
`.xml`, `.ldefs`, `.pspec`, `.cspec`, `.opinion`, `.sinc`-adjacent XML and
data-test file under `../ghidra/Ghidra/Processors` and
`../ghidra/Ghidra/Features/Decompiler/src/decompile/datatests`, and check
the decoded attribute and content values agree with what Ghidra's
`xml.y` rules give for the cases that differ between XML parsers:
entity and character references, attribute whitespace, CDATA, comments,
processing instructions, DOCTYPE, content with mixed text and children
(Ghidra concatenates an element's text). If any file or rule disagrees,
port `xml.y` instead and say so in the status report. Either way the
decoder owns a small DOM or cursor of its own; do not leak the XML crate's
types through the public API.

### 4.6 Address spaces
A space has a name, an index, a type (`IPTR_CONSTANT`, `PROCESSOR`,
`SPACEBASE`, `INTERNAL`, `FSPEC`, `IOP`, `JOIN`), address size in bytes,
word size, endianness, delay and dead-code delay, flags (`big_endian`,
`heritaged`, `does_deadcode`, `programspecific`, `reverse_justification`,
`formal_stackspace`, `overlay`, `overlaybase`, `truncated`, `hasphysical`,
`is_otherspace`, `has_nearpointers`, `allows_wrapped_range`,
`addressable_all`, `addressable_none`), a shortcut character, and derived
values (highest offset, pointer bounds). Keep all of Ghidra's rules:
`wrapOffset`, `byteToAddress`/`addressToByte` word-size scaling, truncation
(`truncateSpace`), overlay containment, `printRaw` and `printOffset`
formatting, `read` (parsing `name-or-number[:size][+offset]`, with register
names resolved through a callback), `encodeAttributes`, `decode` for each kind including overlay
spaces, and the `OtherSpace`, `UniqueSpace` and `JoinSpace` constants
(names, indices, sizes).

`AddrSpaceManager` owns the spaces: insertion rules and index assignment,
lookup by name, index and shortcut, the default code and data spaces, the
constant space, `getNextSpaceInOrder`, join records (`findAddJoin`,
`findJoin`, `constructJoinAddress`, `constructFloatExtensionAddress`,
`renormalizeJoinAddress`), spacebase and stack space handling, and
truncation.

### 4.7 Addresses, ranges, varnode data
`Address` (space + offset) with Ghidra's ordering (by space index, then
offset; the invalid, minimal and maximal extremes), `overlap`,
`justifiedContain`, `containedBy`, `isContiguous`, `isConstant`,
`isJoin`, arithmetic with wrapping at the space's size, `printRaw`,
encode and decode (including the `size` attribute and the forms decode
accepts). `SeqNum` (address, time, order). `Range` and `RangeList`
(insert/remove with merging, `inRange`, `longestFit`, `getFirstRange`,
`getLastRange`, `getLastSignedRange`, encode/decode, `RangeProperties`).
`VarnodeData` (space, offset, size) with its ordering, `contains`,
`isContiguous`, encode/decode. `BitRange` (also defined in `address.hh`). The bit helpers, exactly, including
behaviour at sizes 0 and above 8 bytes.

## 5. Design

- **Layering:** `bk-marshal` is the lowest crate and does not depend on
  `bk-core`. It handles address-space attributes abstractly — an opaque
  space identity plus a small lookup trait the decoder is given (name →
  space, index → space, the special spaces). `bk-core` depends on
  `bk-marshal` and implements encode/decode for its types.
- **Spaces are data, not a class hierarchy:** a `Space` struct with a
  `SpaceKind` enum; `SpaceId` is a typed index into the manager; `Address`
  is `Copy` and small (assert its size in a test: 16 bytes or less).
  Comparison of addresses must not need the manager (order by space index).
- **Errors:** `thiserror` enums (`DecodeError`, `SpaceError`, …) carrying
  what was expected and found. Messages may follow Ghidra's wording where
  a ported test checks it.
- **Zero copy:** packed decode borrows from the input; the XML decoder
  borrows where the XML crate allows.
- **Files:** split by concept (`ids`, `decoder`, `encoder`, `xml/…`,
  `packed/…` in `bk-marshal`; `space/…`, `manager`, `address`, `range`,
  `varnode`, `bits` in `bk-core`), each well under the size limit.

## 6. Tests

- **Port** `UT/testmarshal.cc`: all 18 cases (signed, unsigned, mixed,
  attributes, hierarchy, unexpected element, no remaining, open mismatch,
  close mismatch — each for packed and XML — and buffer padding). Mark
  them in `docs/inventory/tests/decompiler-cpp.md`
  (`unittests/testmarshal.cc`).
- **Port** the Java tests for the same classes if any exist: search
  `docs/inventory/tests/framework-softwaremodeling.md` for classes under
  `ghidra.program.model.pcode` and `ghidra.program.model.address` that
  test encoders, decoders or the pure address arithmetic; port those that
  need no program database and mark them. Leave the others unmarked and
  list them in your report.
- **Derived tests** for everything Ghidra does not test: each bit helper
  (table-driven, including edge sizes), space `printRaw`/`read`
  round-trips, range-list merging, join-record construction, address
  ordering, every decoder error path.
- **Property tests:** encode → decode round-trip for arbitrary element
  trees in both forms; XML and packed decoders agree on the same tree;
  decoders never panic on arbitrary bytes.
- **Fuzz targets:** `packed_decode`, `xml_decode`.
- **Corpus test:** every XML-family file under the Ghidra spec tree opens
  and walks to the end through the XML decoder (skips when `../ghidra` is
  absent).
- **Benchmarks:** packed decode and encode throughput (a synthetic
  document of one million elements with mixed attributes), XML decode of
  the largest `.cspec`; numbers in `PERF.md`.

## 7. Acceptance

1. The 18 marshal tests pass in their ported form.
2. The packed form is byte-identical to Ghidra's for the test documents
   (check against the byte sequences implied by `marshal.cc`; a
   hand-computed vector for each type code).
3. XML encoder output matches Ghidra's text for the test documents.
4. The corpus test passes over the whole spec tree.
5. No `unwrap`, indexing panic or `unsafe`; fuzz targets run 60 seconds
   each without a finding.
6. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- No global id registration; ids are immutable tables (section 4.1).
- Packed decoding works on a contiguous borrowed slice rather than a
  buffer chain (section 4.4).
- Errors are typed values instead of exceptions.

(The implementing agent appends further differences here.)

Appended by the `core-marshal` track:

**`bk-marshal`**

- XML is tokenised by `quick-xml` and checked by `xml/parse.rs`: one root,
  only white space or comments around it, every element closed, no
  DOCTYPE, known entities only. Element content follows `xml.y`: character
  data, each reference and each CDATA section are separate pieces, and a
  piece that is only white space is dropped. Relative to `xml.y`: character
  references give the Unicode character (Ghidra's C++ truncates to one
  byte; its Java side does what basilisk does); an unknown entity, a
  mismatched end tag and a repeated attribute are errors (Ghidra accepts
  them); processing instructions, comments after the root, a byte order
  mark and `standalone` are accepted (Ghidra rejects them; they are legal
  XML). Not checked, where Ghidra rejects: `<` inside an attribute value,
  `]]>` in character data, non-ASCII or malformed names.
- `XmlDecoder::close_element` always checks for unread children and a
  matching id (Ghidra: debug builds only), so both forms fail alike.
- A read with no current attribute is `NoCurrentAttribute` in both forms
  (Ghidra: undefined in XML, reads the next attribute in packed); after an
  attribute of the wrong type the packed decoder always skips it, booleans
  included.
- Packed strings must be valid UTF-8 (`InvalidUtf8`, at the first invalid
  byte); Ghidra passes bytes through.
- The packed decoder does not stop at a NUL byte and accepts empty input
  (Ghidra's ingest ends at NUL and throws on empty input).
- Both decoders refuse more than `MAX_ELEMENT_DEPTH` (1,000) nested open
  elements (`TooDeep`); skipping is iterative and unlimited.
- `patch_integer_attribute` (Java `PatchPackedEncode`) skips a string's
  length bytes correctly and patches only integer attributes; the Java code
  misparses a string before the target.
- Encoders write into memory (`Vec<u8>`, `String`) instead of a stream.
- `read_enum`/`write_enum` replace `readOpcode`/`writeOpcode` and
  `readDatatypeMeta`/`writeDatatypeMeta`: the name in XML, a non-negative
  signed integer in the packed form, as Ghidra writes both.
- "Nothing there" is `None` rather than id 0 (`peek_element`,
  `open_element`, `next_attribute`).
- Bit helpers (`bk_core::bits`): results are defined where the C++ is
  undefined (shifts of 64 or more, sizes 0 and above 8; each function's
  documentation says what it returns); `sign_extend` with
  `size_out < size_in` truncates.

**`bk-core`**

- Index 0 belongs to the constant space alone (`ReservedIndexZero`):
  Ghidra requires the constant space to be at 0, basilisk also forbids any
  other space there, so `Address::is_constant` and
  `JoinRecord::is_pure_padding` compare an index and need no manager.
- Space indices above `MAX_SPACE_INDEX` (0xffff) are refused
  (`IndexTooLarge`); Ghidra resizes its table to whatever a document says.
- The constant, fspec and iop spaces are always little endian; Ghidra
  gives them the host's endianness, and basilisk takes x86-64's (ADR-021,
  on `master` since this track branched).
- `copy_spaces` copies the spaces; Ghidra shares them between managers by
  reference count, so a later truncation of one shows in the other.
- `insert_space` checks everything before changing anything; Ghidra sets
  the special-space pointer (unique, join, …) before the duplicate-index
  check and leaves it dangling when that check throws.
- A decoded space must have `name`, `index` and `size` (Ghidra leaves them
  uninitialised); a missing `delay` reads as 0 (uninitialised in Ghidra).
  An overlay or join piece naming an unknown space, a gap in a join's
  piece numbering, a join without a join space and a register name the
  processor does not have are errors where Ghidra dereferences null or
  reads uninitialised memory.
- `SeqNum`: `Eq` and `Ord` both compare the address, then the unique
  number (Rust requires them to agree; Ghidra's `==` compares only the
  unique number); `same_time` is Ghidra's `==`; `order` takes part in
  neither, as in Ghidra. `SeqNum::decode` reads the address from the
  element's own attributes; Ghidra's reads a child element its encoder
  never writes, and has no caller.
- `Address::const_from_space` (Ghidra `createConstFromSpace`) stores the
  space's index, not a host pointer, and
  `VarnodeData::space_from_const` reads it back.
- Where Ghidra returns -1 for "does not overlap" (`overlap`,
  `justifiedContain`, `overlapJoin`) the result is `Option<u32>`;
  `BitRange::overlap_test` returns an enum (`BitOverlap`) whose variants
  name Ghidra's -1, 0, 1, 2, 3 and 4.
- Address methods that need a space answer `false`/0/`None` for the
  invalid and maximal addresses instead of dereferencing a null pointer;
  `printRaw` prints `invalid_addr` or `maximal_addr`, and a join offset
  without a record prints `{unlinked:0x…}` instead of throwing.
- Fspec and iop offsets print with the ordinary `printRaw`; Ghidra's
  `FspecSpace` and `IopSpace` print the call specification or p-code op
  behind the pointer, which belong to the decompiler.
- Reading a join address from text (`JoinSpace::read`) recurses through
  pieces that name the join space by its shortcut; the depth is limited to
  `MAX_JOIN_READ_DEPTH` (8) (`BadJoinString`).
- `getNextSpaceInOrder` is `first_space` and `next_space_after`, which
  returns `None` where Ghidra returns its maximal-space marker;
  `Range::last_addr_open` turns that into the maximal space at offset 0, as
  Ghidra does.
- Registers come from a `RegisterLookup` the manager holds (in Ghidra
  every space points at its `Translate`). Join records sit behind a
  read-write lock in the manager, because decoding a join address creates
  one while the decoder holds the manager by shared reference (Ghidra's
  `findAddJoin` is `const` with `mutable` members). Join offsets are
  handed out in creation order, as in Ghidra.
- Decoding `<spaces>` resolves space references through a
  `SpaceDirectory` the manager keeps up to date, because a decoder cannot
  hold the manager being filled; Ghidra's decoder points at the manager
  itself.
- `Range` orders by space, first and last offset; `RangeList` keys its
  ranges by space and first offset only, as Ghidra's `set<Range>` does.
  `Range::from_properties` reports an unknown space as `UnknownSpaceName`
  ("Unknown address space", where Ghidra says "Undefined space").
- `BitRange` arithmetic wraps instead of overflowing, and its mask is 0
  for a negative bit count or position (Ghidra's shift is undefined there).

## 9. Status

Implemented by the `core-marshal` track (2026-11-12); status report
`docs/agents/core-marshal.md`.

**Built.** `bk-marshal`: element and attribute ids with a per-scope name
table (`IdTable`), the `Decoder` and `Encoder` traits, `XmlDecoder` over a
small DOM built from `quick-xml` events, `XmlEncoder` (Ghidra's text
exactly, with or without formatting), `PackedDecoder` over a borrowed
`&[u8]`, `PackedEncoder` with `patch_integer_attribute`, C++ `istream`
number parsing, and the abstract space attributes (`SpaceId`, `SpaceRef`,
`SpaceResolver`). `bk-core`: `Space` (one struct with a `SpaceKind`),
`SpaceManager` (insertion rules, lookups by index, name and shortcut,
special and default spaces, truncation, base registers, no-high-pointer
ranges, constant resolvers, registers, join records, `<spaces>` decoding),
`Address`, `SeqNum`, `VarnodeData`, `Range`, `RangeProperties`,
`RangeList`, `BitRange`, `JoinRecord`, `TruncationTag`, `AddressResolver`,
the `printRaw`/`read` text forms of every space kind, encode/decode of
offsets including join pieces, and the bit helpers.

**Tests.** The 18 cases of `testmarshal.cc` (both forms, plus
`marshal_closemismatch_xml`) and the Java `EncodeDecodeTest`; hand-written
packed vectors per type code; every decoder error path; property tests
(round trips in both forms, XML and packed agree, decoders never panic,
range lists against a byte set); the corpus test over the 501 XML files of
Ghidra's processor and data-test trees; integration tests of the address
model; fuzz targets `packed_decode` and `xml_decode` (60 s each without a
finding); benchmarks in `docs/PERF.md`.

**Gaps.**
- The Java program-model address tests (`ghidra.program.model.address.*`,
  eleven classes) and `VarnodeTest` are not ported: they test Java's
  program-model API (`AddressSet`, segmented addresses, signed spaces,
  `addNoWrap`), a different model from the C++ one this spec defines. They
  belong with the program model.
- Agreement with Ghidra's encoders is checked against a transliteration
  of `marshal.cc` (`crates/bk-marshal/tests/gen_marshal_vectors.py`), not
  against a run of Ghidra's binaries; a differential test against the
  reference `decomp` waits for `reference-tools`.
- `Translate`, `PcodeEmit`, `AssemblyEmit` and the `.sla` variant of space
  decoding (`SleighBase::decodeSlaSpaces`) are left to the SLEIGH runtime
  (M1), as section 3 says.
