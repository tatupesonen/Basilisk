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
  the `pcode` track is writing in `bk-pcode` in the same wave. Leave them
  out; the coordinator adds them after both branches merge. Do **not**
  depend on `bk-pcode`.
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
independently. `ATTRIB_UNKNOWN`/`ELEM_UNKNOWN` (id 0) is returned for names
or numbers not registered. `ATTRIB_CONTENT` (id 1) stands for an element's
text content in XML and is an ordinary attribute in the packed form.

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
id, which fails if a different element is next), `closeElement` (fails if
attributes or children remain unread, exactly as Ghidra does),
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
`is_otherspace`, `has_nearpointers`), a shortcut character, and derived
values (highest offset, pointer bounds). Keep all of Ghidra's rules:
`wrapOffset`, `byteToAddress`/`addressToByte` word-size scaling, truncation
(`truncateSpace`), overlay containment, `printRaw` and `printOffset`
formatting, `read` (parsing `0x…+size` and register names through a
callback), `encodeAttributes`, `decode` for each kind including overlay
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
`isContiguous`, encode/decode. The bit helpers, exactly, including
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

## 9. Status

Not implemented yet.
