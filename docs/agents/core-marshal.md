# Track `core-marshal` — handover

Written 2026-11-12 at a checkpoint, on the owner's instruction to stop and
hand over. The track is **not finished**: `bk-marshal` is essentially
complete, `bk-core` has barely started. The next agent continues from this
worktree (`/Users/tatu/slop/basilisk-wt/core-marshal`, branch
`core-marshal`); this file is everything you need from my context.

Spec: `docs/features/core-marshal.md`. Section numbers below refer to it.

## Done

### `bk-marshal` (spec §4.1–4.5) — complete except fuzz targets, benchmarks and docs

| Module | What it holds | Against the spec |
|---|---|---|
| `ids.rs` | `AttributeId`, `ElementId` (const, name + number), `AttrCode`/`ElemCode` (the number as read from a document), the ids of `marshal.cc`, `IdTable` (name → id hash lookup, built once from per-crate static slices, conflicting names rejected) | §4.1 complete |
| `decoder.rs` | `trait Decoder<'a>` | §4.2 complete |
| `encoder.rs` | `trait Encoder` | §4.3 complete |
| `error.rs` | `DecodeError`, `EncodeError`, `AttributeKind` | complete |
| `space.rs` | `SpaceId` (opaque index), `SpaceRef`/`PackedSpace` (what an encoder writes), `trait SpaceResolver` (what a decoder looks up), `NoSpaces` | §5 layering, complete |
| `xml/parse.rs`, `xml/dom.rs` | `Document::parse` (tokenised by `quick-xml`, assembled into an arena DOM applying `xml.y`'s rules), `ElementRef` | §4.5 complete |
| `xml/decode.rs` | `XmlDecoder` | §4.2 complete |
| `xml/encode.rs` | `XmlEncoder`, `xml_escape` | §4.3 complete |
| `xml/number.rs` | C++ `istream` integer rules (`scan`, `parse_u64`, `parse_i64`, `parse_u32`, `Radix`), `parse_bool` | §4.2 complete |
| `packed/mod.rs` | `format` constants (`PackedFormat`) | §4.4 complete |
| `packed/decode.rs` | `PackedDecoder` over a contiguous `&[u8]`, strings borrowed | §4.4 complete |
| `packed/encode.rs` | `PackedEncoder` into a `Vec<u8>`, plus `patch_integer_attribute` (Java `PatchPackedEncode`) | §4.4 complete |

API points the next crates depend on:

- "Nothing there" is `None`, not id 0: `peek_element() -> Option<ElemCode>`,
  `open_element() -> Result<Option<ElemCode>>`,
  `next_attribute() -> Result<Option<AttrCode>>`. Nine Ghidra call sites
  rely on `openElement()` returning 0 to end a loop, so `open_element` keeps
  that meaning as `None`; `open_element_expecting(ELEM_X)` is the strict one.
- Reads of the current attribute are `read_bool`, `read_signed`,
  `read_unsigned`, `read_string`, `read_space`, `read_signed_or_string`;
  lookups by id are the same names with `_attr` and an `AttributeId`.
- `Decoder<'a>` has a lifetime: `read_string` returns `&'a str` borrowed
  from the document, valid while decoding continues. Write consumers as
  `fn decode<'a, D: Decoder<'a> + ?Sized>(d: &mut D, …)`.
- **Opcode/metatype cut** (spec §3): instead of `readOpcode`/`writeOpcode`
  there is a generic pair, `Decoder::read_enum(&by_name)` /
  `read_enum_attr`, and `Encoder::write_enum(attr, value, name)`: a named
  enumeration is its name in XML and a non-negative signed integer in the
  packed form, which is exactly how Ghidra marshals opcodes and metatypes.
  `bk-pcode` can build `read_opcode` on it without `bk-marshal` depending on
  `bk-pcode` (which would be a cycle if `bk-pcode` ever needs `bk-core`).
- Both decoders refuse to open more than `MAX_ELEMENT_DEPTH` (1,000) nested
  elements (`DecodeError::TooDeep`), to bound the recursion of consumers.
  Skipping (`close_element_skipping`) is iterative and not limited.

### `bk-core` (spec §4.6–4.7) — started

In the build and tested:

| Module | What it holds | Against the spec |
|---|---|---|
| `bits.rs` | all the free bit functions of `address.hh`/`address.cc`: `calc_mask`, `calc_uint_max`, `calc_int_max`, `calc_int_min`, `pcode_right`, `pcode_left`, `minimalmask`, `sign_extend_bit` (Ghidra `sign_extend(intb,int4)`), `zero_extend_bit`, `signbit_negative`, `uintb_negate`, `sign_extend`, `extend_signbit`, `byte_swap`, `byte_swap_signed`, `leastsigbit_set`, `mostsigbit_set`, `popcount`, `count_leading_zeros`, `coveringmask`, `bit_transitions` | §4.7 bit helpers complete |
| `ids.rs` | the ids of `space.cc`, `address.cc`, `translate.cc` (`pcoderaw.cc` defines none), static slices, `id_table()` | complete |
| `error.rs` | `SpaceError` with a variant for each `LowlevelError` thrown in the four source files, plus `Decode`/`Encode` wrappers | complete as a list; adjust as the code that raises them is written |

**Written but never compiled** (not declared in `lib.rs`; treat as drafts):

| File | State |
|---|---|
| `src/space/mod.rs` (736 lines) | `Space`, `SpaceKind`, `SpaceType`, `SpaceFlags`, the reserved names and indices, all constructors (`constant`, `other`, `unique`, `join`, `fspec`, `iop`, `processor`, `spacebase`, `overlay`), accessors, `wrap_offset`, word-size scaling, `marshal_ref`, base-register handling, truncation. It declares `pub mod codec; pub mod text;` which do not exist. Over the 600-line guideline: move flags/type/kind into `space/kind.rs`. |
| `src/varnode.rs` | `VarnodeData` (16 bytes: private space key + `pub offset` + `pub size`), ordering, `contains`, `is_contiguous`, `decode`, `decode_from_attributes`, `encode`. Depends on `address::{Address, SpaceKey}` and `manager::SpaceManager`, not written. |
| `src/register.rs` | `trait RegisterLookup` (`register`, `register_name`, `exact_register_name`) and `NoRegisters`. |

Not started: `address.rs` (`Address`, `SeqNum`), `manager.rs`
(`SpaceManager`), `join.rs`, `range.rs`, `space/codec.rs`, `space/text.rs`,
`bitrange.rs`, `TruncationTag`, `AddressResolver`.

## Verified

Run on this branch at the last commit (rustc 1.97.1, macOS arm64):

- `CARGO_BUILD_JOBS=2 cargo test -p bk-marshal -p bk-core` — all pass:
  `bk-marshal` 41 unit tests, `tests/testmarshal.rs` 20, `tests/decoder_errors.rs`
  20, `tests/properties.rs` 10 properties at 512 cases each, `tests/corpus.rs` 2;
  `bk-core` 14 (12 in `bits`, 2 in `ids`). 107 tests, 0 failed, 0 ignored.
- `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra cargo test -p bk-marshal --test corpus -- --nocapture`
  — `corpus: 501 files, 49031 elements, 111275 attributes`; every file
  parses and walks to the end with the strict `close_element`; names,
  attribute names and values agree with `roxmltree` on every element;
  content differs from `roxmltree`'s in white space only in 3 elements (see
  "What I learned"). Without the variable the two tests print `skipped: …`
  and pass.
- `cargo clippy -p bk-marshal -p bk-core --all-targets` — no warnings, **with
  this branch's lint configuration**. `master`'s is stricter now; expect new
  findings after merging it.
- `cargo fmt --all --check` exit 0; `scripts/check-file-size.sh` exit 0.
  (`cargo fmt` does not see the three undeclared `bk-core` files.)

Not run: the full gate (`scripts/gate.sh`), any fuzzing, any benchmark.
Nothing in `docs/PERF.md`. The three draft files have never been through
the compiler.

How the encodings are known to match Ghidra (acceptance 2 and 3):
`crates/bk-marshal/tests/gen_marshal_vectors.py` is a line-by-line Python
transliteration of `PackedEncode` and `XmlEncode` from `marshal.cc` (the
threshold ladder of `writeInteger`, the tag state machine). Its output is
the block of `*_PACKED` / `*_XML` constants in `testmarshal.rs`, and the
Rust encoders reproduce all ten vectors (five test documents, both forms).
`packed/encode.rs` and `xml/encode.rs` add hand-computed vectors per type
code and per formatting case. This is agreement with a second reading of
the C++, not with a run of Ghidra's binary; a differential run against the
reference `decomp` is worth adding once `reference-tools` lands.

## Remaining, in the order I would do it

1. **Merge `master`** into the branch first (the coordinator's instruction;
   stricter lints, licence change, a rule against `unsafe`). Fix what the
   new lints report in `bk-marshal`.
2. **`bk-core`: get the drafts compiling.** Write `address.rs`
   (`SpaceKey`, `Address`, `SeqNum`), then `manager.rs`, `join.rs`,
   `space/codec.rs`, `space/text.rs`, `range.rs`, declare everything in
   `lib.rs`. The design is under "In flight".
3. **`bk-core` tests** (spec §6 "Derived tests"): space `print_raw`/`read`
   round trips, range-list merging, join-record construction, address
   ordering and the `size_of::<Address>() <= 16` assertion, each space
   kind's decode, `<spaces>` decode against a real `.sla`'s space section or
   a hand-written one, encode → decode round trips of `Address`,
   `VarnodeData`, `SeqNum`, `Range`, `RangeList` in both forms (property
   tests), manager insertion rules and every `SpaceError`.
4. `BitRange` (`address.hh`/`address.cc`; not in the spec's table but in the
   source files it assigns — pure arithmetic, about 200 lines).
   `TruncationTag`, `AddressResolver`.
5. **Fuzz targets** `packed_decode` and `xml_decode` in `fuzz/` (the root
   `Cargo.toml` already has `exclude = ["fuzz"]`; no `fuzz/` directory
   exists yet on this branch — another track may create `fuzz/Cargo.toml`,
   so add entries append-only). The `drive` function in
   `tests/properties.rs` (a random walk of decoder operations) is the body
   to reuse. Run each 60 s (`cargo +nightly fuzz run <target> -- -max_total_time=60`).
6. **Benchmarks** (spec §6): packed decode and encode of a synthetic
   million-element document, XML decode of the largest `.cspec`; as
   `#[ignore]` release tests (no new dependency); numbers into `docs/PERF.md`.
7. **Docs**: append to §8 "Differences from Ghidra" in the spec (the list is
   under "Decisions" below, ready to copy) and fill §9 "Status"; replace
   this handover with the final report `RULES.md` asks for.
8. **Checklist**: `testmarshal.cc` and `EncodeDecodeTest` are marked.
   Still to decide and mark in
   `docs/inventory/tests/framework-softwaremodeling.md`:
   - `LinkedByteBufferTest` (5 tests): I would mark `[-]` — it tests Java's
     chunked ingest buffer, which basilisk replaces with a contiguous slice
     by decision (spec §4.4). What it checks about values crossing the
     1,024-byte boundary is covered by
     `testmarshal.rs::values_across_the_ingest_buffer_boundary`.
   - `VarnodeTest` (2 tests): tests `Varnode.intersects` of the Java
     `ghidra.program.model.pcode.Varnode`, with Java's signed stack space.
     The C++ `VarnodeData` has no `intersects`. Leave unmarked for the crate
     that owns the Java-side varnode, or add `VarnodeData::intersects` and
     port it — a coordinator decision.
   - The eleven `ghidra.program.model.address.*` classes
     (`AddressFactoryTest`, `AddressMapImplTest`, `AddressRangeImplTest`,
     `AddressRangeSplitterTest`, `AddressSetMappingTest`, `AddressSetTest`,
     `AddressSpaceTest`, `GenericAddressSpaceTest`, `GenericAddressTest`,
     `SegmentedAddressSpaceTest`, `SegmentedAddressTest`): these test
     Java's program-model address API (`GenericAddressSpace.addNoWrap`
     throwing `AddressOverflowException`, signed spaces, `"ram:0x100"`
     parsing, `AddressSet`, segmented addresses, overlay ordering keys),
     which is a different model from the C++ one this spec defines. I left
     them unmarked; they belong with whichever crate ports that Java model
     (`bk-program`?). The spec's "port those that need no program database"
     would require building that model here — flag to the coordinator.
9. **The gate**: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`.
10. Smaller follow-ups: split `tests/decoder_errors.rs` (906 lines, under
    the ceiling but over the 600 guideline); replace the local
    `ghidra_dir()` helper in `tests/corpus.rs` with `bk-testkit`'s once that
    crate is merged.

## In flight: the `bk-core` design I had settled on

I was writing the `bk-core` modules bottom-up and had just finished
`varnode.rs`; the next file was `address.rs`. Decisions already made (the
drafts assume them):

- **`SpaceId`** is `bk_marshal::SpaceId` re-exported — the opaque identity
  the marshalling layer hands around *is* the typed index into the manager,
  so there is no conversion.
- **Index 0 is reserved for the constant space** (`CONSTANT_SPACE`), and the
  manager must reject any other space at index 0. Ghidra already requires
  the constant space to be at 0; forbidding the converse makes
  `Address::is_constant()` and `JoinRecord::is_pure_padding()` a comparison
  of the index, with no manager lookup. Record it as a difference.
- **`SpaceKey`** (private, in `address.rs`): a `u32` where 0 means "no
  space" (Ghidra's null `base`: the invalid address, also `m_minimal`),
  `u32::MAX` means Ghidra's `~0` pointer (`m_maximal`), and anything else is
  `index + 1`. `Address { space: SpaceKey, offset: u64 }` then derives
  `Ord` and gets exactly Ghidra's `operator<` (invalid first, maximal last,
  otherwise index then offset) without the manager, in 16 bytes.
  `varnode.rs` expects `SpaceKey::NONE`, `SpaceKey::of(SpaceId)`, `.id()`,
  `.raw()`, and `Address::{key, from_key, offset, is_contiguous, encode_sized}`.
  Note `Range::getLastAddrOpen` can produce "maximal space, offset 0", which
  is not `Address(m_maximal)` (offset `~0`); keep a way to build it.
- **Everything that needs space data takes `&SpaceManager`**
  (`addr.is_big_endian(&mgr)`, `addr.add(&mgr, n)`, `VarnodeData::decode(d, &mgr)`).
  Where Ghidra returns `-1` for "does not overlap" (`overlap`,
  `justifiedContain`, `overlapJoin`) I planned `Option<u32>`; the bit
  helpers keep Ghidra's `-1` because later code does arithmetic on it.
- **Registers**: the manager holds an `Arc<dyn RegisterLookup>` (default
  `NoRegisters`), mirroring Ghidra where every space points at its
  `Translate`. That keeps one context object for all decode/print calls.
  The draft `varnode.rs` calls `manager.register(name) -> Result<VarnodeData, SpaceError>`
  (`UnknownRegister` when absent).
- **Join records** live in the manager behind a lock
  (`RwLock<JoinTable>`, records as `Arc<JoinRecord>`), because decoding a
  join address creates a record (`findAddJoin` is `const` with `mutable`
  members in Ghidra) while the decoder holds the manager as its
  `SpaceResolver`; `&mut` is impossible there. `std::sync::RwLock` with
  `PoisonError::into_inner` avoids both `unwrap` and a dependency
  (`parking_lot` is in the workspace if preferred). Caveat for the
  decompiler wave: join offsets are allocated in creation order, so one
  manager shared by parallel decompilations gives scheduling-dependent
  offsets; a per-function table will be needed for determinism. The lookup
  set is ordered like `JoinRecordCompare`: piece count, then pieces
  lexicographically (`VarnodeData`'s order: space, offset, size
  *descending*), then unified size.
- **Spaces are cloned, not shared**: Ghidra's `copySpaces` shares `AddrSpace`
  objects between managers by refcount, so a later `truncateSpace` on one is
  seen by the other. A Rust `copy_spaces` clones; record as a difference.
- **`RangeList`** as `BTreeMap<(SpaceId, u64 /*first*/), u64 /*last*/>`:
  Ghidra's `set<Range>` orders by (space index, first) only.
  `upper_bound(Range(s, x, x))` is `range((Excluded((s, x)), Unbounded)).next()`.
- **`SeqNum`**: Ghidra's `==` compares only `uniq` while `<` compares
  address then `uniq`, which Rust's `Eq`/`Ord` contract forbids. Plan: `Eq`
  and `Ord` on (address, uniq), plus a `same_time` method for Ghidra's test.
- `MAX_SPACE_INDEX = 0xffff` caps the index a space may claim (Ghidra
  resizes its vector to whatever a document says).
- The constant, fspec and iop spaces are always little endian (Ghidra uses
  the host's endianness).

Things that did not work, so you do not retry them:

- **`roxmltree` cannot give Ghidra's content rule.** It merges character
  data, references and CDATA into one text node, and a merged node's
  `range()` covers only its first piece (`"  <![CDATA[x]]>  "` reports the
  range of the two leading spaces), so the piece boundaries cannot be
  recovered from it. That is why the parser moved to `quick-xml`.
- `quick-xml` 0.42: `Attribute::unescape_value` is deprecated in favour of
  `normalized_value`, which normalises white space and so differs from
  Ghidra; `parse.rs` calls `quick_xml::escape::unescape` on the raw value
  instead. `BytesStart::name()`/`attributes()` borrow from the event, not
  from the source; `parse.rs` re-finds the tag text inside the source by
  address (`reslice`, safe code) and builds `Attributes::new(text, name_len)`
  to get source-lifetime strings.
- `prop_oneof!` needs a weight on every arm or on none.

## What I learned from Ghidra's source that the spec does not say

Places the spec is wrong or incomplete:

1. **`ATTRIB_UNKNOWN`/`ELEM_UNKNOWN` are not id 0** (§4.1). They are 161 and
   292 ("number serves as next open index") in both C++ and Java, and that
   is what `find` returns for an unregistered name. 0 is only the "no more
   attributes / elements" return value. Implemented as in Ghidra.
2. **`closeElement` never checks unread attributes** (§4.2), in either form.
   The packed decoder checks that the next byte is an element end (so unread
   *children* fail); `XmlDecode` checks children and the id only under
   `CPUI_DEBUG`, which is why `testmarshal.cc` has no
   `marshal_closemismatch_xml`. basilisk's XML decoder always checks, so the
   forms fail alike.
3. The flag list in §4.6 is missing `allows_wrapped_range` (0x1000),
   `addressable_all` (0x2000) and `addressable_none` (0x4000), which exist
   at the pinned commit and drive `highPtrPossible`.
4. `address.hh` also defines `BitRange`, not mentioned in §2.
5. `AddrSpace::read` parses `name-or-number[:size][+offset]`, not
   `0x…+size` (§4.6): after the first `:` or `+`, `:n` gives the size and
   `+n` an offset added to the address.
6. The Java address tests (§6) are of a different model (see Remaining 8).

Behaviours that are easy to get wrong:

- **XML content is delivered in pieces** (`xml.y` `print_content`): each run
  of character data, each reference and each CDATA section separately, and a
  piece that is only white space (space, `\n`, `\r`, `\t`) is dropped. So
  `<a> &amp; </a>` is `&`, `<a>x <!-- c --> y</a>` is `x  y`, and
  `<body>\n<![CDATA[code]]>\n</body>` is `code`. A standard parser's text
  nodes give different white space in exactly three elements of the corpus:
  `<com>` in `datatests/injectoverride.xml` and two `<body>` elements in
  `Hexagon/data/languages/hexagon.cspec`.
- Ghidra's parser does no attribute-value normalisation and no line-end
  normalisation; it rejects processing instructions, DOCTYPE, the
  `standalone` pseudo-attribute and anything but one white-space run or one
  comment after the root; it accepts mismatched end tags and duplicate
  attributes; it truncates character references to one byte and turns an
  unknown entity into byte 0xFF. The corpus (501 files) uses none of these
  edge cases: no DOCTYPE, PI, BOM, CR, namespace prefix, or white space or
  references inside attribute values, and one file with a character
  reference.
- **Formatted `XmlEncode` output is not lossless for content followed by a
  child**: the new line and indent written before the child become part of
  the content when read back (`<a>text\n  <b/>` holds one piece). Found by
  the round-trip property test; it is Ghidra's behaviour.
- `XmlDecode::read*(attribId)` leaves the sequential attribute position
  alone, while `PackedDecode` resets it to the start (the header comment
  promises the reset). Both are reproduced; code written for both forms must
  not mix lookup by id into a `next_attribute` loop.
- After a child is closed, `XmlDecode` reports no more attributes until
  `rewindAttributes` (its index is set to 1000) but still finds attributes
  by name on the parent; `PackedDecode` would read the closed child's bytes.
  basilisk's packed decoder returns `None` / `AttributesUnavailable`.
- `PackedDecode` reads integers with any length code up to 15, shifting the
  excess bits out, and never checks the marker bit of a group. Kept.
- `PackedEncode::writeHeader` lets an id above 4,095 spill into the
  record-type bits. Kept (no registered id is that large).
- XML integers are read with `istream >>` with the base flags cleared and
  no error check: text without digits is 0, overflow saturates, trailing
  junk is ignored, `-1` read as unsigned is `u64::MAX`, `08` is 0.
- `SeqNum::decode` is broken in Ghidra (it calls `Address::decode`, which
  opens a *child* element that `SeqNum::encode` never writes; the packed
  form then fails on close) and has no caller. Implement the evident intent:
  read the address from the `<seqnum>` element's own attributes.
- `RangeList::insertRange` merges overlapping ranges but **not adjacent
  ones**, despite its comment; `RangeList::decode` inserts ranges without
  merging and silently drops one whose (space, first) repeats.
- `JoinSpace::decodeAttributes` treats *every* attribute id from
  `ATTRIB_PIECE` (94) up to 94+64 as a piece, and leaves gaps in the piece
  list uninitialised; `piecemeal="x"` in XML throws "Bad indexed attribute".
  Its piece syntax is `space:offset:size` or a register name.
- Spaces decoded from a document get neither `addressable_all` nor
  `addressable_none` (only the full constructor sets one, from
  `delay == 0`), and a decoded space with no `delay` attribute has an
  uninitialised delay in C++.
- `SpacebaseSpace::setBaseRegister` compares a new register with the
  *truncated* stored one, so re-registering the same truncated register
  throws. The draft reproduces this.
- `AddrSpaceManager::assignShortcut`: `%` for a processor space named
  `register`, otherwise the first letter lowercased; on collision the next
  letter (wrapping to `a`), and after 26 collisions `z` without registering.
- `JoinSpace::read` recurses through a piece's shortcut; a piece naming the
  join space itself recurses once per character. Guard it (ADR-009).
- `bit_transitions` with a size above 8 bytes counts one extra transition
  when bit 63 is set (the loop sees the value fall to zero).

## Decisions and crate evaluations

Figures from the crates.io API on 2026-11-12 (total downloads / last 90
days / dependents / latest release).

| Crate | Figures | Decision |
|---|---|---|
| `quick-xml` 0.42.0 | 542 M / 173 M / 2,935 / 2026-08-22, MIT | **Adopted** for XML tokenising (added to `[workspace.dependencies]`). It is the most used XML crate, and its event stream — text, CDATA and references as separate events, values unnormalised, names with their prefix — maps one-to-one onto `xml.y`'s rules, so Ghidra's values come out without workarounds. It does not check everything: `parse.rs` adds single root, nothing but white space outside it, all elements closed, no DOCTYPE, known entities, and turns on its comment check. |
| `roxmltree` 0.21.1 | 104 M / 40 M / 994 / 2026-10-24, MIT OR Apache-2.0 | ADR-011 adopted it provisionally. It parses all 501 files, but **fails the value check** of §4.5: it cannot reproduce Ghidra's content rule (three corpus elements differ, and the general rule differs wherever white space touches a reference or CDATA), normalises attribute white space and line ends, and strips namespace prefixes. Kept as a **dev-dependency oracle** in `tests/corpus.rs`. **This changes ADR-011; the coordinator should confirm**, and tell the `lang` track if it reads spec files with `roxmltree` directly. |
| `xml-rs` | 166 M / 31 M / 371 / 2026-08-06 | Not chosen: fewer users than `quick-xml`, owned strings only. |
| `xmlparser` | 168 M / 51 M / last release 2023-09-30 | Not chosen: unmaintained tokeniser. |
| `thiserror` 2.0.21 | 1,835 M / 520 M | In use (workspace). |
| `bitflags` 2.13.2 | 2,253 M / 583 M | For `SpaceFlags` in the draft (workspace). |
| `proptest` 1.12.0 | 243 M / 75 M | In use for tests (workspace). |
| `rustc-hash` 2.1.3 | 1,010 M / 300 M | Not added. `IdTable` uses `std::collections::HashMap`; swap in `FxHashMap` if a profile of XML decoding shows the lookup. |
| `parking_lot` 0.12.5 | 1,269 M / 280 M | Not used yet; `std::sync::RwLock` suffices for the join table. |

Written by hand, with the reason: the packed codec and the XML encoder
(Ghidra-defined byte-exact formats); `xml/number.rs` (nothing on crates.io
reproduces `istream` extraction with base detection, saturation and
tolerated junk — `from_str_radix` and `lexical` reject what C accepts); the
bit helpers (thin wrappers over `u64` intrinsics, kept under Ghidra's names
and `-1` conventions and checked against transliterations of its loops).

Differences from Ghidra so far (to be appended to spec §8):

- XML is tokenised by `quick-xml` and checked as described above. Relative
  to `xml.y`: character references produce the Unicode character (Ghidra's
  C++ truncates to one byte; its Java side does what basilisk does); an
  unknown entity, a mismatched end tag and a repeated attribute are errors
  (Ghidra accepts all three); processing instructions, comments after the
  root, a byte order mark and `standalone` are accepted (Ghidra rejects
  them; they are legal XML and Ghidra's Java reader accepts them). Not
  checked, where Ghidra rejects: `<` inside an attribute value, `]]>` in
  character data, non-ASCII or malformed names.
- `XmlDecoder::close_element` always checks for unread children and a
  matching id (Ghidra: debug builds only).
- A read with no current attribute is `NoCurrentAttribute` in both forms
  (Ghidra: undefined in XML, reads the next attribute in packed); after an
  attribute of the wrong type the packed decoder always skips it, also for
  booleans.
- Packed strings must be valid UTF-8 (`InvalidUtf8`); Ghidra passes bytes
  through.
- The packed decoder does not stop at a NUL byte and accepts empty input
  (Ghidra's ingest ends at NUL and throws on empty input).
- `MAX_ELEMENT_DEPTH` (1,000) in both decoders.
- `patch_integer_attribute` skips a string's length bytes correctly and
  only patches integer attributes (the Java code misparses any string before
  the target and would overwrite a ten-character string).
- Encoders write into memory (`Vec<u8>`, `String`) instead of a stream.
- `read_enum`/`write_enum` replace `readOpcode`/`writeOpcode`/
  `readDatatypeMeta`/`writeDatatypeMeta`.
- `bits`: results are defined where the C++ is undefined (documented per
  function); `sign_extend` with `size_out < size_in` truncates.
- Planned for `bk-core` (see "In flight"): index 0 reserved for the constant
  space; little-endian constant/fspec/iop spaces; cloned rather than shared
  spaces; `MAX_SPACE_INDEX`; `SeqNum` equality; fixed `SeqNum::decode`; a
  space index instead of a host pointer in `create_const_from_space`.

## Commits

See `git log --oneline master..HEAD` at the end of the final message of
this run; the branch has not been merged with `master` since it was created
at `d54803a`.
