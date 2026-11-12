# Track `core-marshal` — final status report

Branch `core-marshal`, worktree `basilisk-wt/core-marshal`. Spec:
`docs/features/core-marshal.md` (sections 8 and 9 are filled in). The track
is complete against the spec's acceptance list; gaps are listed below.

## Built

**`bk-marshal`** (Ghidra `marshal.*`, `xml.*`, Java `PatchPackedEncode`)

- `ids`: `AttributeId`/`ElementId` (const name + number), `AttrCode`/`ElemCode`,
  the ids of `marshal.cc`, `IdTable` (hash lookup built from per-crate
  static slices; no global state).
- `Decoder<'a>` and `Encoder` traits; `XmlDecoder` over a small DOM built
  from `quick-xml` events with `xml.y`'s content rule; `XmlEncoder` (Ghidra's
  text exactly, formatted or not); `PackedDecoder` over a borrowed `&[u8]`;
  `PackedEncoder` with `patch_integer_attribute`.
- `xml::number`: C++ `istream`/`strtoul` integer rules, `parse_bool`.
- `space`: `SpaceId`, `SpaceRef`/`PackedSpace`, `SpaceResolver`, `NoSpaces`.
- `read_enum`/`write_enum` for opcodes and metatypes (no `bk-pcode`
  dependency).

**`bk-core`** (Ghidra `space.*`, `address.*`, `pcoderaw.*` `VarnodeData`,
the `AddrSpaceManager` part of `translate.*`)

- `space`: `Space` (one struct, `SpaceKind` enum, `SpaceType`, `SpaceFlags`
  with all 15 flags), constructors for every kind (`constant`, `other`,
  `unique`, `join`, `fspec`, `iop`, `processor`, `spacebase`, `overlay`),
  `wrap_offset`, word-size scaling, truncation, base registers; `codec`
  (`encode_attributes[_sized]`, `decode_attributes`, join pieces) and
  `text` (`printRaw` for every kind, `printOffset`, `read` with
  `name-or-number[:size][+delta]` and join strings) as manager methods.
- `manager`: `SpaceManager` (insertion rules, lookups by index/name/
  shortcut, shortcut assignment, special and default spaces, `copy_spaces`,
  truncation, near pointers, no-high-pointer ranges, infer-pointer bounds,
  `AddressResolver`s, `RegisterLookup`, `parse_address_simple`,
  `first_space`/`next_space_after`), `<spaces>` decoding with
  `SpaceDirectory`, `TruncationTag`; join operations (`find_add_join`,
  `find_join`, `find_join_covering`, `join_pieces`, `merge_join_sequence`,
  float extension, join and wrapping addresses, renormalisation,
  `strip_join_piece`, `overlap_join`, padding records).
- `address` (`Address`, 16 bytes, ordered without the manager), `seqnum`
  (`SeqNum`), `varnode` (`VarnodeData`, 16 bytes), `range` (`Range`,
  `RangeProperties`), `rangelist` (`RangeList`), `bitrange` (`BitRange`,
  `BitOverlap`), `join` (`JoinRecord`), `register` (`RegisterLookup`,
  `NoRegisters`), `bits` (all free bit helpers), `ids`, `error`
  (`SpaceError`).

## Tests

Gate on the final merge: `tests: 548 passed, 0 failed` (the workspace
includes `bk-pcode` from `master`; this track's crates account for 212).

| Crate | Kind | Count |
|---|---|---|
| bk-marshal | unit | 41 |
| bk-marshal | `testmarshal.rs` (ported `testmarshal.cc` + `EncodeDecodeTest`) | 20 |
| bk-marshal | `decoder_values.rs` + `decoder_structure.rs` (error paths) | 7 + 13 |
| bk-marshal | `properties.rs` (proptest, 512 cases each) | 10 |
| bk-marshal | `corpus.rs` (501 Ghidra XML files; skips without Ghidra) | 2 |
| bk-marshal | `bench.rs` (ignored benchmarks) | 3 |
| bk-core | unit (bits, ids, address, seqnum, join, rangelist, bitrange, text) | 31 |
| bk-core | `spaces.rs` | 24 |
| bk-core | `addresses.rs` (rstest tables) | 34 |
| bk-core | `joins.rs` | 12 |
| bk-core | `codec.rs` (`<spaces>` in both forms, exact XML, packed vector, decode errors) | 8 |
| bk-core | `properties.rs` (proptest, 256 cases each) | 7 |
| bk-core | `fuzz_regressions.rs` (replays `fuzz/regressions/`) | 3 |

Ghidra tests:
- Ported: `unittests/testmarshal.cc` (18) → `crates/bk-marshal/tests/testmarshal.rs`;
  `ghidra.program.model.pcode.EncodeDecodeTest` → same file.
- Not applicable: `ghidra.program.model.pcode.LinkedByteBufferTest` — tests
  Java's chunked ingest buffer, which the contiguous-slice decoder does not
  have (boundary-crossing values covered by
  `testmarshal.rs::values_across_the_ingest_buffer_boundary`).
- Left unmarked (Java program-model API, arrives with the program model):
  `ghidra.program.model.pcode.VarnodeTest` and the eleven
  `ghidra.program.model.address.*` classes — `AddressFactoryTest`,
  `AddressMapImplTest`, `AddressRangeImplTest`, `AddressRangeSplitterTest`,
  `AddressSetMappingTest`, `AddressSetTest`, `AddressSpaceTest`,
  `GenericAddressSpaceTest`, `GenericAddressTest`,
  `SegmentedAddressSpaceTest`, `SegmentedAddressTest`.

## Fuzzing

In `master`'s shared fuzz crate as `bk_marshal_packed_decode` and
`bk_marshal_xml_decode` (bodies in `fuzz/fuzz_targets/bk_marshal_shared/`,
also compiled into `crates/bk-core/tests/fuzz_regressions.rs` to replay
`fuzz/regressions/<target>/`). Each does a random walk of decoder calls
chosen by the input's leading bytes, a full document walk, and every
address-model decoder (varnode, address, seqnum, range, range list,
truncation, space, `<spaces>`), then prints what was created.

| Run | Target | Time | Runs | Result |
|---|---|---|---|---|
| 2026-11-12T17:19Z | `packed_decode` (pre-rename) | 60 s | 1,384,066 | no finding |
| 2026-11-12T17:20Z | `xml_decode` (pre-rename) | 60 s | 3,914,582 | no finding |
| 2026-11-12T17:25Z | `bk_marshal_packed_decode` | 60 s | 1,314,470 | no finding |
| 2026-11-12T17:26Z | `bk_marshal_xml_decode` | 60 s | 3,496,835 | no finding |

Command: `scripts/fuzz-smoke.sh 60 bk_marshal_packed_decode bk_marshal_xml_decode`.

## Benchmarks

`BASILISK_GHIDRA_DIR=../ghidra cargo test --release -p bk-marshal --test bench -- --ignored --nocapture --test-threads 1`;
Apple M1 Pro, load average 20–35 from other agents (lower bounds). Full
table in `docs/PERF.md`. One million mixed-attribute elements: packed
encode 28 ms (953 MB/s); packed decode 170 ms by id, 117 ms in order; XML
encode 102 ms; XML parse 332 ms; XML decode of the parsed DOM 112 ms by id,
194 ms in order. Largest `.cspec` (16 kB) parse + decode: 85 µs.

## Differences from Ghidra

Listed in full in spec section 8. The main ones: XML through `quick-xml`
(stricter in a few places, Unicode character references); `close_element`
always checks in XML; typed errors and depth limit; packed strings must be
UTF-8; constant space alone at index 0; space indices capped at 0xffff;
constant/fspec/iop spaces little endian (ADR-021); spaces copied, not
shared; atomic `insert_space`; `SeqNum` `Eq`/`Ord` on (address, uniq) with
`same_time` for Ghidra's `==`, and a working `SeqNum::decode`;
`Option`/enums instead of -1; no null dereferences on invalid addresses;
join-read recursion bounded; `<spaces>` decoded through a `SpaceDirectory`.

## Gaps

- The Java address/varnode tests above are not ported (different model).
- Encoders are checked against a Python transliteration of `marshal.cc`
  and hand-computed vectors, not against Ghidra's binary; a differential
  test against the reference `decomp` is now possible since
  `reference-tools` has landed on `master`, but was not written here.
- Benchmarks were not compared with Ghidra, and were taken on a loaded
  machine.
- Fspec/iop offsets print with the plain `printRaw` (Ghidra prints the
  object behind the pointer; decompiler concern).
- `Translate`, `PcodeEmit`, `AssemblyEmit`, `decodeSlaSpaces` are M1 work
  (spec section 3).

## Follow-ups — what the SLEIGH runtime needs to know

- **Building a manager**: `SpaceManager::new()`, `set_registers(Arc<dyn RegisterLookup>)`,
  insert `Space::constant()` first (index 0 is reserved for it), then
  `Space::other()`, processor/unique/join/spacebase spaces, then
  `set_default_code_space`. `SpaceManager` is `Send + Sync` and not `Clone`
  (`copy_spaces` copies the layout).
- **Decoding `.sla` spaces**: decoders hold `&'a dyn SpaceResolver` for the
  document's lifetime, so a decoder cannot hold the manager it fills. Build
  the decoder on `manager.directory()` (an `Arc<SpaceDirectory>` the
  manager updates on every insert) and keep using it for the symbol table;
  write `decodeSlaSpaces` in `bk-sleigh` with the public `Space`
  constructors and `insert_space` (see `SpaceManager::decode_spaces` for
  the XML/`translate.cc` variant and `tests/codec.rs` for usage).
- **Registers**: implement `RegisterLookup` on the SLEIGH register table:
  `register(name)`, `register_name(space, offset, size)` (smallest
  containing register), `exact_register_name`.
- **Values**: `Address` and `VarnodeData` are `Copy`, 16 bytes,
  `VarnodeData { offset, size }` public with `space() -> Option<SpaceId>`;
  everything needing space properties takes `&SpaceManager`.
  `Address::const_from_space`/`VarnodeData::space_from_const` encode a
  space index (not a pointer) for `LOAD`/`STORE`.
- **Joins**: `find_add_join` and friends take `&self` (lock inside); join
  offsets follow creation order, so parallel decompilation sharing one
  manager will need a per-function join table for determinism.
- **Marshalling**: `fn decode<'a, D: Decoder<'a> + ?Sized>(d: &mut D, …)`;
  `read_string` borrows from the document; `None` means "nothing left";
  lookups by id in the packed form rescan attributes (iterate in order on
  hot paths). The SLEIGH format scope gets its own `IdTable`.

## Notes for the coordinator

- Two authorised merges of `master`: at the start (`81367e6`) and for the
  shared fuzz crate (`bf7ae6c`). `master` has moved on since (`82c4549`).
  On the second merge, `Cargo.lock` was regenerated from `master`'s, with
  `roxmltree` held at the vetted 0.21.1 (the branch had drifted to 0.21.2).
- Before the shared crate arrived I had built a convention of my own; the
  parts not in `master`'s: per-track helper modules
  (`fuzz_targets/<crate>_shared/mod.rs`) that the owning crate's replay
  test includes with `#[path]`, so regressions run through exactly the
  target's code. You may want that in `fuzz/README.md`. `gnu-disasm`'s and
  `lang`'s branches still carry their own `fuzz/` crates (`bk-fuzz` with a
  `[workspace]` table; `basilisk-fuzz` without one).
- Proposed: none of the workspace lints needed weakening. Suppressions
  added: `same_name_method` on three `SpaceManager` getters that share a
  name with `SpaceResolver` methods (they return `&Space`, the trait
  returns ids), `unused_self` on `Space::print_offset`,
  `too_many_arguments` on `Space::processor`.

## Verification

Verified by running: the gate (exit 0, `tests: 548 passed, 0 failed`) on
the final merge; clippy/fmt/rustdoc of both crates; the corpus test with
`BASILISK_GHIDRA_DIR` set to `/Users/tatu/slop/ghidra`,
`/Users/tatu/slop/basilisk/../ghidra` and
`/Users/tatu/slop/basilisk-wt/core-marshal/../../ghidra/` (501 files each)
and unset (skips with a printed reason, as the worktree default root does
not reach Ghidra); the `.cspec` benchmark with a non-canonical root; all
fuzz runs and benchmarks above. Not verified: agreement with Ghidra's
binary (no differential test); the unset-variable default in the main
checkout (not run there, by the rules).

## Commits

```
bf7ae6c Merge branch 'master' into core-marshal: the shared fuzz crate
64cf68a test(core): the shared types are Send and Sync, VarnodeData is 16 bytes
6ffb471 docs(core-marshal): differences from Ghidra and status in the spec
1754ea0 docs(core-marshal): mark LinkedByteBufferTest not applicable
670aff0 perf(marshal): packed and XML throughput benchmarks, numbers in PERF.md
5d9a225 test(marshal,core): fuzz targets packed_decode and xml_decode in a shared fuzz layout
1418770 test(marshal): split the decoder error tests into values and structure
52e21af test(core): spaces, manager, joins, addresses, codec and property tests
f4ebb43 feat(core): address model — spaces, manager, addresses, joins, ranges, bit ranges
a7a0937 fix(marshal): satisfy the stricter workspace lints
81367e6 Merge branch 'master' into core-marshal
14727ff docs(core-marshal): handover report and checklist marks for the ported marshal tests
b9c4e95 feat(core): bit helpers, ids and error type; address model in progress
ffbd03c test(marshal): decoder error paths, property tests and the spec-file corpus
dd064e9 feat(marshal): element and attribute ids, XML and packed encoders and decoders
```
(plus the commit adding this report).
