# Track `bin-elf` — handover

Written 2026-11-12 by the first agent on this track, which was stopped at a
checkpoint before the spec was finished. **The track is not done.** This file
is the starting point for whoever continues: it says what exists, what was
actually run, what the crate evaluation found, what remains, what was in
flight, and what Ghidra's source says that the spec does not.

Spec: `docs/features/bin-elf.md`. Worktree: `basilisk-wt/bin-elf`, branch
`bin-elf`. Nothing is uncommitted. `master` has **not** been merged into the
branch (the coordinator asked that the next agent do that first; its lint
configuration is stricter).

When running tests, `export BASILISK_GHIDRA_DIR=<path to the Ghidra tree>`;
from a worktree the default `../ghidra` does not resolve and the real-file
test then skips (it prints why).

## 1. Done

### `bk-bin` — complete against spec §4.1 and §4.2

| Module | Content | State |
|---|---|---|
| `endian` | `Endian` | complete |
| `error` | `BinError` (`thiserror`), `is_eof()` for the cases where Ghidra throws `EOFException` | complete |
| `provider/traits` | `ByteProvider`: `len`, `read_into`, `as_slice`, `read_bytes -> Cow`, `read_byte`, validity checks, `name`/`path`; blanket impls for `&P`, `Box<P>`, `Arc<P>`; `Send + Sync + Debug`, object-safe | complete |
| `provider/memory` | `MemoryProvider<B: AsRef<[u8]>>` — owned (`Vec`), borrowed (`&[u8]`), `Arc<[u8]>`, or a memory map from a crate that may create one | complete |
| `provider/file` | `FileProvider`: positional reads, 64 × 64 KiB direct-mapped block cache with a lock per slot, large reads bypass the cache, file size verified by reading the last byte (Ghidra's `/proc` guard) | complete |
| `provider/sub` | `SubProvider` (`ByteProviderWrapper`), `UnlimitedProvider` (`UnlimitedByteProviderWrapper`: zero fill past the end) | complete |
| `provider/range_mapped` | `RangeMappedProvider` with sparse ranges and merging | complete |
| `provider/fill` | `EmptyProvider`, `FillProvider` (`StaticValueByteProvider`) | complete |
| `reader/cursor` | `BinaryReader<'a>`: `Copy`, over a provider or a bare slice, position, `at`, `with_endian`, `align`, `has_next`, `read_exact`, `read_array::<N>` | complete |
| `reader/int` | `read_{u,i}{8,16,32,64}` + `_at` + `peek_`, arrays of 16/32/64-bit types, `read_bytes -> Cow`, `read_uint`/`read_sint` (1–8 bytes), `read_u32_count` | complete |
| `reader/string` | `Charset` (ASCII, Latin-1, UTF-8, UTF-16 LE/BE, UTF-32 LE/BE); terminated and fixed-length reads, generic and per-charset; `read_terminated_bytes_at` (raw, borrowed) | complete |
| `reader/leb128` | `decode_*`, `encode_*`, `encoded_len`, `Leb128Info`, `read_uleb128`/`read_sleb128` with Ghidra's 64-bit rules | complete |

Not ported, deliberately (reasons in the spec, §8): `InputStreamByteProvider`,
`ObfuscatedFileByteProvider`, `SynchronizedByteProvider`, the write half of
`FileByteProvider`, `MemoryByteProvider`/`MemBufferByteProvider` (M4).

### `bk-elf` — partial

| Module | Content | State |
|---|---|---|
| `gen/gen_tables.py` | Generates the constant and name tables from Ghidra's Java (`ElfConstants`, `ElfSectionHeaderConstants/Type`, `ElfProgramHeaderConstants/Type`, `ElfDynamicType`, the 13 `*_ElfExtension` classes) | complete |
| `constants/` | Newtypes `Machine`, `ElfType`, `OsAbi`, `SectionType`, `SegmentType`, `DynamicTag` with constants and name lookup (`SHT_0x%08x` fallbacks); flags; 197 machines, 29 named section types, 11 named segment types, 76 dynamic tags with description and value kind | complete, unit-tested |
| `machine/` | `MachineExtension` per processor (AARCH64, ARM, AVR8, eBPF, HCS12, Hexagon, MIPS, MSP430, PIC30, PowerPC, PowerPC64, RISC-V, x86-32), selection as `canHandle(ElfHeader)`, data-type suffix, the two parsing hooks (MIPS-64 relocation layout, dsPIC30 halved data-segment sizes) | complete, unit-tested |
| `diag`, `error` | `Diagnostic { kind, message }` with Ghidra's message texts; `ElfError` for the fatal cases | complete |
| `limits` | `constrain_count`, `has_fragment` (Ghidra's `constrainHeaderCount` / `hasHeaderFragment`), `is_negative` | complete, unit-tested |
| `header` | `ElfHeader`: all fields, raw and effective values, header-endianness rule, invalid offsets, `PN_XNUM` / `e_shnum`=0 / `SHN_XINDEX` through section 0, entry-size checks, count truncation | written; exercised only by the real-file smoke test — **no tolerance tests yet** |
| `program_header` | `ProgramHeader`, 32/64 layouts, offset validity, prelink-adjusted addresses, `offset_of` (vaddr → file offset), `load_order` | written; smoke-tested; `offset_of`, `load_order` untested |
| `section_header` | `SectionHeader`, compression-header detection with Ghidra's conditions | written; smoke-tested; compression path untested |
| `compress` | `CompressionHeader`, bounded `inflate` (flate2/zlib-rs) | unit-tested; not yet reachable from a public API |
| `strtab` | `StringTable` descriptor, `read` with Ghidra's rules (offset inside the table, UTF-8, Java `trim`) | unit-tested |
| `dynamic/` | `DynamicTable` (entries to the first `DT_NULL`), lookups by tag | unit-tested |
| `symbol` | `Symbol` decode (32/64, both byte orders, zero-padded), accessors, `SymbolTable` descriptor, `SymbolIter` | unit-tested |
| `symbol_name` | `replace_invalid_chars` (`ElfSymbolNameUtils`), `is_cold_symbol_name`, `split_version` | unit-tested |
| `reloc/table` | `RelocationTable` descriptor, `Relocation` with `Elf32` / `Elf64` / `Mips64` layouts | unit-tested |
| `reloc/rel`, `reloc/relr`, `reloc/android` | Lazy decoders for REL/RELA, RELR, Android APS2 (+ the eager `scan` that counts and produces Ghidra's diagnostics) | **written, compiled, never run** — no tests |
| `tables` | `ElfTables`: everything parsed eagerly + lookups (`program_load_header_containing`, `section_load_header_containing`, …) with Ghidra's signed comparisons, prelink, image base, type names | written; partly smoke-tested |
| `parse/mod`, `parse/dynamic` | `parse()`: header → prelink → program headers (incl. the "segments add up to the file" hack) → section headers → dynamic table → string tables; `section_name()` | written; smoke-tested on real files |
| `parse/symbols`, `parse/relocs` | Symbol-table and relocation-table location | **not written** (design in §5) |
| `ElfFile<P>` (`file`) | The public type that owns the provider | **not written** (design in §5); `bk_elf::parse_tables(&dyn ByteProvider)` is a temporary entry point |
| `version` (GNU versioning), `note/*` | | **not started** |
| fixture builder | | **not started** |

## 2. Verified — what was actually run

All on 2026-11-12, macOS on an Apple M1 Pro, Rust 1.97.1, with
`BASILISK_GHIDRA_DIR` pointing at the Ghidra tree (commit `42db038f3c`).

- `CARGO_BUILD_JOBS=2 cargo test -p bk-bin -p bk-elf` — **all pass**:
  - `bk-bin`: 71 unit, 54 in `tests/binary_reader.rs`, 5 in `tests/leb128.rs`,
    19 in `tests/providers.rs`, 11 property tests in `tests/proptests.rs`,
    2 doc tests; 2 benchmarks ignored.
  - `bk-elf`: 70 unit, 2 in `tests/real_files.rs`.
- `cargo fmt --all --check` — clean. `scripts/check-file-size.sh` — passes
  (but `bk-elf/src/constants/generated.rs` is 998 lines after `rustfmt`: two
  more constants in Ghidra and it needs the `// bk:allow-long-file:` opt-out
  or a split).
- `cargo clippy -p bk-bin --all-targets` — **0 warnings**.
- `cargo clippy -p bk-elf --all-targets` — **not clean**, roughly 110 warnings:
  80 `doc_markdown` (Ghidra's description texts in the generated tables and a
  few of mine), about 20 dead-code warnings for code whose caller is not
  written yet (`inflate`, `StringTable::read`, `SymbolIter::new`,
  `RelocationTable::iter`, `scan`, `offset_in_segment`, …), a handful of
  small pedantic ones.
- **The full gate (`scripts/gate.sh`) was not run** and would fail on the
  clippy warnings above.
- Benchmarks: `cargo test -p bk-bin --release --test bench -- --ignored
  --nocapture`, numbers in `docs/PERF.md`.
- Fuzzing: **nothing was fuzzed.** There is no `fuzz/` directory.

**Ghidra tests ported and marked** (`docs/inventory/tests/`):
`BinaryReaderTest` (53 → 53 Rust tests with the same names, plus one extra),
`ByteArrayProviderTest` (2), `FileByteProviderTest` (4),
`RangeMappedByteProviderTest` (12), `LEB128Test` (5). Left unmarked as the
spec says: `MemoryByteProviderTest`, `LEB128DataTypeTest`.

**The real-file smoke test** (`tests/real_files.rs`) parses the 18 files with
the ELF magic under `GPL/GnuDisassembler/data` and
`GhidraDocs/GhidraClass/ExerciseFiles` with `parse_tables`, asserts **no
diagnostics**, and compares with `object` 0.40.0's low-level API: every ELF
header field, every program header field, every section header field, the
dynamic entries up to the first `DT_NULL`, and one string table per
`SHT_STRTAB` section. Symbols and relocations are not compared (not parsed
yet). This is spec acceptance item 2 for the half of the parser that exists.

**Written but untested:** every tolerance rule in `header.rs` (no damaged
fixtures exist yet); the compression-header path; `ProgramHeader::offset_of`;
the lookups in `tables.rs` beyond what the smoke test touches; prelink; the
three relocation decoders and the Android scan; `section_name`'s fallbacks.

**ELF tests in Ghidra.** The inventory has no test class under
`ghidra.app.util.bin.format.elf`, and `grep -rl "ElfHeader\|ElfLoader\|format\.elf" --include='*Test*.java'`
over `Ghidra/` finds no test either. The only ELF-named tests are three
Version Tracking GUI tests (`VT*Correlator_ELF_Test`,
`features-versiontracking.md`), which need whole programs and the UI — for
M4 and later, not for this track. Ghidra's ELF parser is effectively
untested upstream; everything here has to be derived from its source.

## 3. Crate evaluation for ELF parsing (owner rule: use existing crates when they fit)

**Recommendation: write the parser (continue what is here); keep `object` as
the differential oracle. Neither `object` nor `goblin` can carry the
structure parsing under Ghidra's tolerance rules.** The reasons are specific
and were checked by experiment, not assumed.

Figures from crates.io on 2026-11-12:

| Crate | Total downloads | Last 90 days | Reverse deps | Version looked at | Decision |
|---|---:|---:|---:|---|---|
| `object` | 711,985,006 | 143,299,398 | 549 | 0.40.0 (2026-08-01; 0.41.0 was 2 days old) | dev-dependency: oracle |
| `goblin` | 88,126,825 | 22,931,890 | 398 | 0.10.7 (2026-05-28) | not used |
| `flate2` | 844,323,222 | 227,711,843 | 8,481 | 1.1.10 (workspace, zlib-rs) | **used** for `SHF_COMPRESSED` |
| `memchr` | 1,728,542,191 | 460,409,746 | 2,505 | 2.8.3 (workspace) | **used** for terminator search |
| `thiserror` | 1,835,139,734 | 519,826,929 | 79,721 | 2.0.21 (workspace) | **used** |
| `tracing` | 1,039,873,007 | 268,214,236 | 48,285 | 0.1.44 (workspace) | **used** (diagnostics are also logged at debug level) |
| `unicode-properties` | 248,472,702 | 88,748,179 | 135 | 0.1.4 (2025-10-30; pinned `=`, 0.1.5 was 12 days old) | **used** for Unicode general categories |
| `unicode-general-category` | 61,496,706 | 38,736,999 | 153 | 1.1.0 | not used — `unicode-properties` is the more widely used one and does the job |
| `leb128` | 90,077,925 | 18,444,641 | 136 | 0.2.7 | not used (below) |
| `encoding_rs` | 636,408,947 | 152,459,449 | 1,535 | 0.8.42 | not used (below) |
| `lru` | 438,909,615 | 129,052,675 | 1,576 | 0.19.0 | not used (below) |
| `moka` | 160,107,661 | 49,181,866 | 761 | 0.12.16 | not used (below) |
| `quick_cache` | 33,732,801 | 10,111,112 | 129 | 0.7.0 | not used (niche) |

### The experiment

`docs/agents/bin-elf-crate-eval/` holds a small program (not in the
workspace; README there says how to run it). It takes
`ExerciseFiles/Advanced/override.so` (x86-64, little-endian), damages copies
in eleven ways Ghidra tolerates, and prints what `object` 0.40.0 (low-level
`read::elf` and the high-level `File`) and `goblin` 0.10.7 (strict and
permissive `ParseOptions`) do. Output of the run:

| Damage | What Ghidra does (`ElfHeader.java`) | `object` low-level | `object::File` | `goblin` strict | `goblin` permissive |
|---|---|---|---|---|---|
| intact | — | phdrs 7, dyn 28, shdrs 30, symtab 62, dynsym 17 | ok | ok (dyn 24) | ok |
| file cut in the middle of the section header table | warns, keeps the headers that fit plus one zero-padded partial header | `section_headers` **Err** (no sections at all) | **Err** | **Err** | ok but **0 sections** |
| `e_phentsize` = 57 | warns, ignores program headers, uses sections | phdrs **Err**, sections ok (same outcome) | **Err** | ok — **ignores the field** | ok — ignores it |
| section headers stripped (`e_shoff`=`e_shnum`=0) | finds `.dynsym`/`.dynstr`/relocs through the dynamic table + `PT_LOAD` | sections 0, **dynsym 0** (no such path) | ok, dynsyms 0 | ok, **dynsyms 17** | ok, dynsyms 17 |
| `EI_DATA` = 0 | warns, assumes little-endian | **Err** (header rejected) | **Err** | **Err** | **Err** |
| `.symtab` `sh_offset` outside the file | warns, skips that table only | symtab **Err**, rest ok | **Err** | **Err** | ok, syms 0 |
| `e_shnum` larger than the file holds | warns, truncates the count | `section_headers` **Err** | **Err** | **Err** | ok but **0 sections** |
| `e_phoff` outside the file | warns, ignores program headers | phdrs **Err**, sections ok | **Err** | **Err** | **Err** even permissive |
| `PT_DYNAMIC` `p_offset` bogus, `p_vaddr` right | locates the table by `p_vaddr` through `PT_LOAD` — unaffected | dyn **Err** | ok (does not need it) | **Err** | ok but **dynamic dropped** (dynsyms 0, no libraries) |
| `.rela.dyn` `sh_size` past the end | warns, truncates the relocation count | not checked until read | ok | **Err** | ok |
| `.dynsym` `sh_entsize` = 8 | warns, skips the table ("unsupported sh_entsize") | **ignores the field**, dynsym 17 | ok | ok — ignores it | ok — ignores it |
| `e_shstrndx` out of range | sections kept, named `SECTION<n>` | `sections()` **Err** | **Err** | ok | ok |

No panics were seen from either crate on these inputs.

### What this means

**`object`** — the low-level API is a set of independent accessors over
plain-old-data structs, so partial recovery is possible by calling them
separately, but:

1. Each accessor is all-or-nothing where Ghidra clamps. A section header
   table that is cut off or over-counted yields *no* sections; Ghidra keeps
   what fits, zero-pads the last partial entry (it reads headers through
   `UnlimitedByteProviderWrapper`) and reports two specific warnings. An
   out-of-range `e_shstrndx` loses the whole section table.
2. It rejects what Ghidra tolerates outright: invalid `EI_DATA`.
3. It has no path from the dynamic table to the dynamic symbol table when
   section headers are missing (`DT_SYMTAB` + `DT_HASH`/`DT_GNU_HASH` to size
   it, addresses mapped through `PT_LOAD`). This is the rule the spec calls
   out as "what makes stripped files work".
4. It locates the dynamic table by `p_offset`; Ghidra deliberately uses
   `p_vaddr` relative to the containing `PT_LOAD` ("p_offset may not refer to
   the start of the DYNAMIC table").
5. Ghidra-specific rules it does not have: the big-endian-ident /
   little-endian-headers switch, the prelink trailer, the "segments add up
   to the file" offset rewrite, entry-size validation for symbol and
   relocation tables, Android `APS2` decoding.
6. Its `ReadRef` input must hand out `&'a [u8]`; for a file-backed
   `ByteProvider` that means an adapter that keeps every buffer alive
   (`object::ReadCache` does exactly that, without a bound).

   What it *does* have that could be borrowed: the struct layouts
   (`FileHeader32/64`, `Sym32/64`, `Rela64`, …), RELR and MIPS-64 `r_info`
   handling, GNU version tables, note iteration, and — new in 0.40 — typed
   newtypes with name tables (a `name()` method on its `elf` value types). Using the layouts
   would replace roughly ten short `read_u32()` sequences here, at the price
   of zero-padding into a scratch buffer first (rule 1) and of making
   `object` a product dependency generic over class and endianness, which
   the spec's "one struct per concept with 64-bit fields" then converts
   away. Its name tables are not Ghidra's (which values are named, the
   descriptions, the value kinds, the processor extensions' tables), and
   those are generated from Ghidra's source here. So nothing in `object`
   removes a meaningful amount of code from `bk-elf`, and the behaviour that
   is the point of this crate — the tolerance rules — would all still be
   written by hand around it.

**`goblin`** — it *does* resolve stripped files through the dynamic table
(its own rule: the larger of the hash-table count and the highest relocation
symbol index — not Ghidra's), and 0.10 has a permissive mode. But:

1. It parses eagerly from one `&[u8]` into `Vec`s; there is no lazy or
   provider-backed mode.
2. Strict mode aborts the whole parse on any bad table. Permissive mode
   replaces a bad table with an *empty* one and logs through the global
   `log` crate — there is no diagnostics list to return, and "empty" is not
   Ghidra's "truncate and keep".
3. Even in permissive mode a bad `e_phoff` or an invalid `EI_DATA` is fatal.
4. It ignores `e_phentsize`, `e_shentsize` and `sh_entsize` entirely, has no
   extended numbering (`e_shnum` = 0, `PN_XNUM`), keeps only the *last*
   `SHT_SYMTAB`, has no `SHT_SYMTAB_SHNDX`, no RELR, no `APS2`, no prelink.
5. A bogus `PT_DYNAMIC` offset loses the dynamic table (and with it dynamic
   symbols and libraries) where Ghidra is unaffected.

Building on either would mean re-validating every table before handing it
to the crate, to reproduce Ghidra's clamping, and then re-deriving the
warnings — more code than parsing 16–64 byte structures directly, with two
sources of truth for the same bytes.

### Smaller pieces

- **LEB128 — own code (≈40 lines), `leb128` not used.** Two concrete
  conflicts with Ghidra, verified by reading `leb128` 0.2.7's `read::signed`
  / `read::unsigned`: (a) on overflow it keeps consuming continuation bytes,
  so the cursor ends somewhere else than Ghidra's — and the ported
  `LEB128Test.testTooLargeValueBinaryReaderStreamPosition` asserts that
  position; (b) its signed reader rejects a ten-byte value unless the tenth
  byte is 0x00 or 0x7f, while Ghidra accepts any tenth byte. It also needs
  an `io::Read` adapter per call.
- **Endian-aware integers — the standard library** (`from_le_bytes` /
  `from_be_bytes`); `byteorder`/`zerocopy` would add nothing.
- **String decoding — the standard library** (`String::from_utf8_lossy`,
  `char::decode_utf16`, `char::from_u32`). `encoding_rs` was considered and
  does not fit the reader's rules: it implements the WHATWG Encoding
  Standard, which has no UTF-32 and maps the "ASCII" label to windows-1252,
  where Java's `US_ASCII` turns bytes above 0x7f into U+FFFD (Ghidra's
  behaviour, covered by tests here). **This is from the standard the crate
  implements, not from running it** — I did not build against it. It *is*
  the right crate when Ghidra's wider list of Java charsets is needed for
  string data types (M4+); add it then.
- **zlib — `flate2`** (workspace), used.
- **File block cache — own code (≈40 lines).** `lru` (the standard choice)
  needs `&mut` for `get`, hence one exclusive lock around every read, which
  is what the spec's "many threads can read one provider without locking"
  rules out; `moka` is concurrent but brings a large dependency tree for a
  64-slot cache; `quick_cache` is niche. **Neither was built or benchmarked
  here**: the statements about `lru` and `moka` are from their documented
  APIs as I know them, and the decision is on structure, not measured
  speed. If the next agent wants the standard crate regardless, `lru` behind
  a `Mutex` is a drop-in for `FileProvider`'s slots, at the cost of that lock.
- **Unicode general category — `unicode-properties`** (used), for
  `SymbolUtilities.isInvalidCodePoint`.

## 4. Remaining, in the order I would do it

1. **Merge `master`** into the branch (stricter lints, new licence; the
   coordinator asked for this first) and get `bk-bin` clippy-clean again
   under the new configuration.
2. **`parse/symbols.rs`** — `parseSymbolTables`, `parseDynamicSymbolTable`,
   `getExtendedSymbolSectionIndexTable`, the GNU-hash/XHASH/`DT_HASH` symbol
   count (§5 has the rules).
3. **`parse/relocs.rs`** — `parseRelocationTables`,
   `parseDynamicRelocTable`, `parseJMPRelocTable`,
   `parseSectionBasedRelocationTable`, table construction (§5).
4. **`ElfFile<P>`** (`file.rs`) with the lazy API; remove `parse_tables` (§5).
5. **Fixture builder** (`bk_elf::builder`, spec §6): header, sections,
   segments, symbols, dynamic, relocations; 32/64, both byte orders. Needed
   by every test below.
6. **Tolerance tests**: one damaged fixture and the expected diagnostic per
   rule — the full list of rules is in §6 of this file. Acceptance item 3.
7. **Relocation decoder tests**: REL/RELA both classes and byte orders,
   MIPS-64; RELR and Android `APS2` against hand-computed vectors (including
   truncation, group-size errors, the REL-with-addend case that empties the
   table, the count cap).
8. **GNU versioning** (`version.rs`): `.gnu.version` (u16 per dynamic
   symbol), `.gnu.version_d` (`GnuVerdef` 20 bytes + `GnuVerdaux` 8),
   `.gnu.version_r` (`GnuVerneed` 16 + `GnuVernaux` 16), lazy, following
   `vd_next`/`vn_next`/`vda_next`/`vna_next` with a visited/offset bound.
   Ghidra's `ElfHeader.parseGNU_d/_r` are empty stubs; the structures are
   only used for markup.
9. **Notes and info** (`note/`): `ElfNote.read` (name ≤ 1024, desc ≤ 1 MiB,
   name padded to 4, desc **not** padded by `read` — `markupPtNote` aligns
   afterwards), `NoteAbiTag`, `NoteGnuBuildId`, `NoteGnuProperty`,
   `GnuDebugLink`, `GnuDebugAltLink`, `ElfComment`, `GnuBuildAttributes`.
   Ghidra reads these from *program memory*, so write them as functions over
   a `BinaryReader` and add `ElfFile` conveniences over section bytes.
10. **Section contents**: `section_data` (raw; empty for `SHT_NOBITS`),
    decompression through `compress::inflate`, `segment_data`.
11. **Differential tests** against `object` on builder output and on the
    real files: symbols, dynamic entries, relocations (extend
    `tests/real_files.rs`).
12. **Stripped-file test**: take section headers away from a builder file
    and check that dynamic symbols, strings and relocations are still found.
13. **Property tests** (`elf_parse` never panics on arbitrary and on mutated
    builder output; allocation bounded) and the **fuzz target**
    `fuzz/fuzz_targets/elf_parse.rs` (`libfuzzer-sys` 0.4.13 is old enough);
    run 60 s (`cargo +nightly fuzz run elf_parse -- -max_total_time=60`; a
    nightly toolchain and `cargo-fuzz` 0.13.2 are installed). `fuzz/Cargo.toml`
    will be created by several tracks at once — expect a merge conflict.
14. **Benchmark**: symbol table of a million-symbol builder file; numbers in
    `docs/PERF.md`.
15. **Clippy and the gate**: fix or allow `doc_markdown` on the generated
    tables (a module-level `#[expect]` with the reason "descriptions are
    Ghidra's text" on `mod generated`, `mod machines` and the machine
    modules is the least work), remove the handover `#[allow]` in
    `reloc/mod.rs`, run `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`.
16. **Docs**: turn the *(planned)* entries in spec §8 into facts or delete
    them; fill spec §9; replace this file with the final report (RULES.md).

Not started and possibly out of scope — decide when there: the data-type
layout of Android tables (`AndroidElfRelocationTableDataType` records the
offset and length of every LEB128 field for markup; the decoder here yields
relocations only) and of RELR tables (`ElfRelrRelocationTableDataType`).
M4 needs them for markup; a group/word iterator that reports offsets would
do.

## 5. In flight — the design that was being implemented

### `ElfFile<P>`

```rust
pub struct ElfFile<P> { provider: UnlimitedProvider<P>, tables: ElfTables }
impl<P: ByteProvider> ElfFile<P> { pub fn parse(provider: P) -> Result<Self, ElfError> }
impl<P> Deref for ElfFile<P> { type Target = ElfTables; }
```

- Generic over the provider so that both `ElfFile<&MemoryProvider<&[u8]>>`
  (borrowed, for tests and embedded files) and
  `ElfFile<Arc<dyn ByteProvider>>` (owned, no lifetime — what the loader and
  the Python bindings want, ADR-014) work; references, `Box` and `Arc` of
  providers are providers. Rejected: `ElfFile<'p>` holding
  `&'p dyn ByteProvider` (a lifetime in a type plugins hold) and an
  `Arc<dyn ByteProvider>`-only design (cannot borrow a slice).
- All heavy code stays non-generic: `parse::parse(&dyn, &dyn)` builds
  `ElfTables`; `ElfFile<P>`'s methods only make a `BinaryReader` and call
  non-generic functions. Two readers are needed, as in Ghidra: the
  **zero-padding** one (`UnlimitedProvider`, header byte order) for headers,
  symbols, strings and hash tables, and the **raw** one
  (`provider.inner()`) for relocation tables, where Ghidra enforces the end
  of the file.
- Lazy methods planned on `ElfFile`: `section_name(&SectionHeader) -> Cow<str>`,
  `section_by_name`, `symbols(&SymbolTable) -> SymbolIter`,
  `symbol_name(&SymbolTable, &Symbol) -> Result<Option<Cow<str>>, Diagnostic>`,
  `extended_section_index`, `string(&StringTable, offset)`,
  `dynamic_library_names()` (iterator; `UNK_LIB_NAME_<i>` fallback),
  `relocations(&RelocationTable) -> RelocationIter`, `section_data`,
  `decompress_section`, the version and note readers.
- Why names are lazy: see spec §8 (quadratic blow-up otherwise). Why
  `Deref`: every non-I/O accessor and lookup of `ElfTables` is then on
  `ElfFile` without wrappers.

### Symbol name rule (not yet implemented; from `ElfSymbol` + `ElfSymbolTable`)

`st_name` = 0 **and** type `STT_SECTION` **and** `st_shndx` < `SHN_LORESERVE`
and < section count → the section's name. Otherwise, if the table has a
string table → `StringTable::read(st_name)` (failure = Ghidra logs and the
name is null). Otherwise null. A blank name displays as `<no name>`. Note
that a non-section symbol with `st_name` 0 reads the string at offset 0
(normally empty), it is not special-cased.

### `parse/symbols.rs` — rules (`ElfHeader.parseSymbolTables`)

For each `SHT_SYMTAB` / `SHT_DYNSYM` section, in order; each check that
fails logs and **skips that table only**:

1. `is_invalid_offset()` → "Symbol table section header '<name>' has invalid offset value: 0x…".
2. `sh_size` ≤ 0 (signed) → "… has invalid sh_size value (table size): 0x…".
3. `!SymbolTable::is_valid_entry_size(class, sh_entsize)` → "… has unsupported sh_entsize value (table entry size): 0x…".
4. `sh_size % sh_entsize != 0` → "… has sh_size which is not a multiple of sh_entsize value" (warning only, continues).
5. count = `constrain_count(size / entsize, offset, entsize, hard_limit(entsize), "Symbol")`; truncated = `has_fragment(...) || count != expected`.
6. String table: `sh_link` in range → `string_table_index_for_section(link)` (matched by **file offset**, whatever the linked section's type). None → "String table not found for symbol table: <name>" (table is still created).
7. `is_dynamic` = the section's *name* is `.dynsym` (not its type).
8. `SHT_SYMTAB_SHNDX`: only if the file has any; find the SHNDX section whose `sh_link` (1 ≤ link < count) is this symbol-table section; size ≤ 0 or > `i32::MAX` → "Symbol table section index header '<name>' has invalid size: 0x…"; invalid offset → "… has invalid offset value: 0x…"; count = `constrain_count(size / 4, offset, 4, symbol_count, "Symbol section index")` plus `has_fragment` for its log. The plan is to store offset and count (`SectionIndexTable`) and read indexes lazily through the zero-padding reader; index ≥ count → 0.
9. If the table's address equals the prelink-adjusted `DT_SYMTAB` → it is the dynamic symbol table.

If none matched and the dynamic table has `DT_SYMTAB` (else, when there is a
dynamic table: "ELF does not contain a dynamic symbol table (DT_SYMTAB)") →
`parseDynamicSymbolTable`, checks in this order:

1. hash type = first present of `DT_HASH`, `DT_GNU_HASH`, `DT_GNU_XHASH`; if
   `DT_SYMTAB`, `DT_SYMENT` or a hash is missing → "Failed to parse DT_SYMTAB, missing dynamic dependency" **only if** a dynamic string table exists; stop.
2. `DT_SYMTAB` = 0 → "Failed to process DT_SYMTAB with 0 value".
3. No `PT_LOAD` contains the (adjusted) address → "Failed to locate DT_SYMTAB in memory at 0x…".
4. offset = `offset_of(addr)`; ≤ 0, > hard limit or ≥ file length → "Dynamic symbol table has invalid DT_SYMTAB value (table offset): 0x…".
5. Hash address not in a `PT_LOAD` → "Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at 0x…".
6. Invalid `DT_SYMENT` → "Dynamic symbol table has unsupported DT_SYMENT value (table entry size): 0x…".
7. Count: `DT_HASH` → `nchain` (u32 at hash + 4). `DT_GNU_XHASH` → u32 at +8 (`symndx`) + u32 at +0 (`ngnusyms`). `DT_GNU_HASH` → walk below.
8. Count ≤ 0 → "Unable to determine symbol count for dynamic symbol table at address 0x…".
9. constrain / fragment as above ("Symbol").
10. No dynamic string table → "String table not found for dynamic symbol table at address 0x…" (table still created). No SHNDX table for a dynamic-only table.

GNU hash walk (`deriveGnuHashDynamicSymbolCount`), all in signed 64-bit:
`nbuckets`, `symbase`, `bloomsize` = u32 at +0, +4, +8; buckets start at
`hash + 16 + wordsize·bloomsize`; `max_offset` = end of the *section* whose
file range contains `[hash, hash+12)` (if there are sections), else of the
`PT_LOAD` containing the file offset, else fail with "Failed to idenitify
loaded GNU Hash table" [sic]. For each bucket: offset outside
`[hash, max_offset]` → "Error occured while inspecting GNU Hash table" [sic],
count 0; value read as **signed** i32, track the maximum. Then
`chain = buckets_end + 4·(max − symbase)`; `max += 1`; loop: bounds check as
above; read i32; low bit set → stop; else `max += 1`, next. Result `max`.
**Add** a stop at the end of the file (same message): past the end the
zero-padding reader returns 0 forever and `max_offset` is file-controlled.

### `parse/relocs.rs` — rules (`ElfHeader.parseRelocationTables`)

Order (it matters; later duplicates are skipped by file offset):
`DT_REL`(ent `DT_RELENT`, size `DT_RELSZ`), `DT_RELA`(`DT_RELAENT`,
`DT_RELASZ`), then if `DT_PLTREL` exists `DT_JMPREL`(no ent, `DT_PLTRELSZ`,
addend = `DT_PLTREL` == 7), `DT_ANDROID_REL`(no ent, `DT_ANDROID_RELSZ`),
`DT_ANDROID_RELA`(no ent, `DT_ANDROID_RELASZ`), `DT_RELR`(`DT_RELRENT`,
`DT_RELRSZ`), `DT_ANDROID_RELR`(`DT_ANDROID_RELRENT`, `DT_ANDROID_RELRSZ`),
then `DT_JMPREL` again with ent `DT_RELAENT`/`DT_RELENT`, then every section.

Dynamic table entry → table: address missing → skip silently. Address
inside an **allocated section** → treat that section as a section-based
table and stop (if its type is not a relocation type, nothing happens).
Else no `PT_LOAD` → "Failed to locate <DT_NAME> in memory at 0x…"; load
header with invalid offset → skip silently; offset already parsed → skip;
offset < 0, > hard limit or ≥ length → "Invalid derived dynamic relocation
table file offset: 0x…; <DT_NAME>(0x%08x): 0x<addr>" (Ghidra prints the tag's
`toString`, `NAME(0x%08x)`); ent or size entry missing → skip silently;
size ≤ 0 → "Dynamic relocation table has invalid <DT_NAME>(0x…) (table
size): 0x…"; symbol table = the dynamic symbol table; construction error →
"Failed to process relocation table: <message>".

Section → table (types `SHT_REL`, `SHT_RELA`, `SHT_RELR`, `SHT_ANDROID_REL`,
`SHT_ANDROID_RELA`, `SHT_ANDROID_RELR`): offset already parsed → skip;
invalid offset → skip silently; `sh_size` ≤ 0 → "Relocation table section
header '<name>' has invalid sh_size value (table size): 0x…"; `sh_info` ≠ 0
must be a valid section index else "Failed to process relocation table
<name>: invalid linked section index <n>"; symbol-table section = `.dynsym`
*by name* when `sh_link` = 0, else section `sh_link`, which must be
`SHT_DYNSYM` or `SHT_SYMTAB` ("… unexpected section type for section index
<n>"); symbol table matched by file offset (may be absent); entry size
`sh_entsize`.

Construction (`ElfRelocationTable`): entry size = the standard size when the
format is default and the given size ≤ 0; if the format is not Android and
the size ≠ supported (REL 8/16, RELA 12/24, RELR 4/8) → error "Relocation
table has unsupported entry size: 0x…". Then per format — this is what
`RelocationTable::units` is for:
- **default**: expected = length / entsize; count = `constrain_count(..., "Relocation Table")`, truncated = fragment || count ≠ expected; then only entries wholly inside the file are read: if count > complete entries → truncated + "Truncated ELF Relocation table due to unexpected EOF". `units` = readable entries.
- **RELR**: words = ⌈length / entsize⌉; if more than fit in the file → truncated + "Truncated ELF RELR Relocation table due to unexpected EOF". `units` = words.
- **Android**: `reloc::scan_android` (already written) returns count and truncation and pushes Ghidra's diagnostics; its `Err(message)` is Ghidra's `IOException` ("Android relocation table not found at file offset N" / "Unsupported Android relocation table format"), which in Ghidra escapes `parse()` — report it as "Failed to process relocation table…: <message>" and skip the table. `units` = count.

Relocation layout: `RelocationLayout::for_file(class, extension.uses_mips64_relocations(class), header.data_endian())`.

### Things tried or considered that did not work

- **Storing section names eagerly** (as Ghidra does): unbounded on hostile
  input, see spec §8. Names are lazy.
- **`BinaryReader` generic over the provider type**: unnecessary — the
  reader caches `provider.as_slice()` and takes a slice fast path, which
  measured 0.45 ns per `read_u32` through `&dyn ByteProvider`.
- **A source-filter mistake worth knowing about**: reading Ghidra's Java
  with comment lines filtered out hid one line of code that *starts* with a
  comment — `/*long unused_reserved = */ reader.readNextUnsignedInt();` in
  `ElfCompressedSectionHeader.read64`. `Elf64_Chdr` does have the reserved
  word; `compress.rs` reads it. It is the only such line in the ELF sources.
- **`object` 0.40 API change**: accessors return newtypes
  (`e_type() -> FileType`, `sh_flags() -> SectionFlags`, `d_tag() -> DynamicTag`);
  use `.0`. `tests/real_files.rs` is written for 0.40.
- **Version pins**: `cargo` resolved `flate2` to 1.1.11 (six days old) and
  would resolve `unicode-properties` to 0.1.5 (twelve days old); the lock
  file holds `flate2` at 1.1.10 (`cargo update -p flate2 --precise 1.1.10`)
  and the manifest pins `unicode-properties = "=0.1.4"`. After merging
  `master`, check the lock file again.

## 6. What Ghidra's source says that the spec does not

### `BinaryReader` and providers

- There is no `readTerminatedString`/`readFixedLenString` in this Ghidra
  (the spec names them); the forms are `readString(index, charset, charLen)`
  (terminated) and `readString(index, charCount, charset, charLen)` (fixed).
- Terminated: stops at the first all-zero *unit* at a unit boundary; nothing
  is trimmed ("this method no longer trims"); a tab does not terminate.
  Errors are all `EOFException`: nothing readable at the index, data ends
  before the terminator, or the buffer limit (2³¹ − 1025 bytes).
- Fixed-length: reads the whole field (which must be in range), strips
  trailing all-zero units only, keeps embedded NULs and whitespace.
- LEB128 is not in `BinaryReader`; it is `LEB128.read(InputStream, signed)`:
  error when an 11th byte is read (`shift == 70`) or, unsigned only, when
  the 10th byte is > 1. A signed 10-byte value is accepted whatever the
  10th byte holds.
- `readNextUnsignedIntExact` rejects values above `Integer.MAX_VALUE`; array
  reads reject counts above 2³¹ − 1025.
- `FileByteProvider`: 64 KiB buffers, 4 pinned + soft references, all reads
  under one monitor; it verifies the file size by reading the last byte.
- `RangeMappedByteProvider.addRange` has the sparse-merge bug described in
  spec §8.

### `ElfHeader` — the tolerance rules, complete list

Constructor (fatal = `ElfException`):

1. First four bytes ≠ `\x7fELF` (or unreadable) → **fatal** "Not a valid ELF executable."
2. Length < 34 → **fatal** "Not enough bytes to be a valid ELF executable."
3. `EI_DATA` not 1 or 2 → warn "Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x…)".
4. `EI_DATA` = 2 but byte 16 ≠ 0 and byte 20 = 1 → headers are read little-endian (no message). `isLittleEndian()` still reports the ident byte; section *contents* (compression headers) use the ident byte, header tables and relocation tables use the header order.
5. All later header reads go through the zero-padding wrapper: a truncated header gives zero fields, not an error.
6. `EI_CLASS` not 1 or 2 → **fatal**.
7. `e_phoff` / `e_shoff` negative, > 0x7FFF_FFFF_FFFF or ≥ length → warn "Invalid ELF e_phoff value (program header table offset): 0x…" / "… e_shoff value (section header table offset) …", treated as 0.
8. `e_phoff` = 0 → no program headers. `e_phnum` = 0xffff → count from section 0's `sh_info`; section 0 missing, not wholly in the file or not `SHT_NULL` → warn "Failed to load Section-0 required for extended program header count", 0; negative → "Invalid extended program header count: <n>".
9. `e_shnum` ≥ 0xff00 → warn "Invalid ELF e_shnum value (section header count): 0x…", then treated as 0 — which triggers rule 10.
10. `e_shoff` = 0 → no sections. `e_shnum` = 0 → count from section 0's `sh_size` (same failure message with "section header count"); negative or > `i32::MAX` → "Invalid extended section header count: <n>".
11. `e_phentsize` ≠ 32/56 with program headers present: if there are sections → warn "Unsupported e_phentsize value (program header size): <n> (expected <m>), using section headers only"; else **fatal**.
12. Program header count > what fits (one partial entry allowed) or > `i32::MAX / size` → warn "Program Header count <n> exceeds file capacity|hard limit <m>; truncating"; a partial last entry → warn "Program Header has partial entry"; either sets `hasTruncatedProgramHeaders`.
13. Rules 11–12 for sections (`e_shentsize` 40/64, "using program headers only", "Section Header"). The fallback test uses the *already adjusted* other count, so a file with both sizes wrong is fatal on the section check.
14. `e_shstrndx`: 0 if no sections; 0xffff → section 0's `sh_link` (0 if section 0 unusable or the value is negative).

`parse()`:

15. Prelink: last 8 bytes = 32-bit base + ASCII that trims to `PRE` → every address accessor adds the base (`e_entry` only if non-zero).
16. Program headers: if the sum of all `p_filesz` equals the file length, `p_offset`s are rewritten to be consecutive from 0 ("malformed ELF file with only program header sections" hack, no message).
17. A program or section header offset is *invalid* (not an error, a flag) when ≥ 0x7FFF_FFFF_FFFF, ≥ length, or 0xFFFFFFFF in a 32-bit file.
18. Section names: only if `sh_name` ≥ 0 as an int, 0 < `e_shstrndx` < count, the string-table section's offset is valid and `offset + sh_name` < length; read as UTF-8 to the NUL (not bounded by the string table's size, not trimmed); empty or unreadable → `SECTION<index>`.
19. Compression header: used only if the section is not `SHF_ALLOC`, lies in the file, and the type is zlib (1); otherwise the section is silently (a `Msg.warn`) treated as uncompressed.
20. Dynamic table: exactly one `PT_DYNAMIC` → by `p_vaddr` through the containing `PT_LOAD` (or its own `p_offset` if none); `p_vaddr` = 0 or `p_filesz` = 0 → warn "ELF Dynamic table appears to have been stripped from binary"; more than one → warn "Multiple ELF Dynamic table program headers found" and fall through; otherwise exactly one `SHT_DYNAMIC` section inside a `PT_LOAD`. Entries are read to the first `DT_NULL`, not limited by `p_filesz`; `d_tag` is truncated to 32 bits.
21. String tables: every `SHT_STRTAB`; dynamic one by `DT_STRTAB` (missing → "ELF does not contain a dynamic string table (DT_STRTAB)"; no `DT_STRSZ` → "Failed to parse DT_STRTAB, missing dynamic dependency"; address 0 → "ELF Dynamic String Table of size <n> appears to have been stripped from binary"; not in a `PT_LOAD` → "Failed to locate DT_STRTAB in memory at 0x…").
22. Strings: offset ≥ table length → "Failed to read Elf String at offset 0x… within String Table at offset 0x…", name null; result is `trim()`med (Java: characters ≤ U+0020).
23. `DT_NEEDED` names that cannot be read → `UNK_LIB_NAME_<i>`.
24. Symbol and relocation tables: §5 above.

Places where Ghidra's parse **throws** rather than tolerates (an unchecked
exception or `IOException` leaves `parse()` and the import fails). basilisk
should record a diagnostic and skip the table instead — each is a deliberate
difference to document:

- `ElfProgramHeader.getOffset(long)` on a segment with `p_filesz` = 0, or on
  dsPIC30 data segments (`UnsupportedOperationException`), or with a zero
  adjusted load size (`ArithmeticException`). Reached from dynamic string,
  symbol, hash and relocation table location. *(done: `offset_of` returns `Err`)*
- A dynamic table, hash table or section-index read at an offset ≥ 2⁶³
  (`IOException` from the wrapper). *(dynamic table: done)*
- Android table missing or not `APS2` (`IOException`).
- `getSection(String)` with two sections of that name (`RuntimeException`).

Other surprises:

- `ElfSymbol.getBind()` is wrong for bindings ≥ 8 (signed shift).
- The signed 64-bit comparisons everywhere: `size <= 0` also rejects sizes
  ≥ 2⁶³, and range lookups (`getProgramLoadHeaderContaining`, …) use signed
  order. `tables.rs` reproduces this with `as i64`.
- `ElfSectionHeaderType` has no named type for `SHT_RELR` (19) or the
  `SHT_LLVM_*` values although `ElfSectionHeaderConstants` defines them, so
  their names are `SHT_0x00000013` etc. Same for `PT_SUNWBSS`/`PT_SUNWSTACK`.
- HCS12's extension names its types inconsistently (`PT_HCS12X_ARCHEXT`,
  `SHT_AHCS12_ATTRIBUTES` [sic]); Hexagon reuses ARM's names
  (`PT_ARM_EXIDX`, `SHT_ARM_*`). The generated tables keep Ghidra's text.
- x86-64, SPARC, LoongArch and others have **no** ELF extension in Ghidra;
  only the 13 listed in §1 exist.
- No extension overrides the section/segment permission predicates; the only
  format-level hooks are `getRelocationClass` (MIPS-64) and the adjusted
  sizes (PIC30).
- The spec says a fatal error "is reserved for files that are not ELF at
  all"; Ghidra is also fatal for an unsupported class and for a wrong
  entry size with no other table to fall back on (rules 6, 11, 13). The
  code follows Ghidra.

## 7. For the PE / Mach-O and loader tracks — the `bk-bin` API

- Take input as `&dyn ByteProvider` (or be generic over `P: ByteProvider`
  when you need to own it). `MemoryProvider::new(vec_or_slice_or_arc)` for
  bytes in memory, `FileProvider::open(path)` for files,
  `SubProvider::new(&parent, offset, len)` for an embedded file,
  `UnlimitedProvider` when a format's headers must tolerate truncation.
- `BinaryReader::new(&provider, Endian::Little)` or
  `BinaryReader::from_slice(bytes, endian)`. It is `Copy`: `reader.at(offset)`
  gives an independent cursor, `reader.with_endian(e)` another byte order.
- `read_x()` advances, `read_x_at(i)` does not, `peek_x()` reads at the
  cursor without advancing. A failed read never moves the cursor (LEB128
  excepted). Errors are `BinError`; `is_eof()` tells "ran out of data".
- Do not allocate per table entry: `read_bytes_at(offset, len)` borrows from
  memory-backed providers, and `read_array_at::<N>()` copies N bytes onto
  the stack on either path.
- Bound every count from a file before using it; `read_*_array` checks the
  range against the provider first, but `UnlimitedProvider` accepts any
  range, so lengths read through it must be checked against `len()`.
- UTF-16 strings in PE: `read_utf16_at` / `read_utf16_fixed_at` use the
  reader's byte order; `Charset::Utf16Le` etc. are explicit.

## 8. Commits

```
git log --oneline master..HEAD
```

is reproduced in the final message of the run; the last commit is this file.
