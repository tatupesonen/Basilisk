# Track `bin-elf` — status report

Final report, 2026-11-12, by the second agent on the track (Opus 5.5), which
continued from the first agent's checkpoint. **The track is done** against
`docs/features/bin-elf.md` with one stated gap (§7). Worktree
`basilisk-wt/bin-elf`, branch `bin-elf`. `master` was merged twice, as
authorised: at the start, and again for the shared fuzz crate.

Tests that use Ghidra's files need, from a worktree,
`export BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra`; otherwise they skip
with a printed reason. Run with the variable unset (skips), set to
`/Users/tatu/slop/ghidra`, and set to `/Users/tatu/slop/basilisk/../ghidra`
(both find and check all 18 files).

## 1. Built

### `bk-bin` — finished at the checkpoint

Providers (`MemoryProvider`, `FileProvider` with a 64 × 64 KiB block cache,
`SubProvider`, `UnlimitedProvider`, `RangeMappedProvider`, `EmptyProvider`,
`FillProvider`), the `Copy` `BinaryReader` (all integer, array and string
forms) and LEB128. This session changed only three lint findings
(`ok_or_else`, a named `map_err` binding) and the test files' lint header.

### `bk-elf`

| Module | Content |
|---|---|
| `file` — `ElfFile<P>` | `ElfFile::parse(provider) -> Result<ElfFile<P>, ElfError>`; dereferences to `ElfTables`. On demand: `section_name`, `section_by_name`, `string`, `dynamic_library_names`, `symbols` / `symbol`, `symbol_name` (`Result<Option<Cow<str>>, Diagnostic>`), `formatted_symbol_name`, `extended_section_index`, `relocation_layout`, `relocations`, `section_data`, `section_provider` (Ghidra's zero-filled view), `decompress_section`, `segment_data`, `symbol_versions`, `version_definitions`, `version_needs`, `reader` / `raw_reader`. |
| `file_notes` | `section_notes`, `segment_notes`, `program_notes`, `abi_tag`, `build_id`, `gnu_property`, `debug_link`, `debug_alt_link`, `comment`. |
| `tables` — `ElfTables` | Everything parsed eagerly, Ghidra's lookups (signed comparisons), prelink, image base, type names. |
| `parse/{mod,dynamic,symbols,relocs}` | `ElfHeader.parse()` in Ghidra's order: program headers, section headers, dynamic table, string tables; **symbol tables** (sections; `DT_SYMTAB` sized by `DT_HASH`, the `DT_GNU_HASH` walk or `DT_GNU_XHASH`; `SHT_SYMTAB_SHNDX`); **relocation tables** (`DT_REL`, `DT_RELA`, `DT_JMPREL` twice, `DT_ANDROID_REL(A)`, `DT_RELR`, `DT_ANDROID_RELR`, then sections). Ghidra's messages throughout. |
| `reloc/{table,rel,relr,android}` | Lazy decoders: `REL`/`RELA` (32/64-bit, MIPS-64 layout), `RELR`, Android `APS2`, plus the parse-time scan that counts `APS2` relocations and reports Ghidra's diagnostics. |
| `version` | `.gnu.version`, `.gnu.version_d`, `.gnu.version_r`, with bounded chains. |
| `note/{mod,gnu,info}` | `ElfNote`, `NoteIter`, `NoteAbiTag`, `NoteGnuBuildId`, `NoteGnuProperty`, `GnuDebugLink`, `GnuDebugAltLink`, `ElfComment`. |
| `header`, `program_header`, `section_header`, `strtab`, `symbol`, `symbol_name`, `dynamic`, `compress`, `limits`, `diag`, `error`, `constants`, `machine` | From the checkpoint: header tolerance, extended numbering, compression headers, and the constants and processor tables generated from Ghidra. |

- `parse_tables`, the checkpoint's temporary entry point, is gone.
- The generator (`gen/gen_tables.py`) now puts identifiers in Ghidra's
  descriptions into code spans, which fixed the 89 `doc_markdown` warnings
  where the text is produced. `constants/generated.rs` (999 lines) starts
  with `// bk:allow-long-file:`. To regenerate:
  `python3 crates/bk-elf/gen/gen_tables.py <ghidra>`, then `cargo fmt`.
- **Fixtures**: `crates/bk-elf/tests/fixtures/` holds 17 ELF files (116 KB),
  made by Apple clang 17.0.0 and rust-lld 22.1.6, with `generate.sh` and a
  provenance `README.md`. They cover x86-64, i686, AArch64/Android,
  ARMv7/Android, AArch64 BE and ARMv7 BE: `.o` files with `REL`/`RELA` and
  zlib-compressed debug sections, and `.so` files in plain, `RELR`, `APS2`,
  `APS2` + `ANDROID_RELR` and versioned forms.
- **Fixture builder**: `tests/common/builder.rs`, for 32/64-bit and both
  byte orders. It writes the header, sections, segments, symbols, the
  dynamic table and relocations, and has patch helpers for damaging output.
  Its output is checked against `object`.
- **Fuzz target**: `bk_elf_parse` (the spec's `elf_parse`) in the shared
  `fuzz/` crate. The body is `fuzz/fuzz_targets/bk_elf/mod.rs`, which the
  property tests and the regression replay also include.

## 2. Verification: what each part was checked against

Everything below was **run** in this session (macOS, Apple M1 Pro, Rust
1.97.1, Ghidra 42db038f3c).

| Part | Independent reference | Test |
|---|---|---|
| Header, program and section headers, dynamic table, section names, `DT_NEEDED` | `object` 0.40.0 on Ghidra's 18 ELF files, the 17 fixtures and builder output in all 4 encodings | `real_files.rs`, `builder.rs`, `common/oracle.rs` |
| Symbols of every `.symtab`/`.dynsym`: every field and the name | `object`, same files | same |
| `REL`/`RELA`: offset, info, symbol, type, addend | `object`, same files (32-bit `REL` and big-endian included) | same |
| `RELR` (`SHT_RELR`) | `object`'s `RelrIterator`; lld's unpacked twin links (x86-64, i686, AArch64 BE); hand-computed vectors for 32/64-bit and LE/BE | `real_files.rs`, `packed_relocations.rs`, `reloc_vectors.rs` |
| Android `APS2` (`RELA` and `REL`, LE and BE) and `SHT_ANDROID_RELR` | lld's unpacked twins, every relocation compared as (section, offset, type, symbol name, addend target); hand-computed vectors covering every error path | `packed_relocations.rs`, `reloc_vectors.rs` |
| MIPS-64 relocation layout | Hand-computed vector, LE and BE. No real MIPS file: Apple clang has no MIPS backend | `reloc_vectors.rs` |
| Stripped files: `DT_SYMTAB` with `DT_HASH`/`DT_GNU_HASH`, `DT_STRTAB`, dynamic relocations | The same lld file with its section headers intact (11 files: GNU hash, SysV hash, both, Android, BE) | `stripped.rs` |
| GNU versioning: versym, verdef, verneed | `object` on the fixtures; names checked by hand | `real_files.rs`, `notes_versions.rs` |
| `PT_NOTE` notes (build id) | `object`'s note iterator | `notes_versions.rs` |
| `.comment` | clang and lld strings | `notes_versions.rs` |
| `SHF_COMPRESSED` | clang `-gz=zlib` sections inflate to `ch_size`; builder sections compressed with `flate2` | `tolerance_header.rs` |
| Tolerance rules | Builder files damaged one rule at a time; expected texts taken from `ElfHeader.java` | `tolerance_header.rs`, `tolerance_tables.rs` |

**Checked only against my own builder and unit vectors** (no third party):
- ABI tag, GNU property, `.gnu_debuglink`, `.gnu_debugaltlink`;
- `SHT_SYMTAB_SHNDX` extended indexes and `DT_GNU_XHASH`;
- the GNU-hash walk failure;
- the prelink trailer and the "segments add up to the file" rewrite;
- extended numbering (`PN_XNUM`, `e_shnum` = 0, `SHN_XINDEX`).

Diagnostic texts were checked against Ghidra's source by reading it; Ghidra
itself was never run.

**Sensitivity check**: I broke the `RELR` bitmap base and the `APS2` offset
accumulation on purpose. All 7 twin comparisons failed, and the decoders
were then restored.

**Allocation bound**: `tests/alloc_bound.rs` measures peak heap with `dhat`
while parsing and reading everything except decompression. Inputs: the
fixtures, the builder sample, and 256 builder files with random damage. The
limit is 32 × input + 64 KiB. Decompression has its own bound, 1,040 × the
compressed size (zlib's maximum ratio). The measurement can over-estimate
(the peak is global to the process) but cannot under-estimate.

## 3. Tests

| Kind | `bk-bin` | `bk-elf` |
|---|---:|---:|
| Unit | 71 | 80 |
| Ghidra ports (`BinaryReaderTest` 53 + 1, provider tests 19, `LEB128Test` 5) | 78 | — (Ghidra has no ELF parser tests) |
| Differential against `object` (real files: 18 Ghidra + 17 fixtures; builder) | — | 3 + 1 |
| Packed relocations against unpacked twins | — | 7 |
| Hand-computed relocation vectors | — | 12 |
| Stripped files | — | 11 |
| Tolerance (one damaged fixture per rule) | — | 34 (16 header-level, 18 table-level) |
| Notes and versioning | — | 4 |
| Property tests (`proptest`) | 11 | 4 (512 cases each) |
| Allocation bound (`dhat`) | — | 1 |
| Fuzz regression replay | — | 1 (no inputs: nothing was found) |
| Doc tests | 2 | 1 |
| Benchmarks (`#[ignore]`) | 2 | 1 |

`BASILISK_GHIDRA_DIR=… CARGO_BUILD_JOBS=2 cargo test -p bk-bin -p bk-elf`:
all pass.

Ghidra tests ported and marked (by the first agent): `BinaryReaderTest` (53),
`ByteArrayProviderTest` (2), `FileByteProviderTest` (4),
`RangeMappedByteProviderTest` (12), `LEB128Test` (5). Left unmarked, as the
spec says: `MemoryByteProviderTest`, `LEB128DataTypeTest`.

### Ghidra's ELF loader tests, waiting for the program model (M4)

Ghidra has no test class under `ghidra.app.util.bin.format.elf`. ELF is
tested only by loading whole programs:

- **Processor emulator tests** built on
  `ghidra.test.processors.support.ProcessorEmulatorTestAdapter`
  (`*_O0_EmulatorTest`, `*_O3_EmulatorTest`, … in
  `docs/inventory/tests/processors-*.md`). Processors: AARCH64, ARM, Atmel,
  CR16, Hexagon, LoongArch, 68000, MIPS, MSP430, NDS32, PA-RISC, PIC,
  PowerPC, RISC-V, SPARC, SuperH4, TriCore, V850, x86 and Xtensa. They load
  ELF test binaries (not in the tree) through `ElfLoader`, so they need the
  loader, the relocation handlers and the emulator.
- **Version Tracking GUI tests** in `features-versiontracking.md`:
  `VTCombinedFunctionDataReferenceCorrelator_ELF_Test`,
  `VTDataReferenceCorrelator_ELF_Test` and
  `VTFunctionReferenceCorrelator_ELF_Test`. They need whole programs and the
  UI.
- `StringsAnalyzerTest` names a program `libopencoreplayer.so` but builds it
  with `ProgramBuilder`. It never loads ELF.

## 4. Fuzzing (run)

`bk_elf_parse`, seeded from `tests/fixtures/` plus the corpus of a first
37-second run (made under the old target name, no finding):

- **15 minutes**: `cargo +nightly fuzz run bk_elf_parse fuzz/corpus/bk_elf_parse crates/bk-elf/tests/fixtures -- -max_total_time=900 -rss_limit_mb=2048 -max_len=65536`,
  from 2026-11-12T17:27:27Z to 17:42:29Z. Result: `Done 5708054 runs in 901
  second(s)`, **no finding**; coverage 3,188, corpus 1,778, RSS 940 MB at
  the end, under the 2 GB limit.
- **Smoke run**: `scripts/fuzz-smoke.sh 60 bk_elf_parse` gave
  `Done 230508 runs in 61 second(s)`, then `fuzz: all targets ran without a
  finding`.
- `fuzz/regressions/bk_elf_parse/` is empty apart from `.gitkeep`. Its
  replay test (`tests/fuzz_regressions.rs`) runs in the gate.
- The fuzz crate's `Cargo.lock` is not committed (the coordinator's, per the
  rule).

## 5. Benchmarks (run)

Command:
`cargo test -p bk-elf --release --test bench -- --ignored --nocapture --test-threads=1`.
Input: a 41 MB file with one `.symtab` of 1,000,001 symbols, written by the
builder. The fuzzer was running on the machine at the same time, so treat
the figures as indicative.

| Benchmark | Time | Per symbol |
|---|---:|---:|
| `ElfFile::parse` (header, tables located, no symbol read) | 1.3 µs | — |
| Decode every symbol (`MemoryProvider`) | 3.8 ms | 3.8 ns |
| … and borrow its name | 27.8 ms | 27.8 ns |
| … and collect owned names | 50.5 ms | 50.5 ns |
| Decode every symbol (`FileProvider`) | 23.8 ms | 23.8 ns |
| … and read its name (`FileProvider`) | 215 ms | 215 ns |

These numbers are in `docs/PERF.md`, next to `bk-bin`'s reader numbers from
the checkpoint.

## 6. Differences from Ghidra

All are recorded in spec §8. The ones added in this session:

- **Exceptions that end Ghidra's import become diagnostics here**, and the
  affected table is skipped:
  - an Android table that is missing or not `APS2` (an `IOException` in
    Ghidra);
  - an address that `ElfProgramHeader.getOffset` cannot map (an unchecked
    exception in Ghidra).
- **The `APS2` count is capped at the file length.** A group larger than the
  capped count is therefore reported against the capped number.
- **The GNU-hash walk also stops at the end of the file.**
- **`section_by_name` returns the first match**, where Ghidra's
  `getSection` throws if two sections share a name.
- **`st_name` is unsigned.**
- **Lazy reads report their own diagnostics** (a symbol name, a `DT_NEEDED`
  string) instead of adding to the file's list.
- **Android relocations on MIPS-64** use the standard 64-bit split.
- **Section names in diagnostic messages are read with a 256-byte bound**,
  so that hostile names cannot make the messages quadratic.
- **Section and segment data is cut at the end of the file.**
  `section_provider` gives Ghidra's zero-filled view instead.
- **Notes and informational sections are read from the file**, in the
  file's data byte order, not from program memory.
- **GNU versioning chains are bounded.**
- **Kept as in Ghidra, not a difference**: a relocation section whose link
  is bad is reported three times (both `DT_JMPREL` passes and the section
  loop reach it). The test asserts the repetition.

## 7. Gaps

- **Not ported: `GnuBuildAttributes` / `GnuBuildAttribute`.** These decode
  the `.gnu.build.attributes` name fields for markup. The notes themselves
  can be read with `section_notes`.
- **Not ported: the Android and `RELR` table data-type layouts**
  (`AndroidElfRelocationTableDataType`, `ElfRelrRelocationTableDataType`).
  They are M4 markup.
- **No real MIPS, PowerPC or SPARC file** in the fixtures: Apple clang
  lacks those backends. The MIPS-64 relocation layout rests on hand
  vectors.
- **`"Failed to idenitify loaded GNU Hash table"` [sic] has no test.** It
  needs a hash table outside every section and `PT_LOAD` file range while
  its address is inside a `PT_LOAD`, which I could not construct with the
  builder's single whole-file `PT_LOAD`.
- **The 2³¹ hard limit on header-table counts** is tested in `limits.rs`
  and through the section-index table, not with a header-table fixture
  (that would need a multi-gigabyte file).

## 8. For the PE / Mach-O and loader tracks — the `bk-bin` API

- Take input as `&dyn ByteProvider`, or be generic over `P: ByteProvider`
  to own it, as `ElfFile<P>` does. References, `Box` and `Arc` of providers
  are providers.
- `MemoryProvider::new(vec_or_slice)` for bytes, `FileProvider::open(path)`
  for files, `SubProvider::new(&parent, offset, len)` for an embedded file,
  `UnlimitedProvider` when headers must tolerate truncation (reads past the
  end yield zeros).
- `BinaryReader::new(&provider, endian)` or `BinaryReader::from_slice`. It
  is `Copy`: `.at(offset)` gives an independent cursor, `.with_endian(e)`
  another byte order.
- `read_x()` advances, `read_x_at(i)` does not, `peek_x()` reads at the
  cursor. A failed read never moves the cursor (LEB128 excepted). Errors
  are `BinError`, and `is_eof()` tells "ran out of data".
- Do not allocate per entry. `read_bytes_at` borrows from in-memory
  providers; `read_array_at::<N>` copies onto the stack.
- Through `UnlimitedProvider` every range is valid, so bound lengths read
  from the file yourself.
- For a `FileProvider`, read a whole table with one `read_bytes` call and
  decode from the slice. Per-item reads cost about 20 ns each through the
  block cache (§5).
- For the loader: `ElfFile` exposes everything `ElfHeader` did, plus
  `relocation_layout()`. Relocation *handlers*, GOT/PLT markup and data
  types are M4.

## 9. Follow-ups and proposals

- **ADR-011**: please add the `dhat` evaluation from §11 (a dev-dependency
  for allocation-bound tests).
- **`flate2`**: `master`'s lock now has 1.1.11; this branch keeps 1.1.10, as
  the brief asked. The coordinator decides at merge.
- **Lock pins**: `dhat`'s dependency tree brought in `itoa` 1.0.19 and
  `smallvec` 1.16.5, both under two weeks old. They are pinned back to
  1.0.18 and 1.16.4.
- **`object` as the shared oracle**: `tests/common/oracle.rs` is generic
  over class and byte order. It could move to `bk-testkit` once that crate
  is free.

## 10. Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` → **0**; last line `tests: 764 passed, 0 failed` (run on commit `303e3c8`; only this report changed after it). In the gate `BASILISK_GHIDRA_DIR` is unset, so from the worktree the Ghidra-file test skips; it was run separately with the variable set (above).

## 11. Crate evaluation (owner rule: use existing crates when they fit)

**Decision (ADR-011 on `master`): write the parser; keep `object` as
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
  `char::decode_utf16`, `char::from_u32`). `encoding_rs` 0.8.35 was **built
  and run** this time (`target/enc-check`, a throw-away program; output
  below): every ASCII and Latin-1 label resolves to windows-1252
  (41 80 e9 ff → `A€éÿ`, no error; Java's `US_ASCII` gives `A` + three
  U+FFFD, its `ISO_8859_1` gives U+0080 for 0x80), `utf-32`/`utf-32le` are
  unknown labels, and its UTF-8/UTF-16 decoders produce what the standard
  library already does (one U+FFFD per error, unpaired surrogates included).
  It would replace nothing and break two charsets. Recorded in spec §8.

      us-ascii   -> windows-1252  decode(41 80 e9 ff) = "A€éÿ" errors=false
      iso-8859-1 -> windows-1252  decode(41 80 e9 ff) = "A€éÿ" errors=false
      utf-8      -> UTF-8         decode(41 80 e9 ff) = "A���" errors=true
      utf-32     -> None
      utf16 unpaired: encoding_rs="A�B" std="A�B"

- **zlib — `flate2`** (workspace), used.
- **File block cache — own code (≈40 lines), unchanged.** `lru` (the standard choice)
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

- **Heap measurement in tests — `dhat` 0.3.3** (dev-dependency, new): 15.6
  million downloads, 4.9 million in the last 90 days, 401 reverse
  dependencies, released 2024-02-04; MIT/Apache-2.0. The standard crate for
  asserting heap use in tests (`dhat::HeapStats`, testing mode); it needs no
  `unsafe` in our code. Alternative looked at: `stats_alloc` (21.7 million
  downloads, but 2.0 million recent, unmaintained since 0.1.10). Its
  dependency tree adds `backtrace`, `serde_json`, `parking_lot` & co. to the
  lock file; two of those resolved to versions under two weeks old and were
  pinned back (`itoa` 1.0.18, `smallvec` 1.16.4).

## 12. Commits

`git log --oneline master..HEAD` — see the final message of the run.
