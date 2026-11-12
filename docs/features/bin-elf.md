# Byte providers, binary reader and the ELF format (`bk-bin`, `bk-elf`)

Track `bin-elf`, wave 1, milestone M0 (groundwork for M4). Format of this
document: `docs/LOOP.md`, "Feature documents".

Path abbreviations: `BIN/` = `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/`,
`ELF/` = `BIN/format/elf/`, `BT/` = `Ghidra/Features/Base/src/test/java/`,
all under `../ghidra`.

## 1. Purpose

Every loader starts by reading structured data out of a file. `bk-bin` is
the shared byte-source and typed-reader layer for all format parsers;
`bk-elf` is the first of them: a complete, tolerant parser for ELF files
that exposes everything Ghidra's ELF loader later needs. Neither knows
anything about programs.

## 2. Ghidra sources

| Source | What to take from it |
|---|---|
| `BIN/ByteProvider.java` and implementations: `ByteArrayProvider`, `FileByteProvider`, `ByteProviderWrapper`, `RangeMappedByteProvider`, `EmptyByteProvider`, `StaticValueByteProvider`, `UnlimitedByteProviderWrapper`, `SynchronizedByteProvider`, `InputStreamByteProvider`, `ObfuscatedFileByteProvider` | The byte-source contract (length, positional reads, names) and the composable providers |
| `BIN/BinaryReader.java` | Typed, endian-aware reads at a cursor or an explicit index; all string forms; arrays; unsigned helpers; `clone` with a different endianness; error rules |
| `BIN/LEB128Info.java`, `ghidra/program/model/data/LEB128.java` (SoftwareModeling) | LEB128 decoding and its limits |
| `ELF/ElfHeader.java` | The header, and the order and laziness in which the rest of the file is parsed; every tolerance rule for malformed files |
| `ELF/ElfProgramHeader*.java`, `ElfSectionHeader*.java`, `ElfStringTable.java`, `ElfSymbol.java`, `ElfSymbolTable.java`, `ElfDynamic.java`, `ElfDynamicTable.java`, `ElfDynamicType.java`, `ElfRelocation.java`, `ElfRelocationTable.java`, `ElfRelrRelocationTableDataType.java`, `AndroidElfRelocation*.java`, `ElfCompressedSectionHeader.java`, `GnuVerdef.java`, `GnuVerdaux.java`, `GnuVerneed.java`, `GnuVernaux.java`, `ElfConstants.java`, `GnuConstants.java`, `ElfFileSection.java`, `ElfSymbolNameUtils.java`, `ElfException.java` | Each structure: layout for 32- and 64-bit, both endiannesses; constants; derived values; naming |
| `ELF/info/` (`ElfInfoItem`, `ElfNote`, `NoteAbiTag`, `NoteGnuBuildId`, `NoteGnuProperty`, `GnuDebugLink`, `GnuDebugAltLink`, `ElfComment`, `GnuBuildAttributes`) | Notes and informational sections |
| `ELF/extend/ElfLoadAdapter.java`, `ElfExtension.java` and the per-processor extensions under `Ghidra/Processors/*/src/main/java/**/*ElfExtension*.java` | **Only** the parts that change how the file itself is parsed: processor-specific program-header, section-header and dynamic types and their names, and header-parsing hooks. Program-building hooks are M4 |
| `BT/ghidra/app/util/bin/` | The tests (section 6) |

## 3. Scope

**In:** the provider trait and providers; the binary reader; LEB128; the
ELF structures listed above; processor-specific ELF *type tables*.
**Crates owned:** `bk-bin`, `bk-elf` (`bk-elf` depends on `bk-bin`).
They have **no dependency on other `bk-*` crates**.

**Not in this track:** anything that touches a program — the ELF loader
(`ElfProgramBuilder`, `ElfLoader`), relocation *handlers* (applying
relocations per processor), GOT/PLT markup, data-type creation
(`StructConverter` implementations become data types in M4; here the
parser keeps the field values and offsets needed to create them later),
`MemoryByteProvider` (needs program memory: M4), file-system providers
(`FileBytesProvider`, GFile-based providers: M10).

## 4. Behaviour

### 4.1 Byte providers
A provider is a random-access, read-only byte source with a known length:
read `len` bytes at `offset` (error if the range is outside the provider),
read one byte, length, emptiness, validity of an index, and an optional
name and path for messages. It is `Send + Sync` and takes `&self`, so many
threads can read one provider without locking (Ghidra needs
`SynchronizedByteProvider` for this; basilisk does not, by design).

Providers to supply, with Ghidra's semantics:
- in-memory bytes (owned and borrowed);
- a file, read with positional reads (`read_at` on Unix, `seek_read` on
  Windows) through a bounded block cache — no `unsafe`, so no memory map
  in this crate (ADR-005); `FileByteProvider`'s cache behaviour is the
  reference;
- a sub-range view of another provider (`ByteProviderWrapper`: offset and
  length, with nested wrappers composing);
- a range-mapped provider (`RangeMappedByteProvider`: an ordered list of
  ranges from a delegate, plus sparse zero-filled ranges);
- empty, and constant-fill providers.

The API should let parsers borrow bytes without copying when the provider
is in memory, and copy into a caller buffer otherwise (for example a
`Cow`-returning read, or a closure-based read) — parsers of large tables
must not allocate per entry.

### 4.2 Binary reader
A cursor over a provider with an endianness. Port all of
`BinaryReader`'s reads: signed and unsigned integers of 1, 2, 4 and 8
bytes; values of arbitrary byte length 1–8 (`readValue`,
`readUnsignedValue`); arrays of each; "next" forms that advance the
cursor and indexed forms that do not; alignment; `hasNext`; setting and
cloning with a new position or endianness; LEB128 (signed, unsigned, with
Ghidra's 64-bit overflow rules); and every string form — fixed-length and
NUL-terminated, ASCII, UTF-8, UTF-16 with either endianness or the
reader's, UTF-32, and the trimming rules for each (`readAsciiString`,
`readNextAsciiString`, `readUnicodeString`, `readUtf8String`,
`readTerminatedString`, `readFixedLenString` — the Javadoc of each states
what terminates the string and what is trimmed; match it, including
behaviour at the end of the provider). In Rust, signedness is in the type
(`read_u32`/`read_i32`), so Java's `readUnsignedInt`-returning-`long`
helpers collapse into the unsigned reads.

Every read returns a `Result`; reading past the end is an error value
carrying the offset and the length wanted, never a panic.

### 4.3 ELF
Parse 32- and 64-bit, little- and big-endian files into typed structures
holding every field, plus the file offset each was read from:

- the identification bytes and header (class, data encoding, version,
  OS/ABI, type, machine, entry, table offsets, flags, sizes, counts, the
  section-name string-table index), with the extended-numbering rules
  (`e_shnum` = 0 with the count in section 0's size; `e_shstrndx` =
  `SHN_XINDEX`; `e_phnum` = `PN_XNUM`);
- program headers and section headers, with their type and flag constants
  and names, including processor- and OS-specific ranges;
- string tables; symbol tables (`.symtab`, `.dynsym`, with extended
  section indices from `SHT_SYMTAB_SHNDX`), symbol binding, type,
  visibility, and Ghidra's symbol-name handling (`ElfSymbolNameUtils`,
  version suffixes);
- the dynamic table: every tag Ghidra names (`ElfDynamicType`), value
  kinds (address, value, string offset), and lookups by tag; locating
  dynamic structures through the dynamic table when section headers are
  missing or stripped (Ghidra resolves addresses to file offsets through
  the program headers — reproduce this, it is what makes stripped files
  work);
- relocation tables: `REL`, `RELA`, `RELR` (packed relative), Android
  packed relocations (`APS2` group encoding), with symbol index and type
  extraction for 32- and 64-bit and the MIPS-64 special layout;
- GNU symbol versioning (`.gnu.version`, `.gnu.version_d`,
  `.gnu.version_r`);
- compressed sections (`SHF_COMPRESSED`, zlib via `flate2`; record
  unsupported algorithms without failing);
- notes and informational sections (`info/`): ABI tag, build id, GNU
  properties, `.gnu_debuglink`, `.gnu_debugaltlink`, `.comment`;
- processor-specific type tables contributed by each processor's
  extension (ARM, AARCH64, MIPS, PowerPC, x86, RISC-V, …): as static data
  keyed by `e_machine`.

**Tolerance.** Ghidra loads damaged and hostile ELF files: it logs a
warning and carries on when a table lies outside the file, a count is
absurd, an entry size is wrong or a string offset is out of range. For
each such check in `ElfHeader.java` and the table classes, do what Ghidra
does (skip the table, clamp, or stop that part) and return the warning in
a diagnostics list alongside the parsed result. A fatal error is reserved
for files that are not ELF at all. All sizes and counts from the file are
bounded before allocating (ADR-009).

**Laziness.** Parsing the header and the section and program header
tables is eager; symbol, relocation and string tables are parsed on
demand or iterated lazily over the provider, so opening a large file is
cheap and nothing is copied that is not asked for.

## 5. Design

- `bk-bin` modules: `provider/{traits, memory, file, sub, range_mapped,
  fill}`, `reader/{cursor, int, string, leb128}`, `endian`, `error`.
- `bk-elf` modules: `ident`, `header`, `program_header`,
  `section_header`, `strtab`, `symbol`, `dynamic/{table, tags}`,
  `reloc/{table, rel, relr, android}`, `version`, `compress`,
  `note/{…}`, `machine/{arm, aarch64, mips, ppc, x86, riscv, …}`,
  `constants/{…}`, `diag`, `file` (the top-level `ElfFile` that ties the
  parts together).
- Constants are enums or newtypes with `const` values and name lookup
  (unknown values are preserved, not rejected): `SectionType(u32)` with
  associated constants rather than a closed enum.
- Class and endianness are handled once by the reader, not by duplicated
  32/64 structs: one struct per concept with 64-bit fields.
- Evaluate `object` under ADR-011: it is expected to be a dev-dependency
  used as a differential oracle, not the implementation (see the ADR).

## 6. Tests

- **Port** `ghidra.app.util.bin.BinaryReaderTest` (53),
  `ByteArrayProviderTest` (2), `FileByteProviderTest` (4),
  `RangeMappedByteProviderTest` (12) — mark them in
  `docs/inventory/tests/features-base.md` — and
  `ghidra.program.model.data.LEB128Test` (5) — mark it in
  `framework-softwaremodeling.md`. `MemoryByteProviderTest` and
  `LEB128DataTypeTest` need the program model: leave them unmarked.
- **Find and port** any ELF parser tests: search the checklist for
  classes under `ghidra.app.util.bin.format.elf` (most ELF coverage in
  Ghidra is through loader tests that need a program — list those in your
  report for M4, do not mark them).
- **Fixtures:** a small ELF builder in the test support of `bk-elf`
  (header, sections, segments, symbols, dynamic, relocations; 32/64, both
  endiannesses) so tests state their input in Rust. Real files: the two
  ELF files in the Ghidra tree
  (`GPL/GnuDisassembler/data/little.elf`, `big.elf`) and the `.so` files
  under `GhidraDocs/GhidraClass/ExerciseFiles/`, referenced in place
  (tests skip when `../ghidra` is absent).
- **Differential tests** against the `object` crate on the real files and
  on builder output: headers, section and segment tables, symbols,
  dynamic entries and relocations agree.
- **Derived tests:** every tolerance rule (each with a deliberately
  damaged fixture and the expected warning); extended numbering; stripped
  files resolved through the dynamic table; `RELR` and Android packed
  decoding against hand-computed vectors; compressed sections; each
  string form of the reader at the end of data.
- **Property tests and fuzz targets:** `elf_parse` (never panics, never
  allocates more than a fixed multiple of the input size), reader
  round-trips for integers and LEB128.
- **Benchmarks:** parse the symbol table of a large ELF (generate one
  with a million symbols through the builder); reader integer throughput;
  numbers in `PERF.md`.

## 7. Acceptance

1. The listed Ghidra tests pass in ported form and are marked.
2. The real ELF files parse with no warnings and agree with `object`.
3. Every tolerance rule in `ElfHeader.java` has a test.
4. No panics, bounded allocation; fuzz target runs 60 seconds without a
   finding.
5. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- Providers are lock-free (`&self`, positional reads); there is no
  synchronised wrapper.
- Malformed-file handling returns a diagnostics list with the parsed
  result instead of logging through a global message log.
- One set of structures with 64-bit fields for both ELF classes.

(The implementing agent appends further differences here.)

## 9. Status

Not implemented yet.
