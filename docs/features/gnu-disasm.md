# GNU disassembler: binutils built in (`bk-binutils-sys`, `bk-gnu-disasm`)

Track `gnu-disasm`, started alongside wave 1 at the owner's request
(ADR-019). Format of this document: `docs/LOOP.md`, "Feature documents".

Path abbreviations: `GD/` = `GPL/GnuDisassembler/`,
`SDT/` = `Ghidra/Extensions/SleighDevTools/`, both under `../ghidra`;
`BU/` = the binutils 2.41 reference clone at `../binutils` (tag
`binutils-2_41`).

## 1. Purpose

Ghidra can show GNU's disassembly of an instruction beside SLEIGH's, as a
way to check a processor specification. It does this by running `gdis`, a
small C program over binutils that the user must build themselves.
basilisk builds the needed parts of binutils into its single binary and
offers the same comparison as a Rust API — which also gives basilisk's own
tests a second, independent disassembly oracle.

## 2. Sources

| Source | What to take from it |
|---|---|
| `GD/src/gdis/c/disasm_1.c`, `gdis.h` | What `gdis` does: how it obtains a BFD for an architecture (it opens the dummy files `GD/data/little.elf`/`big.elf`), sets architecture, machine, endianness and disassembler options, feeds bytes, captures the printed text through a custom `fprintf`, and what it reports per instruction (text, length, `insn_type`, `branch_delay_insns`, `data_size`, `target`, `target2`). Its command line and output format |
| `GD/build.gradle`, `buildGdis.gradle`, `README.md` | The binutils version (2.41) and how Ghidra configures and builds it (`configure` options, which libraries are linked, in what order) |
| `SDT/src/main/java/ghidra/app/util/disassemble/GNUExternalDisassembler.java`, `GnuDisassembledInstruction.java`, `ExternalDisassembler.java` | The Ghidra side: how a language is mapped to GNU architecture and machine names (the `external_name tool="gnu"` entries in `.ldefs`), the `.gdis` configuration files (`Ghidra/Processors/*/data/languages/*.gdis`: global options and context-register-dependent options), how blocks of bytes are sent and results parsed, alignment and error handling |
| `SDT/src/main/java/ghidra/app/util/disassemble/ExternalDisassemblyFieldFactory.java`, `SDT/ghidra_scripts/GNUDisassembleBlockScript.java` | The listing field and the script that use it — **not** in this track (UI: M7; scripts: M9); read them to see what the API must serve |
| `BU/opcodes`, `BU/bfd`, `BU/libiberty`, `BU/include`, `BU/zlib` | The C source to build. `include/dis-asm.h` is the disassembler interface |

## 3. Scope

**In:**
1. `vendor/binutils-2.41/` — the subset of binutils needed, vendored into
   this repository by a reproducible script.
2. `bk-binutils-sys` — builds that subset from C and exposes a minimal
   raw interface. The **only** crate in the workspace with C code and
   `unsafe` (ADR-019).
3. `bk-gnu-disasm` — the safe Rust API: what `gdis` and
   `GNUExternalDisassembler` do, as a library.

**Crates and paths owned:** `crates/bk-binutils-sys`,
`crates/bk-gnu-disasm`, `vendor/binutils-2.41/`,
`scripts/vendor-binutils.sh`. They depend on **no other `bk-*` crate**
(wave 1 crates are still being written). Mapping a basilisk language to a
GNU architecture through `bk-lang`'s external names is a follow-up after
`bk-lang` merges; this track takes GNU architecture and machine names as
strings and parses `.gdis` files itself (`roxmltree`).

**Not in this track:** the listing field and the script (above); using
GNU disassembly as an oracle in `bk-sleigh` tests (M1 decides); gas, ld,
gdb or any other part of binutils.

## 4. Behaviour

### 4.1 Vendored source
`scripts/vendor-binutils.sh <binutils checkout>` copies from a checkout at
tag `binutils-2_41` exactly the files the build needs — the C sources and
headers of libopcodes, libbfd and libiberty, `include/`, and zlib only if
the build needs it rather than the Rust-side or system one — into
`vendor/binutils-2.41/`, and writes a `MANIFEST` (source commit, file list
with hashes) and keeps binutils' licence files. Leave out what is not
compiled: test suites, documentation, translations (`po/`), ChangeLogs,
other tools. The script is the only way the directory is produced; running
it again on the same checkout reproduces it byte for byte. Keep the
vendored tree as small as it can honestly be and report its size — it is
committed to the repository. Local changes to binutils source, if any are
unavoidable, are separate patch files applied by the script and listed in
the feature doc; never hand-edit the vendored tree.

### 4.2 Building (`bk-binutils-sys`)
`cargo build` on a machine with a C compiler builds the libraries with no
network access and nothing preinstalled beyond what a Rust developer
normally has. Requirements:

- **All of binutils' disassemblers** are included (the equivalent of
  `--enable-targets=all`, 64-bit BFD), since the point is to compare
  against any of Ghidra's processors. If that is impractical, say what is
  included and why.
- Static linking; no shared-library or installed-binutils dependency; no
  NLS.
- The build is driven from `build.rs`. Two ways exist — running binutils'
  own `configure`/`make` in `OUT_DIR`, or compiling the sources with the
  `cc` crate against prepared configuration headers. Choose by evidence:
  what works on macOS and Linux, what could work on Windows (MSVC and
  GNU), build time, and how much hand-maintained configuration it needs.
  Record the evaluation (ADR-011 applies to build dependencies too).
- **Build time matters**: this crate is in the workspace, so every clean
  build and CI run pays for it. Compile only what is needed, in parallel
  through Cargo's jobserver, and report clean and incremental build
  times. A rebuild happens only when the vendored tree or `build.rs`
  changes.
- **Platforms**: macOS (this machine) must build and pass. Linux should;
  verify in a container if one is available, otherwise say it is
  unverified. Windows: support it if the chosen approach allows; if not,
  the crate must still compile there and report at run time that GNU
  disassembly is unavailable on this platform, so the workspace and CI
  stay green — and that is recorded as a gap, not hidden.
- The raw interface is as small as possible: a thin C shim (kept under
  the crate, not in the vendored tree) that offers "create a disassembler
  for architecture/machine/endianness/options", "disassemble one
  instruction from this buffer at this address into this caller-provided
  text buffer and info struct", "destroy", and "list supported
  architectures" — so Rust never touches `struct disassemble_info` or BFD
  internals directly. All `unsafe` is in this crate, each block with a
  `// SAFETY:` comment; `unsafe_code` is allowed here by a crate-level
  attribute with the reason, and nowhere else.

### 4.3 The safe API (`bk-gnu-disasm`)
- Create a disassembler from a GNU architecture name (as `bfd_scan_arch`
  accepts, e.g. `i386:x86-64`), optional machine, endianness and an
  options string (e.g. `intel`); unknown architectures are an error that
  lists what is available.
- Disassemble one instruction, or a block, from a byte slice at a given
  address: for each instruction the text, the length, and the information
  `gdis` reports (instruction type, branch delay count, data size,
  targets). Reproduce `gdis`'s observable behaviour: the text formatting
  it produces, how it treats undecodable bytes, and block handling
  (alignment, the 64-entry and buffer limits are C artefacts — remove the
  limits but keep the results identical for inputs within them).
- `gdis` gets its BFD by opening a dummy ELF file per endianness. In
  process there is no reason to read a file: initialise
  `disassemble_info` directly if that gives identical results, and record
  it under "Differences from Ghidra".
- `.gdis` configuration: parse the files as `GNUExternalDisassembler`
  does (global option string; options selected by context-register
  values) into a typed model, and apply them given a caller-supplied
  register-value lookup.
- Thread safety: binutils' disassemblers use static state. Establish what
  is safe by reading the code, then make the API correct — if calls must
  be serialised, do it inside the crate (a lock) and document it; do not
  expose an API that is unsound when used from several threads.
- Hostile input: bytes come from binaries under analysis. The shim
  bounds every read to the provided buffer (a `read_memory_func` that
  refuses addresses outside it) and every write to the text buffer;
  errors and "memory error" callbacks become Rust errors, never aborts.
  binutils code may call `abort()`/`exit()` in some paths: find out which
  are reachable from disassembly and say what was done about them.

## 5. Design

- `bk-binutils-sys`: `build.rs` (split into modules under `build/` if it
  grows), `shim/` (C), `src/lib.rs` (raw declarations and the unsafe
  wrappers). No bindgen unless it earns its place: the shim's surface is a
  few functions.
- `bk-gnu-disasm`: `arch`, `disassembler`, `instruction`, `block`,
  `gdis_config/{model, read}`, `error`.
- The vendored C is exempt from Rust formatting and lint rules by
  construction; make sure `cargo fmt`, clippy and
  `scripts/check-file-size.sh` do not look at it.

## 6. Tests

- There are no Ghidra JUnit tests for this feature (search the checklist
  for `GNUExternalDisassembler` to confirm, and mark anything found).
- **Golden tests:** known byte sequences for a spread of architectures
  (x86 16/32/64 in AT&T and Intel syntax, ARM and Thumb, AArch64, MIPS
  big- and little-endian, PowerPC, RISC-V, SPARC, m68k, AVR, and others
  Ghidra has `gnu` external names for) with expected text and lengths.
  Derive expectations from a real `objdump` of the same version if one is
  available (`objdump --version`; Homebrew's binutils may differ in
  version — say which was used) or from the instruction-set manuals.
- **Coverage test:** for every `external_name tool="gnu"` in the `.ldefs`
  files under `../ghidra/Ghidra/Processors`, a disassembler can be
  created; report any name binutils 2.41 does not know. Every `.gdis`
  file parses.
- **Derived tests:** undecodable bytes; truncated instruction at the end
  of the buffer; block disassembly; options; delay-slot and branch-target
  info on MIPS and SPARC; concurrent use from several threads.
- **Property test and fuzz target:** arbitrary bytes for arbitrary
  supported architectures never crash the process, read outside the
  buffer or hang (run under the address sanitizer if the toolchain makes
  that practical, and say whether it was).
- **Benchmark:** instructions per second for x86-64 and AArch64; clean
  build time of `bk-binutils-sys`; numbers in `PERF.md`.

## 7. Acceptance

1. `cargo build` and the tests pass on this machine from a clean state
   with no network access and no binutils installed.
2. `scripts/vendor-binutils.sh` reproduces `vendor/binutils-2.41/`
   exactly from `../binutils`.
3. The golden and coverage tests pass; the fuzz target runs 60 seconds
   per architecture family without a finding.
4. `unsafe` exists only in `bk-binutils-sys`, and the workspace's other
   crates still build with `unsafe_code = "forbid"`.
5. The full gate is green; build time and vendored size are reported;
   platform status (macOS, Linux, Windows) is stated truthfully.

## 8. Differences from Ghidra

- The disassembler is linked in and called in process; there is no `gdis`
  executable, no dummy ELF files and no text protocol.
- Nothing for the user to download or build.

(The implementing agent appends further differences here, and lists any
patches to the vendored source.)

## 9. Status

Not implemented yet.
