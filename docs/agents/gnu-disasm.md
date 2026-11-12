# Track `gnu-disasm` — handover

Spec: `docs/features/gnu-disasm.md`. Decision: ADR-019. Branch `gnu-disasm`.

**This track is not finished.** It was stopped at the build decision at the
coordinator's request and is handed over here. What exists: the vendored
binutils subset with its script, and `bk-binutils-sys` building it and
passing 14 tests on macOS. What does not exist: `bk-gnu-disasm` (not
started), the golden/coverage/fuzz/benchmark work, Linux and Windows
verification, and the feature-doc updates.

Every statement below is marked by how I know it:
**[ran]** I ran something and saw the result; **[read]** I read the source;
**[suspected]** inferred, not checked.

Machine: macOS 25.5 on Apple silicon (8 cores, 16 GB), Apple clang 17.0.0,
GNU make 3.81, rustc 1.97.1. Other agents were compiling at the same time
(load average about 21 during the timings), so wall times are pessimistic.

## 1. State of the worktree

| Path | What it is |
|---|---|
| `vendor/binutils-2.41/` | The complete output of the vendoring script: 474 files, 30 MB on disk, 3.3 MB added to the git pack **[ran]** |
| `scripts/vendor-binutils.sh` | Produces that directory from a checkout; `--check` compares without writing |
| `crates/bk-binutils-sys/sources.list` | The 276 compilation units; read by both the script and `build.rs` |
| `crates/bk-binutils-sys/build.rs` | Generates `bfd.h`, compiles units and shim with `cc` into one static library |
| `crates/bk-binutils-sys/config/config.h` | The prepared configuration header (one for opcodes, bfd and libiberty) |
| `crates/bk-binutils-sys/shim/` | `bk_gdis.h/.c` (the C surface), `bfd_nofile.c` (BFD entry points for the no-object-file case), `include/assert.h` (assert → error) |
| `crates/bk-binutils-sys/src/` | `lib.rs` (public types), `real.rs` (FFI and all `unsafe`), `stub.rs` (Windows) |
| `crates/bk-binutils-sys/tests/shim.rs` | 14 tests of the raw interface |
| root `Cargo.toml`, `Cargo.lock` | `cc = { version = "1.10.0", features = ["parallel"] }` added; lock pins `cc` 1.10.0 |

Checks at the handover commit **[ran]**:
`CARGO_BUILD_JOBS=2 cargo build -p bk-binutils-sys` builds;
`cargo test -p bk-binutils-sys` 14 passed, 0 failed;
`cargo clippy -p bk-binutils-sys --all-targets -- -D warnings` clean;
`cargo fmt --all --check` clean; `scripts/check-file-size.sh` passes;
`scripts/vendor-binutils.sh --check /Users/tatu/slop/binutils` reports a match.
**The full gate (`scripts/gate.sh`) was not run.**
`/Users/tatu/slop/binutils` and `/Users/tatu/slop/ghidra` have empty
`git status --porcelain` and unchanged HEADs (`2c73aeb8d2e0`, `42db038f3c`) **[ran]**.

`master` has not been merged into the branch. Per the coordinator, the next
agent merges first; ADR-020 on `master` then applies (section 8).

## 2. The build evaluation

### 2.1 Approach A — binutils' own `configure` and `make`

Tried in a scratch directory outside the repository (since deleted; the
commands are complete here). Source: `git archive` of the tag for the
top-level files plus `bfd opcodes libiberty include zlib libsframe config`
(84 MB), so nothing was built inside the reference clone.

Attempt 1, Ghidra's own options (`GD/buildGdis.gradle`), restricted to opcodes:

    ../src/configure --prefix=$PWD/../inst --enable-targets=all --with-zlib=no \
        --disable-nls --disable-werror --disable-shared MAKEINFO=true
    make -j3 MAKEINFO=true all-opcodes

Failed after 41 s **[ran]**, for two reasons:
* **The bundled zlib does not compile with Apple clang 17**
  (`_stdio.h:322:7: error: expected identifier or '('`, from zlib's
  `fdopen` macro and K&R-style definitions). `--with-zlib=no` is not an
  option binutils knows, so Ghidra's recipe builds the bundled zlib; as
  written, **Ghidra's recipe does not build on this machine**.
* `libsframe/sframe.c` includes `swap.h`, which lives in `libctf/` (my
  export lacked it — but it shows the subset would need `libctf` too).

Attempt 2, adding `libctf` and replacing `--with-zlib=no` by
`--with-system-zlib`: succeeded **[ran]**.

* Time: **1 min 10 s wall at `-j3`** (91 s user + 37 s system), of which
  the `configure` runs (top level, libiberty, zlib, libsframe, bfd, opcodes:
  about 690 "checking…" lines) are serial.
* Output: `libbfd.a` 47.7 MB, `libopcodes.a` 38.2 MB, `libiberty.a` 1.2 MB,
  `libsframe.a` 81 kB.
* Not hermetic: `configure` found Homebrew's **libzstd through pkg-config**
  and made libbfd depend on it; the link then needs `-lzstd` and `-lz`
  from the system. `--without-zstd` and a zlib that compiles would be
  needed to fix that.
* Linking a program that only disassembles pulls in **290 of libbfd's
  objects** (every object-file backend), 176 of libopcodes' 183, 24 of
  libiberty's, libsframe, zlib and zstd; the test executable was 20 MB.
  The link map is where the 176 came from (section 2.3).

What approach A would need elsewhere: on Linux a shell, make, and a zlib
(system or a bundled one that compiles) — plausible, not tried. On
Windows it needs MSYS2 or similar for `sh` and `make`; MSVC is not a
compiler binutils supports. The vendored tree would have to carry the
`configure` scripts, `Makefile.in`s, libtool files, `config/`, all of `bfd`
(27 MB), `libsframe`, part of `libctf` and zlib: roughly 80 MB.

### 2.2 Approach B — the `cc` crate against prepared configuration

First as a scratch experiment (`xargs -P 3 cc -c -O2 …` over the same file
list): **274 files in 9.5 s wall** (19 s user + 5.6 s system) **[ran]**.
Then as the crate that is committed:

    cargo clean -p bk-binutils-sys
    time CARGO_BUILD_JOBS=2 cargo build -p bk-binutils-sys

* **Clean build of the crate: 15.4 s wall at 2 jobs** (19.5 s user + 6.1 s
  system), dev profile (C at `-O1 -g`) **[ran]**. The very first build,
  which also compiles `cc` and its dependencies, took 32 s **[ran]**.
* Rebuild with nothing changed: 0.05 s; after touching `src/lib.rs`: 0.1 s
  (the C is not recompiled) **[ran]**.
* `build.rs` reruns only when `build.rs`, `sources.list`, `shim/`,
  `config/` or `vendor/binutils-2.41/` change **[read]** (cargo's
  directives; I did not test each trigger).
* The static library is 40 MB in the dev profile because of C debug
  info **[ran]**. Whether to turn C debug info off (`.debug(false)`) to
  save build time and `target/` space was going to be measured; it was not.
* Release-profile build time: not measured.
* Parallelism comes from `cc`'s `parallel` feature, which takes tokens
  from Cargo's jobserver **[read]**.

What it needs by hand (all in the crate; about 1,000 lines of C and headers,
comments included):
1. `config/config.h` — about 40 `#define`s. The compiled files consult only a
   few `HAVE_*` results and those are the same on the hosts in question.
2. `bfd.h` — generated in `build.rs` from `bfd/bfd-in2.h` by filling in its
   five `@…@` placeholders (64-bit BFD, plugin support off, 64-bit file
   offsets), exactly what `configure` does; the build fails if a
   placeholder is left over.
3. `-DARCH_all` for `opcodes/disassemble.c` (its own switch for "every
   disassembler") and `-DHAVE_CONFIG_H`.
4. `shim/bfd_nofile.c` — see 2.3.
5. `opcodes/s390-opc.tab` — see section 4.

Linux: **not verified.** A Docker daemon is running on this machine
(server 29.1.2) and I intended to build and test in a `rust` container;
I did not get to it. Things I expect to matter there **[suspected]**:
glibc's `_setjmp`, `alloca` in `libiberty/regex.c` (no `HAVE_ALLOCA_H` is
defined; it compiled on macOS), `basename`/`stpcpy` declarations
(`config.h` defines `_GNU_SOURCE`), and that the generic header closure
of the vendoring script really covers what a Linux compile includes.

Windows: **not verified, and currently a stub.** `build.rs` compiles no C
when `CARGO_CFG_WINDOWS` is set and `src/stub.rs` then provides the same
interface with `is_available() == false` and `RawError::Unavailable`.
**`stub.rs` has never been compiled** (no Windows target was installed);
treat it as unbuilt code. Approach B could work with MinGW or clang
**[suspected]**: known obstacles are `stpcpy` (used by `i386-dis.c`, absent
from MinGW's C library — vendor `libiberty/stpcpy.c` for that target) and
the `-Dabort=…` rename against MSVC's `__declspec(dllimport)` declaration.
MSVC itself compiling binutils' C is doubtful.

### 2.3 Why approach B needs `shim/bfd_nofile.c`

libopcodes has 129 undefined symbols outside itself **[ran]** (`nm` on the
approach-A libraries). Most are in small, self-contained files, which are
compiled for real: `bfd/archures.c`, the 89 `bfd/cpu-*.c`, `bfd/libbfd.c`,
`bfd/elfxx-riscv.c` (RISC-V subset parsing), `bfd/xtensa-isa.c`,
`xtensa-modules.c`, `xtensa-dynconfig.c`, and 13 libiberty files. But 18
functions and 2 variables live in `bfd.c`, `section.c`, `bfdio.c`,
`reloc.c`, `elf.c`, `aout-ns32k.c` and `elf32-xtensa.c`, and those files
drag in the whole of libbfd (that is why approach A links 290 objects):

    _bfd_error_handler  bfd_set_error  bfd_assert  _bfd_abort  bfd_scan_vma
    bfd_get_section_by_name  bfd_get_section_contents
    bfd_malloc_and_get_section  bfd_set_section_contents  _bfd_std_section
    bfd_bread  bfd_bwrite  bfd_seek
    bfd_elf_generic_reloc  bfd_reloc_offset_in_range  _bfd_ns32k_relocate_contents
    xtensa_default_isa  xtensa_read_table_entries  xtensa_compute_fill_extra_space

`bfd_nofile.c` defines them for a disassembler that has no object file:
error reporting keeps the message for Rust; `bfd_scan_vma` is the
original's `strtoull` branch; everything that needs a section, file or
relocation **abandons the call with an error** (it does not return
made-up data). My reading is that none of those is reachable when no BFD,
section or symbol table is passed **[read]** — callers are guarded by
`info->section != NULL`, an ELF-flavoured `abfd`, or are relocation
functions only named in tables. That reading is not yet backed by a fuzz
run; if it is wrong the result is an `Aborted` error, not a crash.

Also left out on purpose: `HAVE_BFD_MIPS_ELF_GET_ABIFLAGS` (needs the MIPS
ELF backend; used only with a section) and `HAVE_DLFCN_H` plus
`BFD_SUPPORTS_PLUGINS 0`, so `xtensa-dynconfig.c` cannot `dlopen` a
library named by the `XTENSA_GNU_CONFIG` environment variable.

### 2.4 Recommendation

**Approach B**, as committed. Reasons, by the spec's criteria:

| | A: configure/make | B: `cc` + prepared config |
|---|---|---|
| macOS (this machine) | Ghidra's recipe fails; works with system zlib and picks up Homebrew zstd | builds, 14 tests pass |
| Hermetic | no (system zlib, zstd via pkg-config unless disabled) | yes: only the vendored tree and a C compiler |
| Clean build | 70 s at 3 jobs | 15 s at 2 jobs |
| Linked code | 290 libbfd objects + zlib + zstd + libsframe, file I/O, `dlopen` | 276 units, no file I/O, no `dlopen` |
| Vendored size | about 80 MB | 30 MB (3.3 MB packed) |
| Windows | needs `sh` and `make`; no MSVC | no tools beyond a C compiler; unverified |
| Hand-maintained | configure options only | `config.h`, 5 substitutions, `sources.list`, `bfd_nofile.c` |

The cost of B is the last row; it is bounded because binutils is pinned to
one release.

To redo the link-closure derivation if `sources.list` is ever questioned:
build approach A (attempt 2), then link this against
`opcodes/libopcodes.a bfd/.libs/libbfd.a libsframe/.libs/libsframe.a
libiberty/libiberty.a -lz -lzstd` with `-Wl,-map,out.map` and read the
"Object files" section of the map:

    #include "config.h"
    #include "bfd.h"
    #include "dis-asm.h"
    static int pf(void *s, const char *f, ...) { return 0; }
    static int pfs(void *s, enum disassembler_style st, const char *f, ...) { return 0; }
    int main(int argc, char **argv) {
      struct disassemble_info di;
      const bfd_arch_info_type *ai = bfd_scan_arch(argv[1]);
      const char **l = bfd_arch_list();
      init_disassemble_info(&di, 0, pf, pfs);
      di.arch = ai->arch; di.mach = ai->mach;
      disassemble_init_for_target(&di);
      disassembler_ftype f = disassembler(ai->arch, 0, ai->mach, NULL);
      unsigned char b[4] = {0};
      di.buffer = b; di.buffer_length = 4;
      int n = f(0, &di);
      disassemble_free_target(&di);
      return n + (l != 0) + (bfd_lookup_arch(ai->arch, ai->mach) != 0);
    }

The libopcodes objects that were *not* linked, and so are not in
`sources.list`: `aarch64-asm.c`, `aarch64-asm-2.c`, `cris-desc.c`,
`lm32-opinst.c`, `m32r-opinst.c`, `msp430-decode.c`, `visium-opc.c`.

## 3. Existing crates looked at

Figures from the crates.io API on 2026-11-12 **[ran]**.

| Crate | Total downloads | Last 90 days | Dependents | Newest | Outcome |
|---|---|---|---|---|---|
| `cc` | 1,504,962,412 | 378,431,231 | 4,464 | 1.11.1 (2026-11-06) | **Adopted**, at 1.10.0 (2026-10-23): the standard way to compile C from `build.rs`; parallel through Cargo's jobserver |
| `autotools` | 16,017,012 | 2,872,308 | 54 | 0.2.7 (2024-04-08) | Not adopted: it drives approach A, which lost (2.4) |
| `cmake` | 399,395,738 | 128,746,402 | 986 | 0.1.58 | Not applicable: binutils has no CMake build |
| `bindgen` | 461,066,791 | 102,433,293 | 3,110 | 0.73.2 | Not adopted: needs libclang at build time, for a header of 7 functions and 2 structs whose layout is asserted on both sides |
| `binutils` | 6,578 | 85 | 0 | 0.1.1 (2018-05-12) | Rejected **[read]**: its `build.rs` downloads binutils 2.29.1 with `curl` during the build, runs `configure`/`make -j8`, and links the system's zlib |
| `libopcodes-sys` | 6,385 | 46 | 1 | 0.1.4 (2024-07-03) | Rejected **[read]**: links an installed libopcodes/libbfd dynamically, reads `/usr/include/dis-asm.h`, runs `/sbin/ldconfig` (Linux only), needs bindgen |
| `libopcodes-rs` | 6,079 | 9 | 0 | 0.1.4 | Rejected: safe layer over `libopcodes-sys` |

`cc`'s own dependencies in the lock (all older than two weeks **[ran]**):
`jobserver` 0.1.35 (2026-07-06), `shlex` 2.0.1 (2026-05-17),
`find-msvc-tools` 0.1.15 (2026-10-19), `libc` 0.2.191 (2026-10-16).

For the coordinator: `cc` is written `version = "1.10.0"` like the other
workspace dependencies, which Cargo reads as `^1.10.0`; the lock pins
1.10.0, but regenerating the lock would pick 1.11.1, which was six days
old on 2026-11-12.

Pure-Rust disassemblers (`capstone`, `iced-x86`, `yaxpeax-*`) were not
evaluated: the feature is GNU's output specifically.

## 4. The vendored subset

`scripts/vendor-binutils.sh <checkout>` **[ran]**, twice with identical
result and once with `--check`:

* reads the tag's commit (`2c73aeb8d2e02de7b69cbcb13361cfbca9d76a4e`) with
  `git archive`, never the working tree, and writes nothing to the checkout;
* takes the units of `sources.list` and follows every `#include` through
  `opcodes bfd include libiberty`, ignoring preprocessor conditions, so the
  set does not depend on the host (a superset of what any one host reads);
* adds `bfd/bfd-in2.h` and the licence files `COPYING`, `COPYING3`,
  `COPYING.LIB`, `COPYING3.LIB`;
* **generates `opcodes/s390-opc.tab`**: binutils builds a host program
  (`s390-mkopc.c`) at build time and runs it on `s390-opc.txt`. The script
  does that once at vendoring time and keeps the generator and its input
  beside the output. This is the only file in the tree that is not a
  verbatim copy; `MANIFEST` says so. It needs a C compiler when vendoring;
* applies `crates/bk-binutils-sys/patches/*.patch` if any exist. **There
  are none: binutils is unpatched**;
* writes `MANIFEST` (commit, generated file, patches, SHA-256 per file).

Result: 474 files, 30 MB (`opcodes` 25 MB, `include` 2.3 MB, `bfd` 1.7 MB,
`libiberty` 0.4 MB); 279 `.c`, 186 `.h`, 2 `.def`. The M32C tables alone
are 9.6 MB (Ghidra maps `m16c` to them). No test suites, documentation,
`po/`, ChangeLogs, `configure` or Makefiles.

Two things the next agent should know:
* **The tag is not the tarball.** At tag `binutils-2_41`,
  `bfd/version.m4` says `2.40.90` and `bfd/development.sh` says
  `development=true`; the release tarball has `2.41`. Ghidra's users build
  from the tarball. I expect the `opcodes` sources to be identical
  **[suspected]**; comparing against
  `https://ftp.gnu.org/pub/gnu/binutils/binutils-2.41.tar.bz2` would
  settle it. Nothing compiled here uses the version string.
* No `.gitattributes` protects the tree from line-ending conversion. On a
  Windows checkout with `core.autocrlf` the hashes in `MANIFEST` would no
  longer match. I meant to add `vendor/.gitattributes` with
  `* -text linguist-vendored`.

`cargo fmt`, clippy and `scripts/check-file-size.sh` do not look at
`vendor/` (it is outside `crates/`, and has no Rust) **[ran]**.

## 5. Findings about safety

### 5.1 What `gdis` does per request (`disasm_1.c`) **[read]**

1. `bfd_openr(<little.elf|big.elf>, "pef")` with no format check: the BFD
   has target PEF (Ghidra always passes `pef`), no sections, no ELF data.
2. `bfd_set_arch_info` with a stack struct holding only `arch` and `mach`.
3. A zeroed `disassemble_info`; `INIT_DISASSEMBLE_INFO`; `arch`, `mach`,
   `flavour` (PEF), `endian`, `display_endian`; `disassemble_init_for_target`.
4. `disassembler(arch, big, mach, abfd)`.
5. `disassemble_init_for_target` a second time, **then** the option string
   is stored. Targets that read options during initialisation (PowerPC,
   S/390) therefore never see them in gdis.
6. `endian_code` is never set, so it stays `BFD_ENDIAN_UNKNOWN`. The CGEN
   targets decode with `endian_code == BIG ? big : little`, so gdis decodes
   **big-endian CGEN targets (or1k, m32r, fr30, …) with little-endian
   instruction order**. Of Ghidra's `gnu` names only `m16c` is CGEN, and it
   is little-endian either way.
7. `octets_per_byte` stays 1 (objdump sets it per architecture).
8. Per instruction: `insn_info_valid = 0`, call, collect text and info;
   advance by the returned size. A size of 0 makes gdis **loop forever**; a
   negative size (read error) makes it **step backwards**. Limits: 64
   instructions, 128 bytes, 128 characters of text (overrun not checked).
9. Architecture by name: exact match against `bfd_arch_list`, then
   `bfd_scan_arch` of that name supplies `arch` and `mach`. By number:
   `0x<arch>:0x<mach>` (Ghidra has one: `0x18:0x5`; I had not yet looked up
   what 0x18 is in 2.41's enum or which language uses it).
10. Java side: text gets tabs replaced by spaces and is trimmed; lines
    containing `is out of bounds.` are skipped; Thumb/ARM options come from
    `ARM.gdis` by the `TMode` context register, `intel` from `x86-16.gdis`.

What the shim does differently, deliberately (to go under "Differences
from Ghidra"; none is written into the feature doc yet):
options are in place before target initialisation (as objdump);
`endian_code = endian` (as objdump); flavour is ELF, not PEF; memory
errors are recorded instead of printed into the text; a fresh
`disassemble_info` per request, initialised once instead of twice.
I checked each use of `info->flavour` and of the `abfd` argument in
`opcodes/*.c` **[read]**: with no section and no symbols, ELF and PEF
behave the same, and only **CRIS** treats gdis' BFD differently from
`NULL` (it chooses the v32 decoder from the BFD's machine). The shim
therefore gives CRIS a stand-in BFD (zeroed, unknown flavour, no symbol
prefix, the right machine) and every other target `NULL`. **Not yet
tested** on CRIS; ARC must get `NULL`, because `arc_get_disassembler`
would search the BFD's (absent) section table.

### 5.2 Static state: libopcodes is not thread-safe **[ran + read]**

`nm` on the compiled objects shows writable statics in about 50 of the
`*-dis.c` files. Three kinds:

* *Lazily built tables* (hash tables, sorted opcode lists; SPARC and CGEN
  rebuild on a machine change). Harmless under a lock.
* *Option state that persists* — ARM `force_thumb`, `regname_selected`;
  AArch64 `no_aliases`, `no_notes`; RISC-V, S/390, ARC, LoongArch, VAX,
  Xtensa and others. In gdis one process serves one configuration; in
  process, two disassemblers of one architecture share this state.
* *Sequence state* — ARM IT/VPT block state (`ifthen_state`,
  `ifthen_address`), AArch64 `insn_sequence`, MicroBlaze `prev_insn_*`,
  RISC-V address tracking in `private_data`, CRIS, SH, xgate, bfin, …:
  the result for an instruction can depend on the one disassembled before.

What is done: **one process-wide mutex** around every call into C
(`src/real.rs`; a `Request` holds it for a whole block), tested from 8
threads **[ran]**. Each request rebuilds `disassemble_info` and copies the
option string afresh, and `disassembler()` is called again whenever another
disassembler has been used in between (it resets RISC-V's subset list and
C-SKY's flags).

What is **not** done and was planned for `bk-gnu-disasm`:
* Options that persist and are only parsed when given: a disassembler
  created *without* options inherits what the previous one set (ARM stays
  in Thumb after `force-thumb`; Ghidra's block disassembly has exactly this
  bug). Plan: per architecture family, prefix the options with the ones
  that restore binutils' defaults — ARM `reg-names-std,no-force-thumb`;
  AArch64 `aliases,no-notes` (check `no_notes`' default first); RISC-V
  resets itself whenever any option string is parsed, so an empty string
  suffices; MIPS resets on every call. **[suspected — the per-target
  parse functions still need to be read one by one]**
* Sequence state across requests cannot be reset from outside. It is the
  same in gdis. Document it; a test should show what happens for Thumb IT
  blocks.

### 5.3 `abort()`, `exit()`, assertions **[ran + read]**

In the 276 units: **504 `abort()` calls in 100 files, 145 `assert()` calls
in 13 files** (AArch64 alone 113; the 13 in `libiberty/regex.c` are compiled
out by that file itself), 8 `OPCODES_ASSERT`, and three `exit`
paths, all out-of-memory (`nios2-dis.c:136`, `obstack.c`, `xexit.c` via
`xmalloc`). I did not try to prove which are reachable from bytes; instead
all of them are trapped:

* the units are compiled with `-Dabort=bk_gdis_abort -Dexit=bk_gdis_exit`;
* `shim/include/assert.h` comes first on the include path and sends failed
  assertions to the shim (assertions stay *enabled* — compiling them out
  would let code run past a failed bounds check);
* BFD's own `abort()` macro goes to `_bfd_abort` in `bfd_nofile.c`;
* each shim entry point does `_setjmp`; the handlers `_longjmp` back and
  the call returns `BK_GDIS_ABORTED` → `RawError::Aborted { message }`.
  Only C frames lie between the two. After an abort inside a step, the
  shim abandons (leaks) the target's state and the next request starts over.

**The trap has not been exercised by any test** — no input that makes
binutils abort is known yet; the fuzz target should find some, and a test
could reach `bfd_nofile.c`'s refusals. Not trapped: writes to `stderr`
by some targets (`fprintf (stderr, …)` exists in aarch64, arc, csky, dlx,
nios2, sparc, tic4x, tic6x, v850 `-dis.c`), a crash, or an endless loop.

### 5.4 Reads and writes

* All reads go through `bk_read_memory`, which refuses anything outside
  the request's bytes with overflow-safe arithmetic and records the first
  refused address **[ran: two tests]**. x86 answers a refused read with
  `.byte 0xb8` and length 1; AArch64 returns a negative length.
* Two targets bypass `read_memory_func` and touch `info->buffer` directly
  **[read]**: `tic30-dis.c:702` (bounded by `buffer_length`) and
  **`csky-dis.c:1161`, which *writes* to the buffer** — it rewrites a
  32-bit little-endian instruction in place. Handing binutils a pointer
  derived from a `&[u8]` would be undefined behaviour. So `Request` copies
  the caller's bytes into a buffer the disassembler owns and passes that,
  mutable; a test checks the caller's bytes stay unchanged over C-SKY
  **[ran]**. Consequence for the API: the copy costs the length of the
  slice per request, so a "one instruction" call must not be handed a
  whole section each time — copy a window (I planned 256 bytes, growing
  when the read fault could be the window's edge).
* Text is appended with a running bound into a 1,024-byte buffer; overlong
  text is cut and flagged **[ran for the normal case; truncation itself is
  untested]**.
* Under `cfg(fuzzing)` the copy is an exactly sized allocation so that
  AddressSanitizer would see a read past the end. **Untested.**
* A second `Request` on the same thread would self-deadlock on the mutex;
  my first test run hung on exactly that. Now `Request` has a `Drop` impl
  (which makes the borrow checker reject two live requests on one
  disassembler) and a thread-local flag turns nesting across disassemblers
  into `RawError::RequestInProgress` **[ran]**.

### 5.5 Smaller facts

* `bfd_arch_list()` has 2 names that `bfd_scan_arch` cannot find:
  `tms320c4x` and `tms320c3x` (their scan function accepts `tic4x`, `c4x`,
  `4x`). gdis would dereference NULL for them **[ran + read]**.
* The symbols of libopcodes, libbfd and libiberty are global in the final
  binary (`xmalloc`, `htab_*`, `bfd_*`); `links = "bk_binutils"` prevents
  two copies of this crate, not a clash with another crate that links a
  libiberty **[suspected to be a non-issue today]**.
* `bk-binutils-sys/Cargo.toml` repeats the workspace lint tables instead of
  inheriting them, because the workspace's `unsafe_code = "forbid"` cannot
  be relaxed by the crate-level `#![allow(unsafe_code, reason = …)]` the
  spec asks for. It adds `undocumented_unsafe_blocks = "deny"`. If the
  workspace tables change, this copy must follow.

## 6. Done / Verified / Remaining, against the spec

| Spec | Done | Verified | Remaining |
|---|---|---|---|
| 4.1 Vendored source | script, tree, MANIFEST, licences, no patches | reproducible twice + `--check` **[ran]** | `.gitattributes`; tarball comparison; size reported (30 MB / 3.3 MB packed) |
| 4.2 Building | `cc` build of all targets, static, no NLS, shim, raw interface, lock, traps | macOS build + 14 tests **[ran]** | Linux; Windows (stub uncompiled); release build time; C debug-info decision; full gate |
| 4.3 Safe API | — | — | all of `bk-gnu-disasm` |
| 6 Tests | 14 raw-interface tests | pass on macOS | golden, coverage of Ghidra's `gnu` names and `.gdis` files, derived tests, proptest, fuzz, benchmark |
| 7 Acceptance | 2 (reproducible) holds | | 1, 3, 4, 5 open |
| 8/9 Feature doc | — | — | Differences (list in 5.1), Status; `PERF.md` |

Order I would take:

1. Merge `master`; register the crate per ADR-020 (section 8).
2. **Review the shim before building on it** — nobody but me has read it.
   Points worth a second pair of eyes: the `BK_GUARD` macro and which
   locals live across `_setjmp`; abandoning target state after an abort;
   `bk_gdis_create`'s failure paths; the CRIS stand-in BFD.
3. Linux in a container (`docker run` with a Rust image, the worktree
   mounted read-only, `CARGO_TARGET_DIR` elsewhere). Fix what it finds.
4. Sanitizer builds of the tests (section 8), then the fuzz target: one
   target taking (architecture index, endianness, bytes), 60 s per family.
   Expect it to produce the first real evidence about 5.2–5.4.
5. `bk-gnu-disasm`: `arch` (name via `bfd_scan_arch`, numeric
   `0x<arch>:0x<mach>`, error listing what is available), `disassembler`,
   `instruction` (raw text and Ghidra's form: tabs → spaces, trimmed; info
   only when `insn_info_valid`), `block` (stop at length ≤ 0 instead of
   gdis' loop/step-back; no 64/128 limits), `gdis_config/{model, read}`
   with `roxmltree` (`<global optstring>`, `<context_register>`,
   `<option value optstring display_prefix>`; values parsed like Java's
   `Long.decode`; combine as `global,option`), `error`.
6. Golden tests. `/usr/bin/objdump` here is Apple's LLVM objdump, not GNU;
   no GNU objdump 2.41 is installed, so expectations must come from
   instruction-set manuals or a 2.41 objdump built in a container.
7. Coverage test over `external_name tool="gnu"` (65 distinct names in
   Ghidra's `.ldefs` **[ran]**, list obtainable with
   `grep -rhoE 'external_name tool="gnu" name="[^"]*"' --include='*.ldefs' Ghidra/Processors`)
   and the two `.gdis` files (`ARM.gdis`, `x86-16.gdis`). Names I expected
   to need attention: `0x18:0x5`, `arm_any`, `iwmmxt`, `n1h_v3m`,
   `hppa2.0w`, `Loongarch64`, `msp:14`. **None was tried.**
8. Benchmarks (x86-64, AArch64 instructions per second), `PERF.md`,
   feature doc, Windows decision, final report.

## 7. In flight, and things that did not work

* I was finishing the raw-interface tests; they pass. Nothing is half
  edited.
* `crates/bk-gnu-disasm` was created as a placeholder and **removed
  again** before committing; the workspace's `crates/*` glob fails on a
  directory without `Cargo.toml`, so do not leave one behind.
* `bfd/cpu-ia64-opc.c` is not a compilation unit (it is included by
  `cpu-ia64.c`); listing `bfd/cpu-*.c` blindly breaks.
* `bfd.h` refuses to be included unless `PACKAGE` is defined, while
  `bfd/sysdep.h` refuses if it is defined *before* `config.h` — so
  `PACKAGE` goes inside `config.h`, not on the command line.
* clippy does not lint `print_stdout` in build scripts: an
  `#![expect(clippy::print_stdout)]` there is an unfulfilled expectation.
* `timeout` does not exist on this macOS; a hung test binary has to be
  found with `ps` and killed.
* The shell here aliases `grep` and `ls` to other tools; use
  `/usr/bin/grep` and `/bin/ls` in commands whose output matters.
* macOS `/bin/bash` is 3.2: the vendoring script avoids associative arrays
  on purpose.

## 8. ADR-020 (`unsafe` only when necessary; Miri) and sanitizers

Not on this branch yet; from the coordinator's description: Miri cannot
run C, so `bk-binutils-sys` is to be listed in `unsafe-crates.txt` as
`no-miri` and checked with AddressSanitizer and UndefinedBehaviorSanitizer
builds of its tests and fuzz target; pure-Rust `unsafe` belongs in a module
Miri can run.

* All `unsafe` is in `src/real.rs`: 8 FFI calls, one `CStr::from_ptr` on
  BFD's static strings, and `unsafe impl Send`. There is **no pure-Rust
  `unsafe`** — every block is a call into C or a read of C-owned memory —
  so there is nothing for Miri to run in this crate as it stands.
* **Sanitizer builds were not tried.** What I expect **[suspected]**:
  `cc` honours `CFLAGS`, so `CFLAGS="-fsanitize=address,undefined"` (plus
  `-fsanitize=fuzzer-no-link` for coverage under cargo-fuzz) instruments
  the C without touching `build.rs`; the Rust side needs nightly
  `-Zsanitizer=address`. Two risks: the AddressSanitizer runtime of the
  Rust nightly and of Apple clang 17 are different LLVM versions and may
  not mix (a Linux container with matching clang avoids that), and the
  abort trap uses `_setjmp`/`_longjmp`, which AddressSanitizer intercepts
  but which deserves a deliberate test. UBSan is likely to report existing
  shifts and overflows in binutils' own code; those would need triage, not
  necessarily fixes. cargo-fuzz is installed here; a nightly toolchain is too.

## 9. Proposals for the coordinator

* `docs/LOOP.md` puts fuzz targets in a root `fuzz/` crate; several tracks
  adding `fuzz/Cargo.toml` at once will conflict. Either the coordinator
  creates it, or tracks keep fuzz crates beside their own crate.
* The feature doc says the crate layout is `build.rs`, `shim/`,
  `src/lib.rs`; it now also has `config/`, `sources.list`, and
  `src/{real,stub}.rs`. Worth reflecting in section 5 of the spec when it
  is next edited.

## 10. Commits

`git log --oneline master..HEAD` at the time of writing (this file is the
commit after these):

    d6622b7 feat(binutils-sys): build binutils' disassemblers from vendored source
    86a975b chore(vendor): binutils 2.41 subset for the GNU disassembler
