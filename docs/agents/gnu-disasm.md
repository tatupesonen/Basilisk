# Track `gnu-disasm` — status report

Spec: `docs/features/gnu-disasm.md` (contract; sections 8 and 9 filled in).
Decisions: ADR-019 (binutils built in), ADR-020 (`unsafe`), ADR-022
(Windows first-class). Branch `gnu-disasm`, worktree
`basilisk-wt/gnu-disasm`.

Every claim is marked by how it is known: **[ran]** I ran it and saw the
result, with the platform; **[read]** from reading source; **[not run]**
not verified.

## 0. Where this stands (for whoever continues)

| | |
|---|---|
| Done | everything in the spec's acceptance list: `bk-binutils-sys` reviewed and hardened; `bk-gnu-disasm` built; goldens against GNU objdump; coverage of Ghidra's names; fuzzing and sanitizers on Linux; macOS, Linux and Windows (MinGW and MSVC, cross-built, tests under Wine) verified; benchmarks; feature doc; full gate green |
| Rests on CI | macOS on GitHub's runner; the next CI run after the C23 fix (section 12) |
| Next | merge (coordinator); follow-ups in section 10 |

Machine: Apple silicon (8 cores, 16 GB), macOS 25.5, Apple clang 17,
rustc 1.97.1, nightly 2026-11-12 for fuzzing, Docker 29.1. Other agents
were building at the same time throughout (load average 9–16).

## 1. What was built

**`bk-binutils-sys`** (C shim and FFI; the workspace's only `unsafe`)
- `build.rs`: compiles 302 units (`sources.list`) of the vendored tree plus
  the shim with the `cc` crate against `config/config.h`, for every
  Unix-like and Windows target (clang-cl for MSVC targets); generates
  `bfd.h`; no C debug info by default (`CFLAGS=-g` to have it);
  `abort`/`exit` redirected through a forced-include prelude
  (`shim/include/bk_prelude.h`, which also carries the Windows
  adaptations), failed `assert` through `shim/include/assert.h`.
- `shim/bk_gdis.c` (entry points, read/write bounds, abort trap),
  `shim/bk_state.c` (new: option resets, once-only options, quarantine),
  `shim/bfd_nofile.c` (libbfd functions that need an object file),
  `shim/bk_compat.c` (`stpcpy` on Windows), `shim/include-msvc/strings.h`.
- `src/real.rs` (all `unsafe`; the crate's lint opt-out is a
  `#[expect(unsafe_code)]` on this module only), `src/lib.rs`, `src/stub.rs`
  (now only for targets that are neither Unix-like nor Windows).
- `unsafe-crates.txt`: `bk-binutils-sys  no-miri:calls-into-C`.
- Raw API: `architecture_names`, `scan_architecture`,
  `RawDisassembler::{new, request}`, `Request::{step, take_message}`,
  `RawError` (new variants `OptionsConflict`, `Quarantined`; `EmbeddedNul`
  now has the position).

**`bk-gnu-disasm`** (safe API; modules `arch`, `disassembler`, `instruction`,
`block`, `gdis_config/{model, read}`, `error`)
- `Architecture::from_gnu_name` — as gdis: exact `bfd_arch_list` names and
  `0x<arch>:0x<mach>`; beyond gdis, `bfd_scan_arch` aliases; unknown names
  are an error that lists all 400+ known names; `tms320c3x`/`tms320c4x`
  (listed but not scannable; gdis crashes) are their own error.
  `from_numbers`, `names`, accessors.
- `Disassembler::new(&Architecture, Endian, Option<&str>)`;
  `instruction`, `instruction_at(bytes, base, offset)` (64 bytes of context
  before, 256 after, widened to the whole slice only if binutils reads past
  the window), `block` (stops at length ≤ 0; `BlockEnd::{Complete,
  NoInstruction, Failed}`).
- `Instruction { address, length, text, text_truncated, info, read_fault }`,
  `ghidra_text()` (tabs → spaces, trimmed, as `GnuDisassembledInstruction`);
  `InstructionInfo { kind, branch_delay_insns, data_size, target, target2 }`.
- `gdis_config::{parse, read_file}` → `GdisConfig { global, context }`;
  `options_for(lookup)` builds Ghidra's option string
  (`global,selected`), `display_prefix_for`; values read as Java's
  `Long.decode`.
- Thread safety: one process-wide lock in `bk-binutils-sys`; types `Send`.

**Vendored tree**: `vendor/binutils-2.41/`, 474 files, 30 MB, now with three
patches (`crates/bk-binutils-sys/patches/`, applied by
`scripts/vendor-binutils.sh`, listed in `MANIFEST`); `--check` against
`/Users/tatu/slop/binutils` reports a match **[ran]**.
`.gitattributes`: `vendor/** -text`; `git ls-files --eol vendor` shows all
474 files `i/lf w/lf` **[ran]**.

**Fuzz target** `bk_binutils_sys_disassemble` in the root `fuzz/` crate
(entries appended alphabetically; `cargo +nightly fuzz list` shows it
**[ran]**). Input format in `crates/bk-binutils-sys/tests/fuzz_input/mod.rs`,
included by the target and by `tests/fuzz_regressions.rs`, which replays
`fuzz/regressions/bk_binutils_sys_disassemble/` (empty: nothing found).
`fuzz/README.md` has a section on instrumenting the C. No `fuzz/Cargo.lock`
committed (coordinator's).

## 2. Shim review (the C and its Rust wrapper, read as someone else's)

Checked, with the outcome:

| Point | Finding | Action |
|---|---|---|
| Reads | `bk_read_memory`: overflow-safe bound on every read **[read]**; only `tic30-dis.c` and `csky-dis.c` touch `info->buffer` directly **[read]**, C-SKY writes to it, so binutils works on a private copy **[ran: test]** | none |
| Writes | text appended with a running bound into a 1,024-byte buffer; `text_len < cap` invariant **[read]**; no ASan report in 31 M fuzz executions **[ran, Linux]** | none |
| setjmp/longjmp | The jump target is the shim entry point; between it and any `longjmp` lie only C frames of binutils and the shim — every callback given to binutils is C (`bk_printf*`, `bk_read_memory`, `bk_memory_error`, binutils' own defaults) **[read]**. Locals live across `setjmp`: only `d` in `bk_gdis_create` (volatile) and `rc` in `destroy` (volatile); the rest are unchanged parameters **[read]**. binutils takes no locks; allocations in abandoned frames leak **[read]**. ASan intercepts `_longjmp`; the trap tests pass under ASan and UBSan **[ran, Linux]** | none |
| Half-updated statics after an abort | not provable in general: an abort can leave a target's statics mid-update | **new: quarantine** — after an abort the architecture family (archs sharing a `*-dis.c`: i386/iamcu, powerpc/rs6000, v850/v850_rh850, m68hc11/12/m9s12x/xg) is refused (`RawError::Quarantined`) for the rest of the process, and its data is leaked, not freed |
| The trap had never fired | two real `abort()` paths found and tested in child processes: a CGEN target with a machine BFD does not know (`m16c` arch, mach 0xdead → `bfd_lookup_arch` fails → `abort()` in `m32c-dis.c`), and `XTENSA_GNU_CONFIG` set (`_bfd_error_handler` + `abort()` in `bfd/xtensa-dynconfig.c`). Both return `Aborted` with binutils' message, quarantine the family, and the process goes on disassembling x86 and ARM **[ran, macOS and Linux, also under ASan and UBSan]**. No `assert()` was reached by any test or by fuzzing | `tests/trap.rs` |
| `-Dabort=…` | also renamed the C library's declaration in `<stdlib.h>` (dllimport under MSVC) | replaced by a forced-include prelude; `nm` shows no vendored object calls the real `abort`/`exit` **[ran, macOS]** |
| Locking | one mutex; `Request` holds it and is `!Send`; nested requests on one thread are refused, not deadlocked **[ran: test]** | none |
| **RISC-V bug (found)** | `disassemble_free_target` releases RISC-V's static extension list, which only `disassembler()` builds; the shim freed the previous request's data at every request but called `disassembler()` only when another disassembler had run in between: **every RISC-V request after the first decoded nothing (`.insn`)**; dropping one RISC-V disassembler during another's request did the same **[ran]** | fixed (`98acc66`): `disassembler()` every request (as gdis), RISC-V's per-request data freed without the shared list; regression test |
| **Option state leaking (suspected → confirmed)** | ARM `force-thumb`/register names/CDE, AArch64 aliases/notes, RISC-V names/aliases, C-SKY `abi-names` persisted into later disassemblers **[ran]**; ARC, LoongArch, VAX apply options once per process, RISC-V `priv-spec` too **[read]** | `bk_state.c`: default-restoring option prefixes, C-SKY flag reset, `OptionsConflict` for once-only targets. Test: 398 configurations (every family both byte orders, plus option variants), each alone in a fresh child process vs. all in one process forwards then backwards — identical **[ran, macOS, Linux]** |
| **CGEN descriptor cache (found by that test)** | binutils bug in 13 CGEN `*-dis.c`: the cache key ignores instruction byte order, and a switch back to a cached descriptor is not recorded; `m16c` big-endian after little-endian used the wrong descriptor **[ran]** | patch `0002` |
| **Sequence state across requests** | ARM IT/VPT, xgate instruction pairing (found by the property test), CRIS case tables live in statics not keyed to anything; the first instructions of a request could be read as continuing an unrelated earlier one, even another disassembler's **[ran]** | patches `0001`, `0003`; state now lasts one request (`block` call). Test over every architecture name and both byte orders: a block prints the same after unrelated requests ending where it starts — fails for xgate without the patch, passes with it **[ran]**; targeted CRIS test fails unpatched, passes patched **[ran]** |
| stderr | some targets `fprintf(stderr, …)` (C-SKY on unknown options, aarch64, arc, …) **[read, seen in fuzz logs]** | not trapped; cosmetic (gap) |
| `getenv` | `xtensa-dynconfig.c` reads the environment under our lock; Rust's `set_var` is `unsafe` (2024) and disallowed by clippy here | none |
| Leaks | binutils keeps small allocations by design (option copies, lazy tables) | not findings; fuzzing bounds RSS instead |

## 3. Sanitizers and fuzzing — what actually ran

All in a `rustlang/rust:nightly` container (Debian 13, **aarch64** Linux,
clang 19, rustc 1.102 nightly with LLVM 23), scripts in `target/linux/`
(scratch, not committed; the commands are in `fuzz/README.md`). Apple
clang's runtimes were not tried with Rust nightly's.

| Run | Result |
|---|---|
| Tests of `bk-binutils-sys` under **AddressSanitizer** (C with clang `-fsanitize=address`, Rust `-Zsanitizer=address`); C instrumentation checked with `nm` (547 objects with `__asan_report_load*`) | all pass, no report **[ran]**: 21 tests first, and the final code's 25 again at the end |
| Tests under **UndefinedBehaviorSanitizer** (clang runtime linked through `-C linker=clang`) | all pass; reports: `riscv-dis.c:170` and `csky-dis.c:274` "non-zero offset to null pointer" (`opt = opt_end + 1` once `opt_end` is NULL at loop end; never dereferenced) **[ran]** |
| Fuzz build: C with `-fsanitize=fuzzer-no-link,address,undefined`, memory-safety UB fatal (`bounds,null,vla-bound,return,unreachable,builtin`), the rest reported; checked with `nm` (`__sanitizer_cov_8bit_counters_init` in 203 objects — the others are data tables) | builds **[ran]** |
| Discovery: all architectures, 600 s, trapped aborts counted as findings | 1,397,103 executions, ~69 k edges, no crash, no ASan report, no abort **[ran]** |
| **60 s per family, all 90 families** (3 in parallel), aborts as findings, `-timeout=10`, `-rss_limit_mb=1024` | 90/90 exit 0, no artifact, 30.2 M executions (fewest: m32c 11 k, most: alpha 980 k); UB reported: the two above plus `tilepro-dis.c:199` "left shift of negative value" **[ran]** |

Conclusions: no memory error, hang or reachable abort/assert found from
bytes; the three UB sites are benign in practice and left unpatched
(reported). Not done: sanitizers or fuzzing on macOS, on x86_64 Linux, or
on Windows.

## 4. Platforms

| Platform | Status |
|---|---|
| macOS arm64 (Apple clang 17) | builds, all tests pass, gate green **[ran]** |
| Linux aarch64 (Debian 13; GCC 14 and clang 19) | builds, all tests pass, also under ASan and UBSan **[ran]** (container); rerun after the C23 fix with GCC 14 and with clang 19 under ASan **[ran]** |
| Linux aarch64, Ubuntu 26.04, GCC 15.2 (C23 default) | builds, all tests of both crates pass **[ran]** (container, after the fix) |
| Windows x86_64, `x86_64-pc-windows-gnu` (MinGW-w64 GCC 14) | **cross-compiled here, all tests pass under Wine 10.0** **[ran]** (emulated linux/amd64 container) |
| Windows x86_64, `x86_64-pc-windows-msvc` (clang-cl 19 + MSVC CRT/SDK via cargo-xwin) | **cross-compiled here, all tests pass under Wine 10.0** **[ran]** |
| Windows on a real machine: CI `windows-latest` (image windows-2025-vs2026), run 43456260254 | **both crates built and every test passed** (25, and 40 + 1 ignored; coverage skips without a Ghidra tree), compiled with clang-cl — inferred: no `CC` in the job, and build.rs stops with an error when `clang-cl` is not on `PATH` **[read from the CI log]**. MSVC's `cl.exe` is not supported (section 6) |
| Linux x86_64, Ubuntu 26.04, GCC 15.2 (what CI's `ubuntu-latest` now is) | **failed to compile in CI** before the fix (section 12); after it, builds and all tests of both crates pass **[ran]** (emulated linux/amd64 container, full suite in under 40 min) |

## 5. Tests (bk-binutils-sys 25, bk-gnu-disasm 44 + 1 ignored benchmark)

- `bk-binutils-sys`: `shim.rs` 15 (raw interface, bounds, RISC-V
  regression), `state.rs` 6 (options don't leak — 398 configs vs fresh
  processes; once-only conflicts; ARM IT per request; sequence state on
  every architecture; CRIS case tables; child entry), `trap.rs` 3 (two real
  aborts), `fuzz_regressions.rs` 1, build-script none.
- `bk-gnu-disasm`: unit 19 (`Long.decode` table, numeric names), `api.rs`
  15 (names, undecodable and truncated bytes, blocks, options, targets,
  MIPS/SPARC delay slots, IT context, window widening, threads, `Send`),
  `golden.rs` 2 (37 insta snapshots; with `BK_GNU_OBJDUMP` also compared
  with GNU objdump), `coverage.rs` 3, `properties.rs` 1 (2,000 cases over
  every architecture), `bench.rs` 1 ignored.
- Goldens: x86 16/32/64 AT&T and Intel, ARM, ARM BE, Thumb, AArch64, MIPS
  BE/LE/microMIPS, PowerPC 32/64/e500, RISC-V 32/64, SPARC v9b, m68k
  (+68020), AVR (2 machines), HPPA, LoongArch 32/64, m16c, m68hc12,
  m9s12x, MSP430, NDS32, SH4, V850 (2), Xtensa, Z80, iWMMXt. Expectations
  checked against **GNU objdump built from tag `binutils-2_41`** (it reports
  `2.40.90.20230730`), built out of tree from a `git archive` into
  `target/gnu-ref/` (`--with-system-zlib --without-zstd`, never inside the
  reference clone) **[ran]**: all 37 agree, allowing only two documented
  gdis/objdump differences (64-bit target printing on 32-bit targets; MIPS
  ISA bit kept by `-b binary`'s unknown flavour), with ARM-family names run
  as `-m arm` because gdis makes ARM ignore the machine.
- Ghidra JUnit tests: none exist for this feature (searched the checklist
  and Ghidra's tests).
- Ghidra-tree tests run with `BASILISK_GHIDRA_DIR` unset (skip with reason
  in this worktree), `=/Users/tatu/slop/ghidra`, and
  `=/Users/tatu/slop/basilisk/../ghidra` — all pass **[ran]**.

## 6. Windows (ADR-022)

**Result: the GNU disassembler builds and works for Windows x86_64 with
both toolchains, as far as can be shown without a Windows machine.**

Container: `target/windows/{Dockerfile,run.sh,dock.sh}` (scratch, not
committed): linux/amd64 Debian 13 under Docker's emulation on this Mac,
`rust:1.97.1-trixie`, `gcc-mingw-w64-x86-64` (GCC 14-win32), Wine 10.0,
clang/lld 19.1.7, `cargo-xwin 0.23.1` (ADR-011: 5.3 M downloads, the usual
tool for this; a developer tool only, no dependency of any crate). xwin
downloads Microsoft's CRT and Windows SDK into `target/windows/xwin-cache`;
that download is under Microsoft's licence terms, accepted by the tool on
the machine's behalf — the owner may want to know that this happened (only
local verification; nothing from it is committed or redistributed).

| Evidence | Result |
|---|---|
| `cargo build --target x86_64-pc-windows-gnu -p bk-binutils-sys` (MinGW GCC) | cross-compiled here **[ran]** |
| `cargo test --target x86_64-pc-windows-gnu -p bk-binutils-sys -p bk-gnu-disasm` under Wine | all pass: 25 + 44 (1 ignored benchmark), including the **abort-trap tests** (`longjmp` out of binutils works) and the child-process state tests **[ran]** |
| `cargo xwin build/test --target x86_64-pc-windows-msvc` (clang-cl, MSVC CRT `-MD`) under Wine | all pass, same counts, trap tests included (`longjmp` through the MSVC runtime, which unwinds with SEH, crosses only C frames) **[ran]** |
| Golden snapshots on both | all 37 identical byte for byte (`long` being 32-bit changes no output; binutils 2.41 uses `uint64_t`/`PRIx64` for `bfd_vma`) **[ran]**. Under Wine a cross-built `.exe` cannot run `cargo metadata`, so insta needs `INSTA_WORKSPACE_ROOT`; on real Windows it does not |
| A real Windows machine; CI's `windows-latest` | built and all tests passed in CI run 43456260254 (section 4) **[read from the CI log]** |
| `build.rs` choosing clang-cl by itself (no `CC` set) | not exercised here (cargo-xwin sets `CC_x86_64_pc_windows_msvc`); CI would exercise it |
| MSVC's `cl.exe` | not attempted (no `cl.exe` off Windows). Not supported, by evidence: clang `-std=c11 -pedantic` over the 302 units finds GNU case ranges (`aarch64-dis.c`, 5), arithmetic on `void *` (`elfxx-riscv.c`), zero-size arrays (`xtensa-modules.c`) and C23 empty initializers (`aarch64-opc-2.c`, 36) **[ran]**, which `cl` rejects [read: MSVC documentation knowledge, not tried] |

What the sources needed from Windows, all in the shim (binutils itself is
not patched for Windows):
- `stpcpy` (neither the UCRT nor MinGW-w64 has it): `shim/bk_compat.c`,
  declared in the prelude.
- MSVC CRT only (prelude, `#ifdef _MSC_VER`): `strcasecmp`/`strncasecmp` →
  `_stricmp`/`_strnicmp`; `<malloc.h>` for `alloca`; `ALMOST_STDC`, because
  `include/symcat.h` otherwise falls back to K&R token pasting when
  `__STDC__` is undefined (as in MSVC mode); `static_assert` renamed,
  because it is a keyword in MSVC mode and `mips-formats.h` names an array
  so; a `<strings.h>` (`shim/include-msvc/`, MSVC targets only) for
  `microblaze-dis.c`.
- `abort`/`exit` redirection by a forced-include prelude instead of
  `-Dabort=…`, which would have renamed the CRT's dllimport declaration.
- One `config.h` for all targets (`_WIN32` conditionals already there).
- `build.rs`: builds for every Unix-like or Windows target; for MSVC targets
  uses `clang-cl` unless `CC` names a compiler, and fails with an
  explanation if `clang-cl` is not on `PATH`.

**What this asks of a user's Windows machine** with the MSVC toolchain:
`clang-cl` on `PATH` (LLVM's installer, or Visual Studio's "C++ Clang tools
for Windows" component) besides the usual Visual Studio Build Tools. GitHub's
`windows-latest` image ships LLVM; whether `clang-cl` is on `PATH` there is
**not verified** — if the CI job fails with the build script's message, add
LLVM's `bin` to `PATH` in the workflow (proposal for the coordinator, who
owns `ci.yml`). The GNU toolchain needs MinGW-w64 GCC as usual.

## 7. Build time and size

See `docs/PERF.md` (macOS, loaded machine): clean dev build of
`bk-binutils-sys` 15.8 s at 2 jobs (20.1 s with C debug info), release
19.6 s; 0.2 s / 0.4 s after a Rust-only change; static library 18.6 MB
(40.2 MB with C debug info — **decision: no C debug info by default**).
Adds **13.4 MB** to a stripped fat-LTO binary. Throughput: x86-64 2.1 M,
AArch64 1.4 M instructions/s (`block`). The shared fuzz crate now compiles
binutils for every target's build: the instrumented fuzz build took 2 min
7 s on Linux (3 CPUs) **[ran]**.

## 8. Architectures and Ghidra's `gnu` names

All 65 distinct `external_name tool="gnu"` names (47 languages' first
names plus 18 further ones Ghidra ignores) resolve and decode with their
language's byte order and `.gdis` options **[ran]**. None fails. But
`0x18:0x5` (Hexagon) is **m9s12x** in binutils 2.41 — upstream binutils
has no Hexagon, so the number comes from another binutils; gdis built from
2.41 does the same. `tms320c3x`/`tms320c4x` are in `bfd_arch_list` but not
found by `bfd_scan_arch` (no Ghidra name uses them). Both `.gdis` files
parse.

## 9. Gaps

- MSVC's `cl.exe` not supported (clang-cl required for MSVC targets). The
  clang-cl version CI used is not in its log.
- Sanitizers and fuzzing ran only on Linux aarch64.
- Text truncation at 1,024 bytes is bounded by construction but never
  triggered by a test.
- binutils' writes to stderr are not captured.
- Three UB sites in binutils (section 3) reported, not patched.
- The `abort()` reachability claim rests on fuzzing (30 M executions, no
  abort) and on two known configuration-triggered paths, not on proof.

## 10. Follow-ups

- Wire `bk-lang`'s external names (`gnu`, `gdis.disassembler.options.file`)
  to `Architecture::from_gnu_name` and `gdis_config`; the listing field
  (M7) and the block script (M9) use `Disassembler::instruction_at` and
  `GdisConfig::{options_for, display_prefix_for}`.
- Hexagon's `0x18:0x5` should be dropped or marked unsupported in the
  language mapping.
- If fuzz build time matters for other targets, `bk-binutils-sys` could be
  an optional feature of the fuzz crate (every `cargo fuzz build` now
  compiles binutils: 2 min 7 s instrumented, Linux, 3 CPUs).
- CI: `clang-cl` was on `PATH` in `windows-latest` (the build succeeded);
  if a future image drops it, add LLVM's `bin` to `PATH` in the workflow.
- Proposed ADR: Windows builds of `bk-binutils-sys` need clang-cl, not
  `cl.exe` (section 6).

## 12. Fix after the merge: GCC 15 and C23 (2026-11-14)

CI run 43456260254 after the merge: `bk-binutils-sys` did not compile on
`ubuntu-latest`, failing in `opcodes/mips-formats.h` ("expected identifier
or '(' before 'static_assert'") for `micromips-opc.c`, `mips-opc.c` and
`mips16-opc.c`. Found by running, not reasoning:

- the runner image is **Ubuntu 26.04** (`ubuntu-26.04`, version
  20261111.196.1 in the job's setup log), not 24.04;
- its GCC is **15.2.0, which compiles C23 by default**
  (`__STDC_VERSION__ 202311L`), and in C23 `static_assert` is a keyword;
  `mips-formats.h` declares `typedef char static_assert[…]` as its
  compile-time check **[ran: ubuntu:26.04 container]**;
- the same compiler with `-std=gnu17` compiles the file with no error
  **[ran]**; Ubuntu 24.04's GCC 13.3 (default `gnu17`) compiles it unchanged
  **[ran, arm64]**; glibc's `<assert.h>` is not involved (those units do
  not include it; the shim's `assert.h` shadows it anyway) **[ran: -E]**;
- my earlier Linux runs used Debian 13's GCC 14 and clang 19, and macOS
  Apple clang 17, all defaulting to `gnu17`.

Fix (`3a8059c`, no change to the vendored tree): `build.rs` pins the
language standard for every compiler (`-std=gnu17`, `/std:c17` for
clang-cl), and the prelude renames `static_assert` for every compiler, not
only in MSVC mode. Verified after the fix **[ran]**: macOS; Ubuntu 26.04
GCC 15.2 on arm64 and on emulated amd64 (full test suites of both crates);
Debian 13 GCC 14; Debian 13 clang 19 under ASan.

## 11. Gate and commits

Full gate, as RULES.md says (`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log
2>&1; echo $?`, `BASILISK_GHIDRA_DIR` unset): exit 0, last lines
`bans ok, licenses ok, sources ok` and **`tests: 401 passed, 0 failed`**
**[ran, macOS]**. (The coverage tests skip there: no `../ghidra` beside
this worktree; they pass with the variable set to the tree, either spelling.)

`git log --oneline master..HEAD` lists this track's commits (and the two
merges of `master`); the branch is behind `master` and was not rebased.
