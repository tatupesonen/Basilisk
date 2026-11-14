# Track `testbed`: the build host as the project's testbed

Status: in progress (2026-11-14).

The Linux build host (`docs/agents/remote-build.md`) is also where the
checks that are slow or impossible on the development Mac run: Windows
tests under Wine, a newer distribution's GCC, sanitizers, Miri, fuzzing and
property tests at length, the full differential runs, and a nightly run
with a report. All of it is committed scripts under `tools/testbed/`,
started through `scripts/remote.sh`, which stays a thin dispatcher.

## Done / in progress / next

- Done: `remote.sh` plumbing (results copied back, `clean --target`,
  informative `cargo fetch`), `wine` (whole workspace passes), `long miri`,
  `long sanitizers`, `long fuzz` script.
- In progress: first runs of `long fuzz`, `long differential`,
  `long proptest`, `ubuntu`; nightly install and first run.
- Next: measurements into this file, final gates.

## Commands

All take the usual `--no-ref` right after the subcommand (the Ghidra tree
and reference tools are then not given to the job). Each sends the
committed `HEAD`, runs on the host in the branch's checkout, below normal
priority (`nice 10`), with a core budget (`BK_TESTBED_CORES`, default
**12** of 20) and a time bound (`BK_TESTBED_TIMEOUT`; default 5,400 s for
`wine`/`ubuntu`, 14,400 s for `long`). The log streams into
`<mode>-remote.log` in the worktree (git-ignored), its last 25 lines are
printed, and the results directory comes back to
`target/testbed/<date>-<mode>/` (`summary.txt`, `failures.txt`, logs, crash
inputs). Exit codes as for `gate`: the check's own (0 = everything passed),
2 no host, 75 branch busy, 124 time bound, 255 connection lost
(`scripts/remote.sh log` reattaches, writes the same local log and fetches
the results).

    scripts/remote.sh wine [--no-ref] [--msvc] [-- CARGO-TEST-ARGS]
    scripts/remote.sh ubuntu [--no-ref] [-- CARGO-TEST-ARGS]
    scripts/remote.sh long [--no-ref] miri
    scripts/remote.sh long fuzz [SECONDS [TARGET...]]      # default 600 s per target
    scripts/remote.sh long proptest [CASES]                # default 1,000,000
    scripts/remote.sh long sanitizers [asan|ubsan]
    scripts/remote.sh long differential [ITEM...]
    scripts/remote.sh long all
    scripts/remote.sh publish                              # local master -> the host's master
    scripts/remote.sh nightly install [CRON-SCHEDULE] | remove | run | status
    scripts/remote.sh report [--all | DATE]
    scripts/remote.sh clean --target BRANCH                # build output only

The scripts also run on any Linux x86-64 machine with Docker, clang 19
(with `libclang-rt-19-dev`), the pinned toolchain, nightly and cargo-fuzz,
from the root of a checkout: `tools/testbed/wine.sh`, `ubuntu.sh`,
`long.sh <what>`, `fuzz.sh`, `proptest.sh`, `sanitizers.sh`,
`differential.sh`. Each writes `summary.txt` and `failures.txt` to
`$BK_OUT` (default `target/testbed/out`); `lib.sh` documents the contract.

## Results on `master`'s content (493ae3f, 2026-11-14)

Measured on the build host (20-vCPU x86-64 Linux VM, Debian 13), 12-core
budget, while another agent was building there (load 12–22).

| Check | Result | Wall |
|---|---|---|
| `wine` (gnu, whole workspace, Ghidra tree mounted) | **2,036 passed, 0 failed, 33 ignored**; 31 tests print `SKIPPED` (reference tools: Unix-only, ADR-022) | 2 min 11 s warm image + cold build |
| `long miri` | no crate is marked `miri` in `unsafe-crates.txt`; nothing to run | 0 s |
| `long sanitizers` | ASan: 66 passed, 0 failed, 1 ignored, 189 binutils objects instrumented, no report. UBSan: 66 passed, 197 objects instrumented, 2 non-fatal report sites (known, below) | 1 min 26 s cold, 15 s warm |
| `long fuzz` (16 targets × 600 s, 12 at a time) | **no finding**; table below | 21 min 24 s (build 1 min 22 s) |

UBSan sites (both already reported by the gnu-disasm track; binutils code,
pointer arithmetic on NULL that is never dereferenced):
`vendor/binutils-2.41/opcodes/csky-dis.c:274:41` and
`vendor/binutils-2.41/opcodes/riscv-dis.c:170:42`, "applying non-zero
offset 1 to null pointer".

Fuzz table (first run, corpora empty except the checked-in regressions):

    target                               exit        execs      cov   corpus
    bk_binutils_sys_disassemble             0       900293    67545    21308
    bk_cspec_decode                         0     12504768     1941     1591
    bk_decomp_types_cdecl                   0      5548555     2132     1904
    bk_decomp_types_xml                     0     16573377     2071     1859
    bk_elf_parse                            0      3914260     2027     1225
    bk_lang_readers                         0      5439132     2049     2129
    bk_marshal_packed_decode                0      7184294     1387     2378
    bk_marshal_xml_decode                   0     18827429     2527     2900
    bk_sla_decode_packed                    0     18688436      852      723
    bk_sla_read                             0      4241804      804      519
    bk_sleigh_compiler_compile              0      2418681     7746     3153
    bk_sleigh_compiler_elaborate            0      1218417     8267     3395
    bk_sleigh_decode                        0      9814404     1656      482
    bk_sleigh_hostile_sla                   0     50964995      596      609
    bk_sleigh_lift                          0     13454604     1526      418
    bk_sleigh_syntax_parse                  0      1968684     3708     3686

The corpora persist on the host (`~/bk/testbed/fuzz/corpus/<target>`), so
each later run (the nightly one included) starts where the last ended.

### Wine and CI's `windows-latest`

`wine` builds for `x86_64-pc-windows-gnu` (MinGW-w64 GCC 14, Debian 13's
`gcc-mingw-w64`) and runs every test binary with Wine 10.0; `wine --msvc`
builds for `x86_64-pc-windows-msvc` with cargo-xwin (clang-cl 19, lld,
Microsoft's CRT and SDK). CI's job builds the MSVC target with Microsoft's
toolchain and runs on real Windows Server.

What it catches earlier than CI, in about 2 minutes, before a push: every
`cfg(windows)` compile error; separator, drive and verbatim-path
assumptions in tests (the three windows-ci failures were all reproduced
under Wine); C-library differences of the MinGW CRT (`round`); the C crates
built for Windows; Ghidra-dependent tests on Windows, which CI cannot run
(it has no Ghidra tree) — here the tree is mounted as `Z:\ghidra`.

What only CI shows: the MSVC linker and CRT of a real Visual Studio (the
`--msvc` build uses clang-cl and xwin's copy of the SDK), NTFS behaviour
(symbolic links need privileges; Wine's `symlink_dir` succeeds but the link
cannot be followed, so that test skips here), real `\\?\UNC\` paths,
Windows file locking and sharing modes, and anything Wine implements
differently from Windows (it is not a test of Windows itself). A Wine
failure that CI does not show is first suspected to be Wine's.

### Differential runs (`long differential`, 6 min 29 s for all four)

Found in the status reports: the only differential test still `#[ignore]`d
is bk-sleigh's `every_language` (sleigh-decode/sleigh-pcode: 131–186 s on
the Mac with three threads); the `regen`/`record_*` tests rewrite
checked-in data and are not checks; bk-sleigh-compiler's and bk-sla's
all-150 comparisons already run in every gate (with the reference set). The
one entry point therefore runs:

| Item | Result | Wall |
|---|---|---|
| `sleigh-every-language` (175 pairs, `BK_THREADS=12`) | **FAIL, snapshot only**: 0 record differences from pcodedump; the coverage-table snapshot differs in one row (below) | 33 s (+1 min release build) |
| `require-reference` (whole suite, release, `BASILISK_REQUIRE_REFERENCE=1`) | **2,030 passed, 0 failed, 33 ignored, 0 SKIPPED**: every differential test of the gate really ran | 3 min 48 s |
| `gnu-objdump` (bk-gnu-disasm goldens + GNU objdump 2.41 built from the GNU tarball, sha256 pinned, cached) | **2 passed**: all 37 goldens agree with objdump 2.41 | 58 s (first time incl. building binutils) |
| `cspec-oracle` (bk-cspec's generator rerun on Linux/libstdc++) | completed on the first try; 152,046 records, as checked in; 5,362 records differ each way (EFF 3,076, ASSIGN 2,976, Q 2,840, TRES 766, TSET 688, JOIN 228, SPLITQ 138, PAIR 12) | 57 s |

**Finding, bk-sleigh (not mine to fix): `every_language`'s coverage
snapshot is host-dependent.** `ARM:LE:32:v8-m` records `oracle-crashes 5`,
`tolerated …/145/0` (macOS, where it was recorded) but gives
`oracle-crashes 4`, `…/146/0` on Linux x86-64, the same in two runs. One
directed input crashes pcodedump (Ghidra's C++) on macOS and not on Linux;
the four that crash here are `79ee01df`@0x8, `71fe4def`@0x2 (`cond_mask` 8,
`itmode` 1), `45fe095f`@0x1c, `73fe457f`@0x2 (`itmode` 1). Because the
snapshot is asserted first, the record and threshold assertions after it
were not reached — the printed output shows no record difference. Suggested
fix: leave oracle-crash counts (and what they shift into "tolerated") out
of the snapshot, or assert them separately per host. Reproduce:
`scripts/remote.sh long differential sleigh-every-language` (the `.snap.new`
comes back under `target/testbed/<job>/snapshots/`). The oracle also
crashes on 13 random inputs for MIPS:BE:32:micro / sparc 32 and 64 here.

The cspec-oracle differences are those `docs/agents/remote-build.md`
already explains (pair order, the "heavy" pair per `.cspec` chosen by
readdir order, `std::sort` tie orders in libstdc++ against libc++); the
generator did not abort this time (it aborted in 3 of 4 runs there).

## Proposed text (not edited by this track)

For `docs/LOOP.md`, a subsection after "The build host":

> #### Testbed
>
> The build host is also the project's testbed: the checks that are slow or
> impossible on the Mac run there, through `scripts/remote.sh` (scripts in
> `tools/testbed/`, details in `docs/agents/testbed.md`). They take 12 of the
> 20 cores by default, run below normal priority, are bounded in time, and
> copy their results back to `target/testbed/`:
>
> - `wine [-- -p <crate>…]` — the tests built for `x86_64-pc-windows-gnu`
>   and run under Wine, with the Ghidra tree as `Z:\ghidra`. It catches
>   path, separator, C-library and `cfg(windows)` problems before CI;
>   CI's `windows-latest` job (MSVC, real Windows, NTFS links) stays the
>   final word. `wine --msvc` builds with cargo-xwin and clang-cl instead.
> - `ubuntu` — the crates that compile C and the reference tools with
>   Ubuntu 26.04's GCC 15.
> - `long miri|sanitizers|fuzz|proptest|differential|all` — Miri, ASan and
>   UBSan on the C-binding crates, every fuzz target for 10 minutes, the
>   property tests at 1,000,000 cases (where a suite leaves the count to
>   `PROPTEST_CASES`), and the full differential runs.
>
> A nightly run (the host user's crontab, 01:30 host time) tests the host's
> `master` — fed by `scripts/remote.sh sync` from a checkout on `master`, or
> `scripts/remote.sh publish` — with the gate, the Wine check and one
> rotating slot of the long runs, and writes one report per night;
> `scripts/remote.sh report` prints the latest, `report --all` lists them.
> The coordinator reads it each morning; a new failure there is a task.

For `docs/agents/RULES.md`, "Build hygiene", after the build-host bullet:

> - **Testbed checks before the final report.** Besides both gate runs: a
>   track that touches paths, files, processes, floating point, C code or
>   anything under `cfg(windows)` runs `scripts/remote.sh wine -- -p
>   <crate> …` for its crates and reports the counts; a track that adds or
>   changes a parser runs `scripts/remote.sh long fuzz 300 <its targets>`;
>   a track that changes C code or `build.rs` of a C-binding crate runs
>   `scripts/remote.sh long sanitizers` and `scripts/remote.sh ubuntu`; a
>   track with `unsafe` runs `scripts/remote.sh long miri`. The whole-
>   workspace Wine run, fuzzing at length, the million-case property tests
>   and the full differential runs belong to the nightly run; do not start
>   them yourself unless your brief says so.
