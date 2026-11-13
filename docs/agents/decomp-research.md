# Track `decomp-research` — status report

Research track (no Rust code). Worktree `basilisk-wt/decomp-research`, branch
`decomp-research`. Brief: how basilisk's decompiler can be more accurate and
more readable than Ghidra's, with a plan the project can build from.

**State on 2026-11-13: in progress — see "Next" below.** This file is kept
current after every commit so another agent can continue from the files.

## 1. Deliverables

| Path | What | State |
|---|---|---|
| `docs/research/decompiler-quality.md` | The research document: conclusions, recommendations, weakness catalogue, survey, measurement plan, proposed ADR | Full draft committed (`ba6569f`); being revised |
| `docs/research/decompiler-quality/` | Experiment corpus and harness: `src/` (36 cases, 104 functions), `frag/` (fragments and console scripts fed to `decomp`), `out/` (Ghidra's output), `tools/` (`run.py`, `elf2frag.py`, `metrics.py`), `README.md` | Committed (`aa6f47e`, `f31dc0f`) |
| `docs/agents/decomp-research.md` | This report | Current |

## 2. Done

1. **Harness.** `tools/run.py` compiles each case with clang 20.1.8 (x86-64,
   x86, AArch64) and GCC 14.4.0 (AArch64, x86-64, in containers), links a
   small static ELF, converts it with `tools/elf2frag.py` to the
   `<binaryimage>` form of Ghidra's data tests, and runs the reference
   `decomp` console on it. 74 builds, 209 decompiled functions.
2. **Weakness catalogue** from those runs: 12 accuracy classes (A1–A12) and
   20 readability classes (R1–R20), each with source, Ghidra's output, the
   wanted output and the responsible Ghidra source file
   (`decompiler-quality.md` section 3).
3. **Survey** of structuring, type recovery, variables, idioms, naming,
   presentation and language models, with sources and a mark on every claim
   saying how it was verified (section 4).
4. **Recommendations** in priority order, staging and gating against the
   parity plan, and the design requirements for the M3 port (section 2).
5. **Measurement plan** and a working prototype of the cheap counters
   (`tools/metrics.py`) (section 5).

## 3. Experiments: commands and results

All from `docs/research/decompiler-quality/`. Needs `../reference` built
(`scripts/build-reference.sh`), Homebrew `llvm@20` and `lld@20`, Docker.

```sh
# The whole corpus (about 100 s). On this machine the two GCC images are
# named by id so that no image tag is moved (see "Machine notes").
BK_GCC_IMAGE_A64=e750467579a2 BK_GCC_IMAGE_X64=2534543d1c5c tools/run.py
tools/run.py a16_retval r02_loops        # named cases, output printed
tools/metrics.py                         # counters over out/
```

Result of `tools/metrics.py` over the checked-in output (209 functions,
2,695 body lines): 12 gotos, 424 casts, 29 `CONCAT`/`SUB`/carry artefacts,
63 `do … while`, 10 `for`, 13 `while`, 3 `switch`, 21 warnings, 83 raw
addresses, 2,520 automatic names, 320 declarations, 49 functions printed
`void` (25 of them not `void` in the source, of 174 non-`void` source
functions, excluding the two cases that supply prototypes).

Findings checked by hand beyond the corpus run:

| Check | Command (console script) | Result |
|---|---|---|
| The `void` results are not caused by decompiling twice | `load function inc` / `decompile` / `print C` once, for `inc`, `after_call`, `find_first` (x86-64 and AArch64), `bump`, `my_strlen`, `greet` | All still `void` |
| NaN terms are removed by default | `load function below`, `print raw` before and after `decompile`; then `option nanignore none`, `decompile`, `print C` on `frag/a13_float.x64-clang-O2.xml` | Lifted p-code has `CF = NAN(a) \|\| NAN(b) \|\| a f< b`; default output `param_1 < param_2`; with the option `(NAN(param_1) \|\| NAN(param_2)) \|\| param_1 < param_2` |
| A flow override is only read while flow is followed | `load function direct_tail`, `override flow r0x200122 callreturn`, `decompile` once against twice | Once: the callee's body is printed inline. Twice: `ext_i(param_1 + 1); return;` |

Sources re-opened by me to check the helpers' reports: SAILR's result tables,
D-LiFT's 93.2% figure and checker coverage, Binary Ninja's restructuring post,
VarBERT's overlap and accuracy figures, the DSN 2025 study's main finding,
TRex's abstract, DecompileBench's rates, and two figures of Dramko et al.
(85.9%, 76.1%). Everything else from the survey was read by a helper and is
marked `[S]` or `[S?]` in the document.

## 4. Mistakes made and corrected (so they are not repeated)

* **Jumps to another function were followed into it.** The bare console has
  no tail-call knowledge; a first run seemed to show calls "vanishing". Fixed
  by emitting `override flow … callreturn` for every unconditional jump to a
  function symbol (what Ghidra's `SharedReturnAnalyzer` does), and by
  decompiling twice because `load function` follows flow before the override
  exists.
* **A container tag changed platform under the harness.** Between two runs
  the local `gcc:14` tag moved from the arm64 image to the amd64 image (not by
  this track), and the "AArch64 GCC" outputs became x86-64 code decoded as
  AArch64. Commit `aa6f47e` contains those wrong outputs; `f31dc0f` replaces
  them. The runner now passes `--platform` and checks the ELF machine of every
  build.
* **A probe of mine moved that tag.** `docker run --platform linux/arm64
  gcc:14` pulled and re-pointed `gcc:14` at the arm64 image. I pointed the tag
  back at the amd64 image (`docker tag 2534543d1c5c gcc:14`), which is where
  it was just before the probe; both images remain present. Since then the
  harness uses image ids only.
* **A blocked removal.** An `rm` of the first smoke-test outputs was refused
  by the tool's safety check and was not retried; the smoke case was kept as
  the real case `t_smoke` instead.

## 5. Machine notes

* `gcc:14` currently points at the **amd64** image `2534543d1c5c`; the arm64
  image is `e750467579a2` (untagged). Another track appears to use the amd64
  one. Do not run `docker run --platform … gcc:14`: with the classic image
  store that pulls and moves the tag.
* No `timeout` command on this Mac; commands are bounded with the tool's
  timeout.
* Three helper subagents (web research) ran on 2026-11-12 before the owner's
  cap on workers; all finished then. None has been started since and none is
  running.

## 6. Next

1. Re-read the draft against the corpus numbers; mark any claim still
   unmarked.
2. Add to the document: a per-area table of what the port must decide at the
   start against what can follow parity; the split of the harness into gate
   and nightly runs; a proposed ADR in ready-to-paste form.
3. Final report.

## 7. Gaps

* No full Ghidra (Java) run: catalogue rows that depend on analysis outside
  the engine say so.
* No other decompiler was run on the corpus.
* x86-64 GCC covers seven cases only; no MSVC; C only.
* Nothing about run-time cost was measured.
