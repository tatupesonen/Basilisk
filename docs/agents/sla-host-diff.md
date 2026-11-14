# Track `sla-host-diff` — final report

Investigation: why Ghidra's C++ `sleigh` gives different `.sla` for 14 of
150 specifications on macOS AArch64 (clang/libc++) and Linux x86-64
(GCC/libstdc++). Branch `sla-host-diff`, worktree
`/Users/tatu/slop/basilisk-wt/sla-host-diff`. Findings, evidence and the
proposed ADR text: `docs/research/sla-host-dependence.md`. Nothing pushed
or merged; no crate, PLAN, PROGRESS, PARITY, DECISIONS, DIRECTION or
feature spec edited.

## Status

* Done: all six questions of the brief (below).
* In progress: nothing.
* Next (for the coordinator): accept the ADR-029 revision; apply the
  `sleigh-compiler-back.md` changes (research doc 6.3); ask
  `reference-tools` to add `-ffp-contract=off` to the reference build and
  rerun its tests; then start `sleigh-compiler-back`.

## Established, and how

1. **What differs** (measured, `tools/sla-host-diff`: `scan`, `classify`,
   `trees`): 14 differ / 136 identical confirmed. Only decision trees
   differ, in 1–2 tables per file, at 25 nodes in total where a different
   field is tested (e.g. TI_MSP430 `DEST_W_AD root/1/9`: bits 4..6 vs
   6..7); the subtrees below have a different shape but the same
   (constructor, pattern) set. Everything else — symbols and ids,
   constructors, operands, print, context, templates, other patterns — is
   identical. Not a renumbering or a reordering.
2. **Cause** (isolated by 14 builds, table in research doc §2):
   floating-point contraction of `sc -= p * log(p)`
   (`slghsymbol.cc:2135`, `DecisionNode::getScore`). AArch64 compilers
   emit `fmsub`; x86-64 without FMA rounds the product. macOS clang with
   `-ffp-contract=off` = x86-64 bytes for all 150; GCC on x86-64 with
   `-mfma` = macOS bytes; GCC/libstdc++ and clang/libc++ on Linux arm64 =
   macOS bytes; a one-line patch rounding the product (default flags) on
   macOS = x86-64 bytes. Standard library, `std::sort`, pointer order, OS:
   ruled out.
3. **Mechanism** (instrumented build `patches/trace-score.patch`): exactly
   25 nodes where fused and unfused arithmetic choose differently; in all
   25 the two fields have the same multiset of bin counts (equal entropy in
   exact arithmetic), scores 1–2 ulp apart, decided by the strict
   `sc > score` (`slghsymbol.cc:2172`, `:2189`).
4. **Behaviour**: identical. All 25 differing subtrees resolve every
   input to the same constructor (exhaustive over the constrained bits,
   up to 2^25 inputs, `equiv`); reference `pcodedump` gives byte-identical
   output with either variant on 2 MB random bytes per language plus all
   MSP430 first words.
5. **Java** (read and measured on installed releases): same algorithm;
   Java never contracts, so it agrees with x86-64 at all 25 nodes (11.4.2
   release and Homebrew 12.0 built on Apple silicon both do). But
   `Math.log` is host-dependent: at one ARM8 node the 11.4.2 release
   matches glibc and Homebrew's AArch64 build matches fdlibm.
6. **`log` matters as well** (one binary with run-time switches,
   `patches/score-config.patch`): unfused arithmetic with Apple's `log`,
   glibc's FMA or non-FMA `log` gives x86-64's 150 files; with fdlibm's
   `log` (the `libm` crate ADR-024 chose) ARM8_le and ARM8m_le differ.
   The `log`s disagree in the last bit on most arguments
   (`sla-host-dependence/logtables.txt`); glibc's own result depends on
   the CPU's FMA (ifunc) without changing the 150 files today.

## Not established

* No run on real x86-64 hardware; emulated `linux/amd64` reproduced the
  lent box's 150 files exactly (E3, E9). The confirming command for real
  hardware is in research doc §2.
* Java was not run (as instructed); Java conclusions rest on the source
  and on two installed releases whose sources differ slightly from the
  reference commit (pattern sets at the compared nodes checked equal).
* A correctly rounded `log` was not tried in the compiler (glibc is not
  correctly rounded on the domain, so it would not be guaranteed to
  reproduce x86-64).

## Proposed ADR revision

The ready-to-paste text replacing ADR-029 is in research doc §6.4. In
short: basilisk computes the score with unfused `f64` arithmetic in
Ghidra's order and a `log` bit-equal to glibc's (FMA variant) on every
`k/n` with n ≤ 16,384, verified by a checked-in table
(`docs/research/sla-host-dependence/logtable-glibc.txt.gz`); not
`libm::log`. Oracle: byte equality with x86-64 Linux for all 150, no
tolerated ties; the reference build gains `-ffp-contract=off` so every
host produces those bytes. ADR-024's `libm` bullet is replaced by a
pointer to ADR-029.

## Follow-ups

* `sleigh-compiler-back.md` changes: research doc §6.3 (4.3 floating
  point, a `log` table test, 6.2 oracle and removal of the admitted-tie
  class, 7, 8); `inventory/01-sleigh.md` 10(e)1 gains contraction.
* `reference-tools`: add `-ffp-contract=off` to `CXX_EXTRA_FLAGS` in
  `scripts/build-reference.sh`, rebuild, rerun unit/data tests.
  Reference `pcodedump` segfaults on random MIPS bytes (`mips32le`,
  2 MB seeded input from `scripts/pcodedump-compare.sh`), identically
  with both `.sla` variants — a robustness bug in the oracle tool or in
  Ghidra's MIPS decoding to look at.
* Docker: this track added the tag `bk-sla-host-diff/gcc14:arm64`
  (image `e750467579a2`) and pulled `alpine:3.22` (arm64) and an untagged
  amd64 alpine (`812e99317af7`); remove them when no longer needed. All
  containers were `--rm` and have exited.

## Built

* `tools/sla-host-diff/` — standalone Cargo project (own workspace and
  lock file; deps `bk-sla` by path and `libm =0.2.16`, already in the root
  lock): `scan`, `classify`, `diff`, `trees`, `equiv`, `node`,
  `maxpatterns`, `logtable`, `logdump`; README with every command.
* `tools/sla-host-diff/containers/`: `build-sleigh.sh` (build `sleigh`
  from a source copy with any compiler/flags/patches, compile specs),
  `run.sh` (bounded containers), `patches/` (`trace-score`,
  `unfused-getscore`, `score-config`), `logtable/` (`logtable.c`,
  `crlog.py`).
* `tools/sla-host-diff/scripts/pcodedump-compare.sh`.
* `docs/research/sla-host-dependence.md` and its evidence directory.

## Tests / gate

Research track: no crate changed, the tool is outside the workspace, so
the gate is unaffected and was not run.

## Commits

See `git log --oneline master..HEAD` (listed in the final message).
