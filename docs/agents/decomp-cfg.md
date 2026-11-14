# Track `decomp-cfg` — status report

D04 of `docs/features/decomp-plan.md`: crate `bk-decomp-cfg` (block graph,
analyses, structured hierarchy, structurer). Contract:
`docs/features/decomp-cfg.md`.

## State (kept current; continue from here)

- [x] Crate skeleton, every module of spec 5.4 (see "Built").
- [x] Port of every "In" item of spec 3 (graph surgery, analyses,
      hierarchy, structurer, XML codec, print tree).
- [x] First cross-check: `gen_graphs.py 1 3000 40` through the Mac
      reference's `structure blocks` — 3,000 of 3,000 byte-identical,
      the 161 `Could not finish collapsing block structure` included
      (scratch run, `tests/xml_dev.rs` with `BK_CFG_XC_DIR`).
- [x] Rust graph generator (`tests/support/graphgen.rs`, four classes).
- [x] 6.2 table `tests/data/structure_blocks.txt.gz` (4,000 graphs; Mac
      and build host byte-identical) and its replay test (all equal).
- [x] 6.1 unit tests, 6.5 properties, 6.6 fuzz targets, 6.7 benchmarks
      (PERF.md), spec sections 8–10 appended.
- [x] 6.3/6.4 oracle tests against the D00 formats (skip until
      `decomp_bk` exists; `tests/oracle/regen.sh`).
- [ ] Testbed checks (fuzz 300 s, Wine, arm64), both gates, report.
- [ ] When D00 lands: `git merge master`, switch test helpers to
      `bk-testkit`, run `tests/oracle/regen.sh` on both builds, corpus
      captures (6.3.2), host-difference classification.

## Notes for whoever continues

- Ghidra source read in full: `block.hh`, `block.cc`, `blockaction.hh`,
  `blockaction.cc` 20–1904.
- All builds/tests for gates through `scripts/remote.sh`.
