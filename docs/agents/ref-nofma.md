# Track `ref-nofma` — status

Reference build with `-ffp-contract=off` (ADR-032).

## Done
- `scripts/build-reference.sh`: `-ffp-contract=off` on every compile
  (Makefile `ADDITIONAL_FLAGS`, `pcodedump`, zlib), recorded in `STAMP`
  (`fp_flags`, `zlib_cflags`, `make_overrides`). No new option was needed:
  `BASILISK_REFERENCE_DIR` already chooses the output directory.
- Staging build: `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference.staging
  CXX=g++ scripts/build-reference.sh --jobs 3`, clean, 88 s wall.
- Verification of the staging build (all passed):
  - `.sla`: all 150 compressed files byte-identical (`cmp`) to
    `/Users/tatu/slop/reference-x86_64/x86_64-linux/`; against the old
    `../reference` exactly the 14 of ADR-029 changed, 136 identical.
  - Ghidra's tests: 204/205 unit, 758/760 data, same three failures as
    before (`double_decimal_precision`, `Float print #6`, `#13`);
    `logs/unittests.log` and `logs/datatests.log` byte-identical to the
    old build's. The flag changed no test result.
  - `pcodedump`: 10 languages × 1,000,000 seeded random bytes
    (x86-64, x86, AARCH64 v8A, AARCH64 AppleSilicon, ARM v8 LE,
    TI_MSP430, PowerPC LE 64, tricore, 6502, MIPS LE 32), old tool on old
    root vs new tool on new root: identical output for all 10.
  - `decomp` console: all 93 data tests' scripts run on their images,
    old vs new: stdout, stderr and exit status identical for all 93.

## In progress
- Post-swap workspace test run (pre-swap: 1,747 tests passed, 0 failed,
  log `target/ref-nofma/test-before.log`).

## State of `/Users/tatu/slop/reference`
SWAP COMPLETE (2026-11-14). The live tree is the `-ffp-contract=off`
build: 281 files replaced by `mv -f` from the staging build, in the order
of `/Users/tatu/slop/reference.aarch64-fused/SWAP-MANIFEST` (`STAMP`
last), no failure; the other 1,702 files were byte-identical and not
touched. Checked afterwards: every file equals the staging build; all 150
`.sla` equal x86-64 Linux's; a run of the script on a copy of the tree
does nothing ("nothing to do"), so its build state is consistent. The
staging directory is removed. Old files kept for the record:
`/Users/tatu/slop/reference.aarch64-fused/` (the 14 fused-variant `.sla`
at their relative paths, the old `STAMP`, and `SWAP-MANIFEST`).
