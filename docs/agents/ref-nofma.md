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
- Swap into `/Users/tatu/slop/reference` (waiting for the pre-swap
  workspace test run).

## State of `/Users/tatu/slop/reference`
SWAP IN PROGRESS (started 2026-11-14). Procedure: for each path in
`/Users/tatu/slop/reference.aarch64-fused/SWAP-MANIFEST` (281 paths,
relative to the reference root, `./STAMP` last), in order,
`mv -f /Users/tatu/slop/reference.staging/<p> /Users/tatu/slop/reference/<p>`.
Paths not in the manifest are byte-identical in both trees and are not
touched. To find where it stopped: a manifest path still present under
`reference.staging` was not moved yet. To finish: run the remaining
moves in order. To undo: the old 14 `.sla` and old `STAMP` are in
`/Users/tatu/slop/reference.aarch64-fused/` (same relative paths); the
old tools and objects are not kept — undo by rebuilding without the flag.
