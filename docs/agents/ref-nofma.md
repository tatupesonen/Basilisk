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

- Workspace tests (`cargo test --workspace`, reference env set): before
  the swap 1,747 passed, 0 failed; after the swap 1,747 passed, 0 failed;
  the sorted per-test result lists are identical (no SKIPPED lines in
  either run).
- `docs/features/reference-tools.md` (step 4), `sleigh-compiler-back.md`
  and `inventory/01-sleigh.md` 10(e)1 (step 5).

- Step 6: `docs/research/pcodedump-crashes.md`.
- Step 7: Docker: removed tag `bk-sla-host-diff/gcc14:arm64`, image
  `alpine:3.22` (`062964a69725`) and the untagged alpine `812e99317af7`;
  no container used them. The image behind the removed tag
  (`e750467579a2`, the arm64 `gcc:14`, 1.49 GB) is still listed as
  `gcc:<none>`; it was not on the list, so it was left alone.

## Final report

**Done.** Gate: `CARGO_BUILD_JOBS=2 scripts/gate.sh` exit 0, last line
`tests: 1747 passed, 0 failed`.

**What the flag changed:** exactly the 14 `.sla` of ADR-029, which now
equal the x86-64 Linux files (all 150 compressed files `cmp`-identical to
`../reference-x86_64/x86_64-linux`). **What it did not change:** Ghidra's
unit and data-test logs (byte-identical; 204/205 and 758/760, the same
three failures: `double_decimal_precision`, `Float print #6`, `#13`);
`pcodedump` output on 1 MB of random bytes in 10 languages; `decomp`
console output (stdout, stderr, exit status) on all 93 data-test scripts;
Basilisk's workspace tests (1,747 passed before and after the swap, same
per-test list).

**Spec edits** (`sleigh-compiler-back.md`): 4.3 floating point now
specifies unfused `f64` arithmetic in Ghidra's order (never `mul_add`)
and a glibc-equal `log` (FMA variant) on `k/n`, 1 ≤ k < n ≤ 16,384, a
port of Arm optimized-routines' MIT-licensed `log`, with the ADR-011
evaluation left to the implementing track; 6.2's oracle is x86-64 byte
equality via `REF` with no tolerated differences, the admitted-tie class
and its tie file removed (the AArch64 comparison kept as a diagnostic);
6.4 gains a hand-made fused/unfused tie test and the oracle-free `log`
table test loading
`docs/research/sla-host-dependence/logtable-glibc.txt.gz` from the
repository; acceptance 1 and section 8 rewritten as research 6.3 says.
`inventory/01-sleigh.md` 10(e)1 names contraction. The front half's
terms (`Elaborated`, handle remapping after reordering) do not clash with
the spec, so nothing else was changed.

**Crashes:** one Ghidra bug for SPARC and the `mips32le` random input.
`SleighBuilder::delaySlot` points the builder at a walker on its own
stack (`sleigh.cc:364–365`). An `UnimplError` from the delay-slot
instruction (`semantics.cc:1045`) skips the restore at `:371`, so the
handler in `oneInstruction` dereferences the dangling walker
(`sleigh.cc:756–758`; confirmed in `lldb`). Reproducers:
`sparc:BE:32:default --hex 1080000081b80000`,
`MIPS:LE:32:default --hex 080000106ecac546`. ARM v8-m is not reproduced
and cannot be this mechanism (ARM has no `delayslot`). MIPS micro is
likely the same bug, not verified. Details in
`docs/research/pcodedump-crashes.md`.

**Follow-ups:**
- `tools/reference/README.md`'s table of Makefile overrides still lists
  `ADDITIONAL_FLAGS` without `-ffp-contract=off`. That file is not owned
  by this track.
- The 5 ARM v8-m crash cases need their bytes and configuration from
  `sleigh-decode`'s harness.
- ADR-032's "until it is rebuilt" clause and ADR-029's split oracle can
  now be closed: `../reference` gives the x86-64 bytes for all 150.
- `PERF.md` figures were not re-measured. The rebuild took 88 s clean
  with 3 jobs.

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
