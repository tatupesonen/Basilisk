# Track `cspec-host` — status report

Brief: make `bk-cspec`'s oracle table host-independent. Ghidra's own answers
differ between libc++ (macOS, clang) and libstdc++ (x86-64 Linux, g++);
find why row by row, define Basilisk's result, test against both tables.

## State

In progress.

- [ ] 1. Generator deterministic and robust (sorted pairs, stated heavy rule,
      merged-model `numgroup` defect avoided), 20/20 runs on both machines.
- [ ] 2. Both tables generated and diffed.
- [ ] 3. Every differing row traced to Ghidra source.
- [ ] 4. ADR text.
- [ ] 5. `bk-cspec` implementation and strict two-table replay.
- [ ] 6. Tests on both machines.
- [ ] 7. Gates.

## Notes as I go
