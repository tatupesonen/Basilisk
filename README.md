<p align="center"><img src="assets/brand/basilisk-logo.svg" alt="Basilisk" width="420"></p>

# Basilisk

A reimplementation of [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
in Rust: loaders, SLEIGH, p-code, analysis, the decompiler and an egui user
interface. It reads Ghidra's processor specifications unchanged, aims for
full parity with Ghidra, and improves on it where it can.

**Status:** just started. Nothing usable yet; see `docs/PROGRESS.md`.

## Documentation

| | |
|---|---|
| `docs/DIRECTION.md` | The owner's decisions: goal, scope, rules |
| `docs/PLAN.md` | Architecture, crate map, milestones |
| `docs/DECISIONS.md` | Architecture decision records |
| `docs/LOOP.md` | How development proceeds; engineering and testing rules |
| `docs/PROGRESS.md` | Where things stand now |
| `docs/PARITY.md` | Status against every Ghidra module |
| `docs/features/` | One document per feature |
| `docs/inventory/` | What Ghidra contains; `tests/` is the test-parity checklist |
| `docs/PERF.md` | Performance budgets and measurements |

## Building

```
cargo build
scripts/gate.sh > gate.log 2>&1; echo $?   # fmt, clippy, tests, file-size check
```

Tests that compare against Ghidra expect its source tree at `../ghidra`
(or `BASILISK_GHIDRA_DIR`) and skip themselves when it is absent.

## Licence

GPL-3.0-or-later (`LICENSE`). Basilisk is derived from Ghidra, whose
Apache-2.0 code is included as that licence permits; see `NOTICE` and
`LICENSE-APACHE`.
