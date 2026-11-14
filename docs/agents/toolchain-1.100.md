# Track toolchain-1.100 — status

Goal: make the gate green on Rust 1.100.0 (pinned in `rust-toolchain.toml`).

## Done
- rustfmt: 6 `newtype!(…)` invocations in `crates/bk-elf/src/constants/mod.rs`.
- clippy: `manual_bit_width` (1), `chunks_exact_to_as_chunks` (2),
  `float_cmp_const` (5), `assert_is_empty` (44) fixed; clippy clean.
- rustdoc `-D warnings`: clean, nothing to change.
- cargo-deny (licenses, bans, sources): ok, nothing to change.
- check-file-size, check-unsafe: ok.
- `scripts/miri.sh`: nothing to check (no crate marked `miri`); uses nightly,
  unaffected by the pin.
- Changed crates still compile on 1.97.1 (`bk-marshal`, `bk-elf`), so
  `rust-version = "1.97"` stays true.

## In progress
- tests (with and without BASILISK_GHIDRA_DIR / BASILISK_REFERENCE_DIR).

## Next
- fuzz crate check, Windows clippy cross-check, Wine tests, full gate, report.
