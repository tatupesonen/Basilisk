# Track toolchain-1.100 — status

Goal: make the gate green on Rust 1.100.0 (pinned in `rust-toolchain.toml`).

## Done
- rustfmt 1.100: `cargo fmt --all` reformatted 6 `newtype!(…)` invocations in
  `crates/bk-elf/src/constants/mod.rs` (trailing argument on its own line).

## In progress
- clippy (workspace, all targets, all features, `-D warnings`).

## Next
- rustdoc, cargo-deny, tests, unsafe/file-size checks, fuzz, Miri, Windows,
  docs naming 1.97.1.
