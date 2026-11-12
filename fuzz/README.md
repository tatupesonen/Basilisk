# Fuzzing

One `cargo fuzz` crate for the whole workspace. It is outside the Cargo
workspace (`exclude = ["fuzz"]` in the root manifest) because fuzzing needs
a nightly toolchain and sanitizer flags.

| | |
|---|---|
| Add a target | `fuzz_targets/<crate>_<what>.rs` (for example `elf_parse.rs` → `bk_elf_parse.rs`), plus the crate under `[dependencies]` and a `[[bin]]` entry in `Cargo.toml`, alphabetically |
| List targets | `cargo +nightly fuzz list` (from the repository root) |
| Run one | `cargo +nightly fuzz run <target> -- -max_total_time=60` |
| Run all briefly | `scripts/fuzz-smoke.sh [seconds-per-target]` |
| A crash | fix it, save the input as `fuzz/regressions/<target>/<short-name>`, and add a normal test in the crate that replays every file in that directory |

`corpus/`, `artifacts/` and `target/` are git-ignored. `Cargo.lock` is
committed; when two branches both change it, do not merge it by hand — the
coordinator regenerates it.
