# Track toolchain-1.100 — status and report

Goal: make the gate green on Rust 1.100.0 (pinned in `rust-toolchain.toml`
on master by the owner). Pure formatting and lint fixes; no behaviour, API,
dependency or lint-configuration change.

## Status

- Done: every gate step on 1.100.0; fuzz crate; Miri script; Windows
  cross-clippy; Wine tests of the changed crates (see below).
- Gate: see "Gate result" at the end.

## What each step reported on 1.100.0 before the fixes

| Step | Result on master (900711d) with 1.100.0 |
|---|---|
| `scripts/check-file-size.sh` | ok |
| `scripts/check-unsafe.sh` | ok |
| `cargo fmt --all --check` | 6 diffs, all in `crates/bk-elf/src/constants/mod.rs` (`newtype!(…)` invocations: rustfmt now puts the trailing width argument on its own line) |
| clippy (`-D warnings`, all targets/features) | 52 errors from 4 lints, all new or extended in clippy 1.100: `assert_is_empty` 44, `float_cmp_const` 5, `chunks_exact_to_as_chunks` 2, `manual_bit_width` 1. No `unfulfilled_lint_expectations`: no existing `#[expect]` went stale. |
| rustdoc (`-D warnings`) | clean |
| `cargo deny --offline check licenses bans sources` | ok (the usual duplicate-crate warnings, unchanged) |
| tests | not run before the fixes (only lint changes were needed); after them: 1819 passed, 0 failed, 27 ignored, both with `BASILISK_GHIDRA_DIR`/`BASILISK_REFERENCE_DIR` set and with both unset |
| `scripts/miri.sh` | "no crates contain unsafe code; nothing to check" — it uses `+nightly`, so the pin does not affect it |

Cargo 1.100 also prints 8 new manifest warnings (not errors; the gate does
not fail on them; absent on 1.97.1): `unused workspace dependency` for
`anyhow`, `bk-decomp-types`, `bk-gnu-disasm`, `bk-sleigh`,
`bk-sleigh-compiler`, `memmap2`, `rayon`, and `unused field authors in
workspace.package`. Left alone (root `Cargo.toml` is shared with the
running tracks, which may start using those entries) — see "Decide at
project level".

## Changes, per lint and crate

1. `style(elf)`: `cargo fmt` — `crates/bk-elf/src/constants/mod.rs`.
2. `clippy::manual_bit_width` (1): `crates/bk-marshal/src/packed/encode.rs`,
   `u64::BITS - value.leading_zeros()` → `value.bit_width()` (same `u32`,
   0 for 0).
3. `clippy::chunks_exact_to_as_chunks` (2): `crates/bk-elf/src/version.rs`
   (`symbol_versions`: `as_chunks::<2>()`, which also drops the
   unreachable `_ => 0` arm; a trailing odd byte is still ignored) and
   `crates/bk-bin/tests/bench.rs`.
4. `clippy::float_cmp_const` (5): the lint now fires inside `assert_eq!`.
   `crates/bk-pcode/tests/java_floatformat_roundtrip.rs` (3) and
   `java_bigfloat.rs` (2) compare the smallest-subnormal constants
   exactly on purpose; they now compare `to_bits()`, as the same files
   already do for signed zeros (identical result for these finite,
   non-zero values).
5. `clippy::assert_is_empty` (44, all test code): `assert!(x.is_empty())` →
   `assert_eq!(x, [])`, `assert!(!x.is_empty())` → `assert_ne!(x, [])`;
   where the element type cannot be inferred (`String`, `PathBuf`,
   `QueryResult`), `Vec::<T>::new()`. Per crate: bk-lang 13,
   bk-sleigh-syntax 10, bk-testkit 5, bk-ui 4, bk-sla 3, bk-elf 3,
   bk-decomp-types 3, bk-bin 1, bk-binutils-sys 1, bk-gnu-disasm 1.

`#[expect]` added: none. `#[expect]` removed: none (none became
unfulfilled). Nothing in `[workspace.lints]`, `clippy.toml`,
`rustfmt.toml` or `Cargo.lock` changed.

**Crates of the running tracks:** `crates/bk-sleigh` and `crates/basilisk`
— not touched. `crates/bk-cspec` is not on master.

Every change still compiles on 1.97.1 (checked `bk-marshal`, `bk-elf` with
`cargo +1.97.1 check`; `bit_width` and `as_chunks` are older than 1.97),
so `rust-version = "1.97"` stays true and branches on 1.97.1 can merge
this.

## Verified where

- macOS arm64, 1.100.0: the whole gate (below); `cargo check --locked
  --manifest-path fuzz/Cargo.toml --bins` clean (the fuzz crate is not in
  the gate; `cargo fuzz` itself runs on nightly, unaffected);
  `scripts/miri.sh` (nothing to check).
- Windows, cross-checked from macOS: `cargo clippy --workspace --exclude
  bk-binutils-sys --exclude bk-gnu-disasm --all-targets --all-features
  --locked --target x86_64-pc-windows-msvc -- -D warnings` clean (includes
  `bk-ui` and `basilisk`). `bk-binutils-sys`/`bk-gnu-disasm` cannot be
  checked for MSVC here (the build script needs clang-cl for the vendored
  C).
- Windows under Wine: see "Wine" below.
- Linux: rests on CI.

## Other things the toolchain change touches

- `Cargo.toml` `rust-version = "1.97"`, edition 2024: unchanged and still
  accurate. Experiment (reverted): with `rust-version = "1.100"`, clippy's
  MSRV-gated `map_unwrap_or` reports 17 more sites (`map(_).
  unwrap_or_default()` → `map_or_default`, newer than 1.97): bk-ui 11,
  bk-sleigh-compiler 2, bk-binutils-sys, bk-decomp-types, bk-elf, bk-lang
  1 each.
- CI (`.github/workflows/ci.yml`): `rustup toolchain install` reads
  `rust-toolchain.toml`, so it picks up 1.100.0 by itself;
  `Swatinem/rust-cache` keys on the rustc version, so the first run on
  each OS is a cold build (the 45-minute job timeouts held before; watch
  the first Windows test job). The Miri job uses nightly (unchanged). The
  deny job uses `cargo-deny-action` (own toolchain; unaffected). The site
  job builds in a Node/Playwright image with no Rust: unaffected.
- `tools/*`: not built by CI; not checked.
- Dependencies: everything builds on 1.100.0; no dependency changes.
- Documents naming 1.97.1, all records of when something was measured or
  built, so left as they are: `docs/PERF.md` (lines 23, 55, 102, 107, 128,
  152, 223, 247, 298), `docs/PROGRESS.md` (56, 561),
  `crates/bk-elf/tests/fixtures/README.md:6`, `docs/agents/lang.md:97`,
  `bin-elf.md:61`, `gnu-disasm.md:21, 173`, `spec-plugin.md:167`,
  `spec-plugin-experiments/README.md:9`. `README.md` and `docs/LOOP.md` do
  not state the pinned version.
- The Wine image `bk-gnu-disasm-win` carries Rust 1.97.1 (`rust:1.97.1-
  trixie`); my copy of `run.sh` installs the pinned toolchain and the
  `x86_64-pc-windows-gnu` target at the start of each run (the container
  is `--rm`, so every run downloads it again). Rebuilding the image on
  `rust:1.100.0` would save that.

## Decide at project level

- `clippy::assert_is_empty` (44 sites here): I think it is right for this
  project (tests are where it fires, and a failing CI run now shows the
  unexpected contents). Its form for `Vec<String>` etc. needs
  `Vec::<T>::new()`; acceptable.
- `float_cmp_const` now also checks `assert_eq!`; test files that already
  allow `clippy::float_cmp` at file level do not cover it. Comparing
  `to_bits()` is the better fix for exact-value tests anyway.
- Cargo's new `unused workspace dependency` warnings (8): either remove the
  entries or use them via `workspace = true` in the crates; the
  coordinator should do this once the running tracks have merged (they
  may be the users of `bk-sleigh`, `bk-sleigh-compiler`, `rayon`,
  `memmap2`…).
- Whether to raise `rust-version` to 1.100 (17 `map_unwrap_or` sites, see
  above). Keeping 1.97 costs nothing today and lets old-toolchain branches
  build.

## Note for the running tracks (sleigh-pcode, decomp-cspec)

When you move your worktree to 1.100.0 (merge master): run `cargo fmt
--all` and `cargo clippy -p <your crates> --all-targets --all-features --
-D warnings`. Expect these new lints in your own code: `assert_is_empty`
(write `assert_eq!(x, [])` / `assert_ne!(x, [])`, or `Vec::<T>::new()`
when the element type cannot be inferred), `float_cmp_const` inside
`assert_eq!` (compare `to_bits()`), `chunks_exact_to_as_chunks` (use
`as_chunks::<N>()`), `manual_bit_width` (use `x.bit_width()`), and
rustfmt's new layout of macro invocations whose arguments are not plain
expressions. Nothing in this track touched `crates/bk-sleigh`,
`crates/basilisk` or `crates/bk-cspec`.

## Wine

(pending)

## Gate result

(pending)

## Commits

(pending)
