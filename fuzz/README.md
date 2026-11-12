# Fuzz targets

One `cargo-fuzz` crate, `bk-fuzz`, holds the fuzz targets of every crate
(docs/LOOP.md, Testing rules: every parser of untrusted bytes has one). It
is not a workspace member — it needs nightly Rust and libFuzzer — and has
its own `[workspace]` table and `Cargo.lock`.

## Running

    scripts/fuzz.sh                    # every target, 60 s each
    scripts/fuzz.sh -t 300 xml_decode  # one target, 5 min
    cargo +nightly fuzz run <target>   # by hand, from the repository root

`scripts/fuzz.sh` seeds each run from `seeds/<target>/` and
`regressions/<target>/`, keeps the growing corpus in `corpus/<target>/`
(git-ignored), writes the libFuzzer log to `artifacts/<target>.log` and
prints one line per target with the time, run count and result. Record the
line in your status report.

## Layout and conventions

| Path | What | Owner |
|---|---|---|
| `Cargo.toml` | the fixed header, then one block per track: its `[dependencies]` lines and `[[bin]]` entries | shared, append-only |
| `fuzz_targets/<target>.rs` | a thin entry: `fuzz_target!(\|data\| <track>::<target>(data))` | the track |
| `fuzz_targets/<track>/mod.rs` | the target bodies of one track, using only the crates under test (no `libfuzzer-sys`) | the track |
| `seeds/<target>/` | small checked-in seed inputs (optional; never copies of Ghidra's spec files, ADR-002 — point at `../ghidra` at run time instead) | the track |
| `regressions/<target>/` | every input that once crashed, kept after the fix | the track |
| `corpus/`, `artifacts/`, `target/`, `coverage/` | generated, git-ignored | — |

- **Target names** are what the feature spec names them (`packed_decode`,
  `elf_parse`, …); otherwise `<area>_<what>`.
- **Regressions are replayed by a normal test** in the owning crate, which
  includes the track module with
  `#[path = "../../../fuzz/fuzz_targets/<track>/mod.rs"] mod <track>;` and
  runs each file of `regressions/<target>/` through the same function the
  target calls, so the gate keeps fixed crashes fixed. Example:
  `crates/bk-core/tests/fuzz_regressions.rs`.
- **Merging two tracks' `fuzz/` directories**: keep the header once, take
  the union of the `[dependencies]` lines and `[[bin]]` blocks, and
  regenerate `Cargo.lock` with `cargo +nightly fuzz build`.
- Crates whose `unsafe` calls C (`unsafe-crates.txt`, `no-miri`) run their
  targets under AddressSanitizer, which `cargo fuzz` enables by default.

## Targets

| Target | Track | Crates | What it does |
|---|---|---|---|
| `packed_decode` | core-marshal | `bk-marshal`, `bk-core` | packed decoder: a random walk of decoder calls chosen by the input's leading bytes, a full walk of the document, and the address-model decoders (varnode, address, seqnum, range, range list, truncation, space, `<spaces>`) |
| `xml_decode` | core-marshal | `bk-marshal`, `bk-core` | the same over the XML parser and decoder, for input that is UTF-8 |
