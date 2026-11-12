# Crate evaluation experiment for the ELF parser (track `bin-elf`)

A throwaway program, kept so the experiment behind the evaluation in
`docs/agents/bin-elf.md` can be rerun. It is **not** part of the workspace
(it has its own `[workspace]` table) and the gate does not build it.

It takes one little-endian 64-bit ELF shared object, damages copies of it in
eleven ways that Ghidra's `ElfHeader` tolerates, and prints what
`object` 0.40.0 (low-level `read::elf` API and the high-level `File`) and
`goblin` 0.10.7 (strict and permissive) make of each.

```text
cd docs/agents/bin-elf-crate-eval
CARGO_BUILD_JOBS=2 cargo run --release -- \
    "$BASILISK_GHIDRA_DIR/GhidraDocs/GhidraClass/ExerciseFiles/Advanced/override.so"
```

Use a `--target-dir` outside the repository (or delete `target/` and
`Cargo.lock` afterwards) so nothing is left behind. The output of the run on
2026-11-12 is reproduced in `docs/agents/bin-elf.md`.
