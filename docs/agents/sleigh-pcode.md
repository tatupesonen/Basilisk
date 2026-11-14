# Track `sleigh-pcode` — report

Branch `sleigh-pcode`, worktree `/Users/tatu/slop/basilisk-wt/sleigh-pcode`.
Spec: `docs/features/sleigh-pcode.md` (sections 8 and 9 filled in). Master
(Rust 1.100.0, 9a156d9) merged in on the coordinator's instruction. Nothing
pushed.

## Built

`crates/bk-sleigh`, part 2 of the SLEIGH runtime:

| Module | What |
|---|---|
| `emit` | `PcodeEmit` (borrowed inputs, never a directive); `PcodeCollector` (own arena), `PcodeCounter`, `PcodeRecords` (`pcodedump` `P` records), `write_record`, `write_varnode` |
| `pcode/mod.rs` | `Decoder::lift`, `lift_observed`, `lift_decoded` (lifts the instruction the last `decode` produced without decoding it again), `build_template` / `build_template_observed` with `InjectContext` (instruction, next and call addresses; `(operand, varnode)` parameters); `BuildObserver`, `BuildFeature` |
| `pcode/buffer` | `OpBuffer` (Ghidra `PcodeCacher`): ops and varnodes in two reused vectors, labels, label references, `resolve_relatives`, emission; `calc_mask` |
| `pcode/location` | `Walk` (Ghidra's walker as a value: handles from a parse node or from parameters, the addresses constants use, unique bits), `fix`, `fix_space`, `locate` (`generateLocation`), `pointer`, `is_dynamic` |
| `pcode/build` | `Builder`: `build`, `BUILD`, `buildEmpty` (implied builds), labels, `dump` (dynamic `LOAD`/`STORE`, truncation `INT_ADD` through `uniqbase+0x100`, relative branches) |
| `pcode/nested` | `DELAY_SLOT` (parses from the prepared run), `CROSSBUILD` (main or delay parse, else decoded on demand into a scratch parse handed down the recursion) |
| `pcode/error` | `LiftError` (Decode, DelaySlot, Unimplemented, Unaligned, MissingLabel, CrossBuildInSection, CrossBuildTarget, DelaySlotMissing, DirectiveInTemplate, TooManyVarnodes, Limit), `class()`, `flow_length()` |
| `dump` | `pcodedump`'s linear sweep and record format v1, `SweepObserver`, `write_header`, `write_trailer` |
| `translate` | `Translate` completed (`one_instruction`, registers, user ops, spaces, float formats, alignment, endianness, `unique_base`/`unique_start`, `set_context_default`, `allow_context_set`); `UniqueLayout`; `Language::unique_start` |

Part-1 changes in the same crate: `Parse::next2_error` (the next
instruction's decode error, raised when a template needs `inst_next2`, as
Ghidra's `getN2addr` throws it); `inst_next2` is computed when a template
uses it; handles are resolved last node first (Ghidra's order is kept for
reporting an error); precomputed main-template ids, varnode symbols and
space classes.

`crates/basilisk`: `src/cmd/disasm.rs` (`basilisk disasm`, spec 4.7, plus
`--sla-dir`); `main.rs` only registers it.

### Plugin binding constraints (`features/plugin-binding-constraints.md`)

* 1 (no lifetimes in held types): `Decoder`, `PcodeCollector`,
  `PcodeCounter`, `InjectContext`, `Translator` own their data;
  `PcodeEmit`'s borrowed `inputs` live only for the call; `PcodeRecords`
  borrows its output string (a writer, not a held result). Meets.
* 2 (`Send + Sync`): `Language` stays `Send + Sync`; `Decoder` is `Send`
  (per-thread worker); `PcodeCollector`/`InjectContext` are `Send + Sync`.
  Meets.
* 4 (typed errors): `LiftError` is a `thiserror` enum, `#[non_exhaustive]`,
  with the address and structured fields, `class()` and `flow_length()`; no
  panics on any input (proptest, fuzz). Meets.
* 6 (owned results): `PcodeCollector` gives owned ops (`CollectedOp`) and
  their inputs. Meets.
* 7 (monitor): lifting one instruction is bounded (65,536 ops, 512 levels);
  sweeps belong to `bk-disasm`. Not applicable.
* 3, 5, 8–10: program model, analysis, UI. Not applicable.

## Tests

All pass on macOS (Rust 1.100.0). bk-sleigh: unit 21; `pcode_units` 30
cases (22 functions, rstest); `pcode_properties` 2 (proptest, honours
`PROPTEST_CASES`, run at 20,000); `properties` 3; `pcode_fixture` 1 (+1
ignored recorder); `fixture_oracle` 1 (+1); `recorded` 2 (+1); `differential`
1 (+1 ignored full run); `decode_units` 6; `fuzz_regressions` 3;
`bench_heap` 1; benchmarks 3 ignored. basilisk: `disasm` 5.

* **Ghidra tests ported: none**, as the spec says (`PcodeEmitContextTest`,
  `PcodeEmitContextCrossBuildTest` belong to `sleigh-language`); no
  checklist line marked.
* **Differential, full run** (`every_language`, 186 s, three threads, every
  record compared: `I`, `E`, `P`, `U`, `T`): all 175 (`.sla`, `.pspec`)
  pairs, **no record differs from `pcodedump` outside the tolerated cases**.
  Coverage: root pairs 418,908 of 421,932 confirmed (99.28 %); constructors
  whose main template was built in a confirmed record 174,794 of 180,260
  (97.0 %; lowest x86-64 91.1 %, x86-32 93.2 %; every language ≥ 90 %
  except the two `DATA` languages, which have no template); op templates
  built 1,143,912 of 1,154,353 (99.1 %). Feature columns (languages whose
  `.sla` has the construct / languages where confirmed records built it):
  delay slots 36/36, crossbuild 1/1 (Hexagon, 43,468), named sections 1/1,
  relative branches 113/113, dynamic loads 100/101, stores 66/69 (the extra
  ones: constructs the harness did not see statically), truncated dynamic
  operands 7/7. The SPARC "load present, never built" is a harness
  over-estimate (`retea` with `i=1` exports a constant pointer), in
  `tests/data/coverage-exceptions.txt` with the `DATA` template entries. A
  feature-directed search (`tests/common/features.rs`) adds samples that
  reach constructs the directed samples miss; the oracle confirms them like
  any other. Table: `tests/snapshots/differential__coverage_table.snap`.
* **Tolerated differences** (counted per run): more than 20 operands 3,
  bytes past 15 1, `inst_next2` with commit 0, plus three new ones, each
  backed by a model of Ghidra in the harness:
  * **unset handle** 1,543 records in 18 languages: the template reads the
    handle of a subtable operand that exports nothing; Ghidra reads an
    uninitialised `FixedHandle` (stale data of an earlier parse), basilisk
    the constant 0. Tolerated only when the `I` line is equal.
  * **crossbuild target not cached** 1: Ghidra's 8-entry parse cache does
    not hold the target in the p-code state (modelled in
    `tests/common/cache.rs`); basilisk decodes it on demand.
  * **cache clobbered** 1 (Toy `harvard_rev`, `brdslt` with `skvs` in its
    delay slot): `skvs` uses `inst_next2`, whose look-up evicts the
    branch's own parse from Ghidra's 2-entry cache; Ghidra then builds the
    branch with the wrong parse (`BRANCH (unique,0xc00,1)`); basilisk
    builds the right one.
* **Oracle crashes**: 37 instructions (SPARC 32: 17, SPARC 64: 13, MIPS
  micro BE: 1 — `unimpl` in a delay slot; ARM v8-m LE: 5, BE: 1). The ARM
  v8-m ones are **a second Ghidra bug**, not reproduced by the crash
  research: their templates read the handle of an export-less subtable, and
  in a fresh parse slot that `FixedHandle` is zeroed, so `generateLocation`
  dereferences a null space. Exact cases (context `cond_mask=8 itmode=1`
  except the fourth, `itmode=1`; base 0, standalone `--hex` reproduces):
  `ARM:LE:32:v8-m` `79ee01df`, `35fe0c2f`, `71fe4def`, `45fe095f`,
  `73fe457f`; `ARM:BE:32:v8-m` `fe4baf03` (all `vpt…`). Test:
  `arm_v8m_oracle_crashes_read_unset_handles`. basilisk lifts all 37; the
  SPARC and MIPS reproducers of `docs/research/pcodedump-crashes.md` give
  "Instruction not implemented in pcode" with flow length 8 naming the
  delay-slot instruction at 0x00000004
  (`pcodedump_crash_reproducers_lift_without_a_crash`).
* **Reduced form in the gate** (`twelve_languages_one_sample_per_pair`,
  23 s): now compares every record, `P` and `U` included; no difference.
* **What runs in CI** (no Ghidra tree, no reference build):
  `pcode_fixture` — the `bkpc` language built in Rust
  (`tests/fixture/pcode.rs`: every opcode, dynamic loads and stores with
  and without truncation, a constant pointer, labels forward/backward and
  nested, a user op, delay slots of one and two instructions and a nested
  one, crossbuild of the previous instruction and of itself, implied
  section builds, `CROSSBUILD` in a section, a missing label, unique bits)
  replayed against `pcodedump`'s recorded output
  (`tests/data/pcode-fixture-oracle.txt`, 30,330 lines, 27 oracle crashes
  split out); `fixture_oracle` (bkfix); `disasm` tests against the same
  recording (byte equality of `basilisk disasm` output); `pcode_units`,
  `pcode_properties`, `properties`, `fuzz_regressions`, `bench_heap`, unit
  tests. The real-language recording `recorded.rs` (now with `P` records)
  and the AltiVec snapshot (now with basilisk's p-code) need Ghidra's files
  and skip in CI.
* **Fuzz** `bk_sleigh_lift` (fixture languages; reference languages with
  `BASILISK_REFERENCE_DIR`): 60 s, 1,941,879 runs, clean; `bk_sleigh_decode`
  now also lifts.
* Ran with both variables unset (oracle tests print SKIPPED and pass), with
  `/Users/tatu/slop/reference`, and part 1's non-canonical spelling check
  is unchanged.
* Gate: see the final message (run after the master merge).

## Benchmarks

`docs/PERF.md`, `bk-sleigh` (p-code). Commands there. Same-session numbers
(load average about 6–12):

| | basilisk | Ghidra C++ | |
|---|---:|---:|---|
| decode + lift, counting emitter | 1.61 M instr/s, 6.60 M ops/s | 1.60 M/s, 6.57 M ops/s | met (equal op counts: 608,674) |
| decode + text + lift | 1.38 M/s | 1.01 M/s | met |
| `basilisk disasm --quiet`, 778 kB | 0.190 s | `pcodedump --quiet` 0.201 s | met |
| full listing to a null device | 0.396 s | 0.714 s | met |
| allocations per instruction, lifting | 0 (bkpc, x86-64; 100,000 instructions) | — | met |

## Scaling (8 threads)

See `docs/PERF.md`; the machine never became quiet during the track (load
average 15–50 from other agents). Measured: decode 8 threads 3.8–4.7×,
decode + lift 4.7–5.7×, best at the lowest load. Lifting scales better than
decoding alone though it does strictly more work per instruction, and both
rise as the load falls; no shared state is written (the `Arc` clone per
lift was removed). With 6 performance and 2 efficiency cores, 6× needs the
efficiency cores at 100 % of a performance core; my reading is that the
shortfall is the machine and its load, not the code, but this was not
proven on an idle machine.

## Differences from Ghidra

`docs/features/sleigh-pcode.md` section 8 (spec's list plus appended):
unimplemented in delay slot/crossbuild is an error, not a crash; unset
handles read 0; no parse cache (delay slots from the prepared run,
`DelaySlotMissing`); `inst_next2` decode errors; crossbuild targets decoded
on demand have no `inst_next2`; `lift_decoded`; bounds; `BUILD` in a
free-standing template is a no-op.

## Gaps

* **8-thread scaling ≥ 6×** not shown (above).
* **`print_assembly`** keeps part 1's two-string form, not an emitter.
* **6.4 snapshots in CI**: impossible without Ghidra's files (ADR-002), as
  part 1 found; the `bkpc` recording is the CI check of p-code.
* **Template coverage** judged on main templates; named-section templates
  count in "op templates".

## Spec items found wrong or underspecified

* `LiftError` needs `DelaySlotMissing` ("Could not obtain cached delay slot
  instruction") and `DirectiveInTemplate`; `Unaligned` keeps
  `flow_length` `None` as `pcodedump` does (it prints the plain length).
* "None is expected in p-code" (6.2): three Ghidra behaviours make
  differences that are not basilisk's fault (unset handles, cache clobber,
  uncached crossbuild targets); the harness models Ghidra to recognise them
  and counts them.
* Feature columns: "the `.sla` contains the construct" cannot be decided
  exactly for dynamic loads/stores (it depends on which constructor a
  subtable picks at run time); the harness uses a conservative static test
  and the exceptions file.
* Module names of 5 (`op`, `labels`, `delay`, `crossbuild`, `inject`)
  became `build`, `buffer`, `nested`, `pcode/mod.rs`.
* The 778 kB sample was not in the repository: `build.sh` now builds it.

## Platforms

* macOS arm64: everything above.
* Windows: `cargo clippy -p bk-sleigh --all-targets --target
  x86_64-pc-windows-msvc -- -D warnings` and the same for `-p basilisk`
  clean. Wine: see the final message.
* Linux: rests on CI.

## Follow-ups

* Upstream Ghidra bugs: (1) the delay-slot/crossbuild walker (research
  doc); (2) uninitialised `FixedHandle` for export-less subtables read by a
  template (ARM v8-m crash, stale p-code elsewhere); (3) the 2-entry parse
  cache lets a delay slot's `inst_next2` look-up evict the instruction being
  built.
* No new third-party crate; `Cargo.lock` adds only workspace crates to
  `basilisk`'s and `bk-sleigh`'s dependency lists (`rstest` as a
  dev-dependency of `bk-sleigh`; `bk-pcode`, `bk-sla`, `bk-testkit`,
  `tempfile` dev-dependencies of `basilisk`); `check-dep-age.py master`: 0
  new registry packages.
* Known wishes unchanged: `bk-testkit` `Pcodedump` with a configurable root,
  `ReferenceDir::module_options()`; a registry helper over the reference
  directory (the CLI and tests both build one by hand).
* ADR candidate: "where Ghidra's p-code depends on its parse cache or on
  uninitialised memory, basilisk gives the result of a fresh parse; the
  differential harness models the cache to recognise those records."
