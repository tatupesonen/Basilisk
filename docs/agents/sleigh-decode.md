# Track `sleigh-decode` — final report

Branch `sleigh-decode`, worktree `/Users/tatu/slop/basilisk-wt/sleigh-decode`.
Crate `crates/bk-sleigh` (new). Spec: `docs/features/sleigh-decode.md`
(sections 8 and 9 filled in). Nothing pushed, nothing merged.

## Built

`crates/bk-sleigh` — the SLEIGH runtime, part 1.

| Module | What |
|---|---|
| `language/{mod,load,registers,setup,tables}` | `Language`: `from_sla(Arc<Sla>)`, `load(&LanguageRegistry, &LanguageId)` (`.sla`, `<truncate_space>`, `.pspec` `<context_data>`), `truncate_space`, `apply_processor_spec`; spaces with the register table installed; `RegisterTable` (`RegisterLookup`, Ghidra's ordering with larger sizes first and the `getRegisterName` quirk); user ops; context variables in name order; `initial_context`, `empty_context`, `set_context_everywhere`; alignment, `unique_base`, `unique_mask`, `max_delay`, `num_sections`, float formats, `has_semantics`. Per-constructor and per-operand tables (operand placement, definitions, `checkTableFill`, flow-through, delay) |
| `context/{mod,db,partmap,tracked}` | `ContextDb` (port of `ContextInternal`: default, split points with value and explicitly-set mask, `change_point`, `region`, by-variable forms, `get_with_range`, tracked sets and `tracked_value`, change counter); traits `ContextSource`, `ContextSink`; `ContextVar`; `OffsetRange` |
| `decode/{mod,bytes,tree,expr,decision,resolve,handles,commit}` | `Decoder` (per thread, reuses its buffers): `decode`, `resolve_handles`, `apply_commits`, `prepare` (alignment, decode, handles, commits, delay slots, flow length), `disassemble` (owned text), `set_operand_limit`; `ByteSource` + `SliceBytes`; `Parse` (nodes as contiguous child runs, `FixedHandle`, commits, local context, `reads_past_window`, `max_operands`); decision walk, pattern matching, expression evaluation, handle templates, commits |
| `print` | `Language::mnemonic`, `Language::body` (Ghidra's `printMnemonic`/`printBody`, flow-through, `0x`/`-0x` numbers) |
| `error` | `DecodeError` (Ghidra's texts, `address()`, `class()`), `LoadError`, `RawText`, `Limit`, `TableKind` |
| `translate` | `trait Translate` (`instruction_length`, `print_assembly`) and `Translator<B>` (language + context + bytes); p-code is part 2 |

Seams for `sleigh-pcode`: `Decoder::prepare` leaves the main and delay-slot
parses (`parse()`, `delay_slots()`) with handles resolved and `next_address`
moved past the delay slots; `Parse::nodes()`/`Node::handle()`/`child()`;
`Language::has_semantics`; `ConstTpl` resolution helpers live in
`decode/handles.rs` (`fix_const`, `fix_space`) and can be made `pub(crate)`
for the builder; `Translate` gets `one_instruction`.

### Plugin binding constraints (`features/plugin-binding-constraints.md`)

* 1 (no lifetimes in held types): `Language` is shared as `Arc<Language>`;
  `Decoder` owns everything; `Decoder::disassemble` returns an owned
  `Disassembly`; `Parse` is a borrowed view of the decoder's buffers for the
  hot path, not the only way in. Meets.
* 2 (`Send + Sync`): `Language`, `ContextDb` asserted `Send + Sync`;
  `Decoder` is `Send` (it holds a `Cell` flag, so not `Sync` — a per-thread
  worker). Meets.
* 4 (typed errors): `DecodeError` and `LoadError` are `thiserror` enums,
  `#[non_exhaustive]`, with structured fields (address, path, name) and no
  panics. Meets.
* 6 (owned results): `Disassembly` is owned; the language data a result
  needs is reachable through `Arc<Language>`. Meets.
* 7 (monitor): decoding one instruction is bounded (depth, node and
  expression limits); a long sweep belongs to `bk-disasm` (M5), which takes
  the monitor. Not applicable here.
* 3, 5, 8–10 concern the program model, analysis and UI; not applicable.

## Tests

Counts (all pass): 18 unit tests in the library; integration:
`decode_units` 6, `properties` 3 (one a 2,000-case proptest),
`fixture_oracle` 1 (+1 ignored recorder), `recorded` 2 (+1 ignored
recorder), `differential` 1 (+1 ignored full run), `bench_heap` 1,
`fuzz_regressions` 2, `bench` (1 ignored).

* **Ghidra tests ported: none** — the spec states no C++ unit test targets
  the SLEIGH runtime and the decompiler data tests belong to `bk-decomp`;
  no checklist line was marked.
* **Differential, full run** (`every_language`, ignored; 131 s with three
  threads): every one of the 175 distinct (`.sla`, `.pspec`) pairs the
  registry names and `pcodedump` can run; eight directed samples per root
  leaf pair plus a coverage search (300,000 Basilisk-side fillings per
  language), 64 kB of random bytes, and the `.text` of the `bk-elf` ELF
  fixtures (x86-64, i686, AArch64 LE/BE, ARM LE/BE also as Thumb). Result:
  **no record differs from `pcodedump`**. Coverage: 419,098 of 421,932 root
  pairs confirmed (**99.33 %**), 177,946 of 183,115 constructors exercised
  (97.2 %); every language ≥ 95 % of pairs and ≥ 90 % of constructors except
  `DATA:BE:64:default` and `DATA:LE:64:default` (one constructor of length
  0: both sides report "instruction has no length"), which are in
  `tests/data/coverage-exceptions.txt`. Lowest others: x86:LE:64:default
  (pairs and constructors just above the thresholds after prefix nesting),
  ARM v8-m/v8T. Table: `tests/snapshots/differential__coverage_table.snap`.
  Tolerated differences: 3 × more than 20 operands (PowerPC; the harness
  fails as Ghidra does, see below), 1 × bytes past index 15 (68000), 0 ×
  `inst_next2` with commit.
* **Languages where Basilisk and `pcodedump` disagree**: none outside the
  tolerated cases. Ghidra's engine **crashes** (SIGSEGV) 36 times in the
  random sweeps — SPARC 32 (12) and 64 (18), ARM v8-m LE (4) and BE (1),
  MIPS micro BE (1): when a delay-slot instruction has an `unimpl` body,
  `oneInstruction`'s error path uses a walker that no longer exists. The
  harness locates the instruction by bisection and splits the stream there
  (both sides restart their context); the recorders do the same.
* **Reduced form in the gate** (`twelve_languages_one_sample_per_pair`, 24 s
  with the reference tools; skips without them): x86 32/64, ARM v8 LE,
  AARCH64, MIPS32 BE, PowerPC 32 BE, SPARC, 68000, AVR8, RISC-V 64, Hexagon,
  Toy BE; no difference.
* **Runs everywhere** (no oracle, no Ghidra files): `fixture_oracle` replays
  `pcodedump`'s recorded output (`tests/data/fixture-oracle.txt`, 285 kB,
  provenance in its header) for **`bkfix`, a language built in Rust with
  `SlaBuilder`** (`tests/fixture/mod.rs`: varnode lists, value maps and name
  tables with unusable entries, signed values, an `inst_start` expression,
  flowing and noflow commits, a context-dependent combined pattern, an
  operand placed after a sub-table, flow-through printing, delay slots
  including a delay slot holding another, 21 operands, a little-endian field,
  `unimpl`, alignment 2) — Ghidra's C++ loads the `.sla` our writer
  produces. Also `decode_units`, `properties` (proptest, 8-thread
  agreement), `bench_heap`, `fuzz_regressions`, all unit tests.
* **Recorded real languages** (`recorded.rs`, `tests/data/recorded-oracle.txt`):
  Toy directed samples (536 instructions), 200 instructions of x86-64,
  ARM with a `blx` into Thumb then 190 Thumb instructions, MIPS with delay
  slots (a branch in a delay slot, a likely branch) and random words. The
  replay needs the languages' `.sla`/`.ldefs`/`.pspec`, which are Ghidra's
  files (ADR-002: not copied into the repository), so **it is skipped in CI**;
  the `bkfix` replay is the check that runs there. AltiVec: Basilisk-only
  snapshot `tests/snapshots/recorded__altivec.snap` (`vadduhm`, `vsubuhm`,
  27 operands; with `set_operand_limit(Some(20))` the decoder gives Ghidra's
  error).
* Ran with both variables unset (every reference test prints `SKIPPED` and
  passes), with `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`, and with
  `/Users/tatu/slop/basilisk-wt/../reference` (pass).
* **Fuzz** (`fuzz/fuzz_targets/bk_sleigh_decode.rs`,
  `bk_sleigh_hostile_sla.rs`, shared body `bk_sleigh_shared/mod.rs`, replayed
  by `tests/fuzz_regressions.rs`): 60 s each, clean — 2,109,703 runs (the
  fixture plus seven reference languages via `BASILISK_REFERENCE_DIR`) and
  374,008 runs (seeded with the six smallest inflated reference streams).
* Gate: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` printed 0; last line `tests: 1742 passed, 0 failed` (macOS arm64, 2026-11-14).

## Benchmarks

Commands and table in `docs/PERF.md` (`bk-sleigh`). Same session, loaded
machine: `Language::load` x86-64 20.3 ms (reference 32.2 ms); decode only
3.25 M instructions/s (reference 3.17 M/s); decode + text 2.41 M/s
(reference 1.50 M/s); 0 allocations per instruction over 100,000
instructions; 8 threads 4.78× one thread (2: 1.98×, 4: 3.60×) — below the
6× target. The machine had load average 10–15 from other agents, and an M1
Pro's 8 cores are 6 performance + 2 efficiency cores, so 6× is at the limit
of the hardware even when idle; re-measure on an idle machine.

## Differences from Ghidra

Listed in `docs/features/sleigh-decode.md` section 8 (spec's list plus the
appended ones): flat error enum with `class()`; unset handles are constant
0; out-of-band operand evaluation at the current position where Ghidra's
walker is uninitialised; `inst_next` while resolving is the instruction's
address; context words past the array read zero, context-op shifts modulo
32; negative index into a filled table and unusable varnode-list entry at
print time are `NoTableEntry`; `inst_next2` look-ahead timing and error;
`set_operand_limit` option; bounded delay-slot loop; unmasked OR in the
word-level context sets as in Ghidra.

## Gaps

* **8-thread scaling 4.78× < 6×** on this loaded machine (above).
* **The `T` record** is compared as (instruction count, error count without
  `U` records): `U` records come from p-code generation (part 2). Flow length
  is predicted, including the case where Ghidra's builder fails because a
  delay-slot instruction has its own delay slot that `prepare` did not
  decode ("Could not obtain cached delay slot instruction").
* **Real-language recordings do not run in CI** (they need Ghidra's files);
  the self-contained `bkfix` recording does.
* Linux and the Windows CI job were not run by me (see Platforms).

## Spec items found wrong or underspecified

* **Stream cutting**: "cut after a sample whose parse committed context, at
  most 200 invocations" leaves ARM Thumb at 83 % of pairs (most samples
  commit; after the cap later samples decode in a changed context).
  Implemented: a stream is cut when the next sample no longer decodes to its
  target in the context the stream has reached, or when the previous
  instruction reads bytes past its length that the next sample would change
  (Toy `builder`'s little-endian `nop`); samples that do not decode to their
  target are dropped; cap 1,000 invocations (the full run takes 131 s).
* **Tolerated difference 1** by resynchronisation produced false failures:
  after the oracle's 1-byte error the sweeps take different instruction
  boundaries and meet again with different context. Implemented instead
  with `Decoder::set_operand_limit(Some(20))` in the harness, so both sweeps
  fail identically and stay in step; Basilisk's decoding of those
  constructors is checked by the `over-20` count and the AltiVec snapshot.
* **Pairs reachable only through a context set inside the instruction**
  (x86 VEX/EVEX/REX prefixes set context and re-enter the root table): a
  `--context` configuration cannot express them. Implemented: such pairs
  are also sampled behind a prefix constructor that re-enters the root
  table, which lifted x86-64 from 91 % to above 95 %.
* **"Every language"**: the registry has 175 distinct (`.sla`, `.pspec`)
  pairs; RISC-V's `old/` language definitions name a `.sla` that is not
  beside their `.ldefs`, which `pcodedump` requires (Ghidra searches every
  language directory), so they are excluded — their `.sla` files are the
  current RISC-V ones, which are covered.
* **6.4 snapshots in CI**: impossible without Ghidra's files (ADR-002); the
  `bkfix` fixture provides the CI-runnable differential check instead.
* `resolve_handles(&mut parse)` became `Decoder::resolve_handles(bytes,
  context)` (an `inst_next2` look-ahead needs both); text functions are on
  `Language` taking `&Parse`.

## Platforms

* macOS arm64: everything above, the gate.
* Windows: `cargo clippy -p bk-sleigh --all-targets --target
  x86_64-pc-windows-msvc -- -D warnings` clean (it found `result_large_err`
  on `LoadError`, fixed by boxing); the crate's tests built for
  `x86_64-pc-windows-gnu` and run under Wine in the `bk-gnu-disasm-win`
  container (scripts copied to `target/windows/`): all oracle-free tests
  pass (unit 18, `decode_units` 6, `fixture_oracle` 1, `properties` 3,
  `fuzz_regressions` 2, `bench_heap` 1; the reference tests print SKIPPED).
* Linux: rests on CI.

## Follow-ups

* `fuzz/Cargo.lock` also gains `bk-binutils-sys`, which the fuzz crate
  already depended on but master's lock lacked (additions only).
* No new third-party crate. `wait-timeout` (workspace version, already in
  the lock) is a new dev-dependency of `bk-sleigh`; `Cargo.lock` gains only
  `bk-sleigh`; the fuzz crate's lock gains `bk-sleigh`.
* `bk-testkit`: a `Pcodedump` with a configurable root (the `bkfix` recorder
  runs the binary itself), and `ReferenceDir::module_options()` (known
  wish). The reference directory has no `Module.manifest` files, so tests
  build the registry with one `.module()` per processor directory
  (`tests/common/mod.rs`); a `bk-testkit` helper would serve other tracks.
* `pcodedump` resolves the `.sla` beside the `.ldefs`; making it search like
  Ghidra would let the oracle run RISC-V's `old/` definitions.
* Ghidra bug worth reporting upstream: SIGSEGV in `Sleigh::oneInstruction`'s
  `UnimplError` handler when the unimplemented instruction is in a delay
  slot.
* For `sleigh-pcode`: `prepare` is the entry; the harness's flow-length
  prediction (`tests/common/sweep.rs::nested_delay_missing`) becomes the
  builder's real error; `tests/data/recorded-oracle.txt` keeps the `P`
  records for comparison.
* ADR candidate: "the differential harness may emulate a documented Ghidra
  limitation (the 20-operand limit) to keep the sweeps in step; the
  emulated cases are counted and checked separately."

## Commits

See `git log --oneline master..HEAD` in the final message.
