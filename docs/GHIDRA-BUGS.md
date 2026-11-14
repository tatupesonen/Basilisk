# Defects found in Ghidra

Defects in Ghidra's own code that the Basilisk tracks ran into while
comparing against it (Ghidra at commit
`42db038f3c88c6bd7e9bedbb919138111f8b77fd`). Kept here so that they can
be reported or fixed upstream later (owner, 2026-11-14: "Document these
so we can fix them later"). Nothing has been reported upstream yet.

Each entry is as the finding track reported it; the "Source" column
names the report with the evidence. An entry is **confirmed** when the
defect was reproduced against the reference build (a crash, or output
that changes from run to run), and **read** when it follows from the
source alone. What Basilisk does instead is recorded in the feature
specs' "Differences from Ghidra" sections and in ADR-024, ADR-038,
ADR-039, ADR-040, ADR-041 and ADR-042. Paths are relative to
`Ghidra/Features/Decompiler/src/decompile/cpp/` unless they say
otherwise.

When a track finds another one, its report lists it under "Follow-ups"
and the coordinator adds it here.

## Crashes and undefined behaviour

| # | Component | Defect | Effect | Status | Source |
|---|---|---|---|---|---|
| 1 | SLEIGH engine, p-code generation (delay slots, crossbuild) | After an error inside a delay-slot instruction (an `unimpl` there) the parser walker is left pointing at freed or stale state | `pcodedump` crashes: 31 instructions (SPARC 32: 17, SPARC 64: 13, MIPS micro BE: 1) | confirmed | `agents/sleigh-pcode.md`; `research/pcodedump-crashes.md` |
| 2 | SLEIGH engine, handles | A template reads the `FixedHandle` of a subtable operand whose constructor exports nothing; the handle is never set for this parse | Stale p-code from an earlier parse (1,543 records in 18 languages); a crash where the stale space pointer is null (ARM v8-m `vpt…`: 6 instructions) | confirmed | `agents/sleigh-pcode.md`, ADR-038 |
| 3 | SLEIGH engine, parse cache | A delay-slot instruction that uses `inst_next2` looks up the following instruction, which evicts the branch's own parse from the two-entry cache; the branch is then built from the wrong parse | Wrong p-code (Toy `harvard_rev`, `brdslt` with `skvs` in its delay slot: `BRANCH (unique,0xc00,1)`) | confirmed | `agents/sleigh-pcode.md`, ADR-038 |
| 4 | SLEIGH engine, crossbuild | A crossbuild target that is not in the parse cache makes generation fail although the target decodes | An error for a valid instruction (1 record) | confirmed | `agents/sleigh-pcode.md`, ADR-038 |
| 5 | SLEIGH engine, decoding | Out-of-band operand evaluation reads a walker that is not initialised; context words past the array are read; context-operation shifts of 32 or more | Undefined behaviour; results depend on memory contents | read | `agents/sleigh-decode.md`, `features/sleigh-decode.md` §8, ADR-024 |
| 6 | Prototype models (`fspec.hh:630`, `732`) | `ParamListMerged`'s default constructor never initialises `numgroup`, `maxdelay`, `thisbeforeret` and `autoKilledByCall` (only `ParamListStandard::decode` sets them; merged lists are built by `ProtoModelMerged::foldIn`). `assignParameterStorage` (`fspec.cc:2416`) calls `allocateStatus`, which is `status.resize(numgroup, 0)` (`fspec.cc:790`), before `ParamListMerged::assignMap` (`fspec.hh:737`) throws the expected "Cannot assign prototype before model has been resolved" | `std::length_error` abort when the garbage is negative or huge (25–75 % of runs on x86-64 Linux; so far never on macOS) | confirmed (valgrind `--track-origins`: uninitialised value in `assignParameterStorage` and `vector::_M_fill_insert`, created in `foldIn`) | `agents/remote-build.md`, `agents/cspec-host.md` |
| 7 | SLEIGH compiler, constraints | A null equation from `constrainOperand`; a dangling op after a failed macro expansion | The compiler dies on two malformed inputs | confirmed | `agents/sleigh-compiler-front.md` (`GHIDRA_CRASHES` in its diagnostics test) |
| 8 | SLEIGH compiler, constraints | Division by zero in a constraint expression is evaluated | Undefined behaviour | read | `features/sleigh-compiler-back.md` §8 |
| 9 | SLEIGH compiler, operand offsets | Operand offsets are left uninitialised on one path; the offset-unravelling loop has no guard | Undefined values; a possible endless loop on malformed input | read | `agents/sleigh-compiler-back.md` |
| 10 | SLEIGH compiler, `EqualEquation` | The C++ range test compares signed where Java compares unsigned | Constraints on 64-bit fields are unsatisfiable in the C++ compiler | read | `features/sleigh-compiler-back.md` §8 |
| 11 | SLEIGH compiler, enumeration | A constraint enumerates every value of the fields involved; equations, expressions and table chains recurse without bound | Never finishes, or overflows the stack, on wide fields or deep nesting | read | `features/sleigh-compiler-back.md` §8 |
| 12 | P-code snippet lexer (`PcodeLexer::curtoken`) | A token is copied into a 256-byte buffer without a bound check | Buffer overflow for a token longer than 255 characters | read | `features/sleigh-snippet.md` §8 |
| 13 | P-code snippets, bit ranges (`pcodecompile.cc` `createBitRange`, `assignBitRange`, `buildTruncatedVarnode`; `pcodeparse.y` 114, 187) | `(numbits+7)/8`, `bitoffset+numbits` and `byteoffset+numbytes` are computed in 32-bit unsigned arithmetic and wrap | A bit range with numbers near 2³² gets a wrong template instead of an error (Basilisk reproduces the wrap since `sleigh-fixups`, so that its output equals Ghidra's) | confirmed against the oracle | `features/sleigh-snippet.md` §8, `agents/sleigh-fixups.md` |
| 17 | Parameter trials (`ParamTrial::operator<`, `fspec.cc:1881`) | The comparator is not a strict weak ordering: the reverse-stack flag is read from one operand only, the offset is compared only within one exclusive entry, and all trials without an entry compare equal | Undefined behaviour in `std::sort` (`sortTrials`, `fspec.hh:322`; `fillinMapFallback`, `fspec.cc:1659`, `1708`); the order of such trials is the library's choice | read; its effect is confirmed as entry 15 | `agents/cspec-host.md`, ADR-040 |
| 18 | SLEIGH engine, labels (`sleigh.cc` `PcodeCacher::addLabel`, lines 69–74) | The label vector is grown up to the label id read from the compiled language, an unchecked `uint4` | A crafted `.sla` makes the engine allocate up to about 16 GiB | read | `agents/sleigh-fixups.md` |
| 19 | Value ranges (`rangeutil.cc` `CircleRange::pushForwardBinary`, `INT_LEFT`, lines 1265–1275; `normalize`, line 30) | With a step bound above 2³⁰ the `int4` `step <<= 1` overflows to 0 and `normalize()` divides by it | SIGFPE on x86-64. Not reachable from Ghidra's own callers, which bound the step at 32 | confirmed (the oracle program died with "Floating point exception" on the build host) | `agents/decomp-range.md`, ADR-041 |
| 20 | Value ranges (`CircleRange::pushForwardBinary`, `INT_MULT`, lines 1235–1239) | With a constant whose low 32 bits are 0 and a step bound above 2³⁰ the doubling loop reaches 0 and never ends | Hang. Not reachable from Ghidra's own callers | read | `agents/decomp-range.md`, ADR-041 |
| 21 | Value ranges, unsound results (`rangeutil.cc`) | `contains` of a full stepped range ignores the phase (314); `intersect` never compares the phases of equal steps, and `newStride` misreads ranges that wrap or round past the top (111–128, 595); `pullBackBinary` for `INT_SUB` with the variable in slot 1 does not reverse the bounds (942–943); the `INT_RIGHT`/`INT_SRIGHT` push-forward of a wrapping range is one value short (1313, 1329–1335); a comparison pull-back of a range holding both outcomes gives `[0,2)` instead of everything (820 and similar); `minimalContainer` of a full range returns the other range and leaves `right - step + 1` unmasked (478–495); `getMaxInfo` ignores the step and the sign bit, so the `INT_MULT` and `INT_LEFT` push-forwards can miss a wrap (280–297, 1241, 1272); `SUBPIECE` of a full stepped range loses its phase (1289); `pullBackUnary` for `INT_SEXT` uses `left & step` where `left % step` is evidently meant (774) | A range that does not contain every value the variable can take, or contains values it cannot: possible wrong jump-table bounds or value-set results. Basilisk reproduces each (the decompiler's output depends on them) | confirmed by enumeration against the oracle's results (property tests) | `agents/decomp-range.md`; `crates/bk-decomp-range/tests/properties.rs`, `edge_cases.rs` |
| 22 | Value ranges, undefined arithmetic and uninitialised reads (`rangeutil.cc`) | 18 sites with shifts by 64 or more or by a negative count, an `int4` multiplication overflow (1283) and an `int64` addition overflow (1331); `getMax`, `getMaxInfo`, `setStride`, `minimalContainer` and `widen` read the bounds of an empty range, which no constructor initialises | Undefined behaviour; results depend on the compiler and on memory contents (13,085 and 2,777 of 152,913 oracle rows) | confirmed (UndefinedBehaviorSanitizer with per-row handlers; valgrind) | `agents/decomp-range.md`, ADR-041 |
| 24 | Block structuring (`BlockGraph::structureLoops`, `block.cc:2212–2228`; `findSpanningTree`, `block.cc:1058`) | When `findIrreducible` reports an irreducible tree edge it asks for a rebuild, but `findSpanningTree` clears the irreducible flags at the start of every pass, so the same tree and edge would come back forever | Latent endless loop; by the same reading the branch cannot be reached (a tree edge is never reported). Basilisk bounds the loop | read | `agents/spec-decomp-wave1.md`, `features/decomp-cfg.md` |
| 25 | Block structuring (`TraceDAG::selectBadEdge`, `blockaction.cc:749`) | `(*iter).exitproto` on `badedgelist.begin()` without a check that the list is not empty | A missing defensive check rather than a reachable defect: by reading, the list cannot be empty there (proof in `features/decomp-cfg.md` §10 item 4), and it never is in the property tests | read; unreachable | `agents/spec-decomp-wave1.md`, `agents/decomp-cfg.md` |
| 26 | Block XML (`FlowBlock::decodeNextInEdge`, `block.cc:89–101`) | Out-edge slots that no in-edge names stay default-constructed, with an indeterminate pointer | `structure blocks` on a malformed document is undefined behaviour | read | `agents/spec-decomp-wave1.md` |
| 29 | Block structuring (`TraceDAG::pushBranches`, `blockaction.cc:983–1014`, with `openBranch` 839 and `retireBranch` 900) | When the loop-DAG view of the graph contains a cycle, one trace alternately opens and retires a branch point for ever, allocating a `BranchPoint` on every turn. Such a cycle arises because `FlowBlock::eliminateInDups`/`eliminateOutDups` (`block.cc:450–476`, 492) OR a merged edge's label into one half of the edge only and `ruleBlockCat` reads the other half, so a list can absorb a back edge and leave a cycle of tree edges | The decompiler never finishes and its memory grows (1 of 4,000 generated graphs: 25 nodes, irreducible). Basilisk returns `CfgError::TraceCycle` once a trace has opened more than 2·nodes + 8 branch points | confirmed (the reference console ran at full CPU with growing memory until killed; Basilisk's port reproduces the loop) | `agents/decomp-cfg.md`; the test `rules::endless_trace_is_an_error` and the `hang` row of the crate's `structure_blocks.txt.gz` |

## Results that depend on the host

| # | Component | Defect | Effect | Status | Source |
|---|---|---|---|---|---|
| 14 | SLEIGH compiler, `DecisionNode::getScore` | `sc -= p * log(p)` is left to the compiler's floating-point contraction and to the C library's `log` | 14 of the 150 shipped `.sla` differ between an AArch64 build that fuses and x86-64; the Java compiler's output depends on `Math.log` (ARM8_le, ARM8m_le differ between two JDK builds) | confirmed | ADR-029, ADR-032, ADR-034, ADR-039; `research/sla-host-dependence/` |
| 15 | Prototype models, effect lists and trials | `std::sort`, which is not stable, on elements that compare equal, and lookups answered from the resulting order: effect records at one address (`ProtoModel::decode`, `fspec.cc:2680`, comparator `fspec.hh:1786`), `lookupEffect` (`fspec.cc:2463`) returning the last tied record, identical trials (`sortTrials`, `fspec.hh:322`), trials without an entry (`fspec.cc:1881`). Latent in `intersectEffects` (`fspec.cc:2767`), `lookupRecord` (`fspec.cc:2501`), the `FuncProto` effect sort (`fspec.cc:3673`), `ScoreProtoModel::doScore` (`fspec.cc:2728`). The fix upstream is `std::stable_sort` | With libstdc++ and libc++ the decompiler's own tables differ in 119 of 152,046 rows: 56 reordered effect rows (NDS32, RISC-V gcc), 24 different `hasEffect` answers (3 on macOS, 1 or 2 on Linux), 39 trial results (tricore, Loongarch lp64f, x86-64 golang). Ghidra's Linux, macOS and Windows releases use three different libraries | confirmed (both tables generated 20 times each, byte-identical per library; valgrind clean) | `agents/cspec-host.md`, ADR-040 |
| 16 | P-code snippet lexer, numbers | An octal literal holding an 8 or a 9 (`09`) is read through the stream's number parser | 0 with libstdc++, an overflow error with libc++ | confirmed | `features/sleigh-snippet.md` §8 |
| 23 | Value ranges (`CircleRange::pushForwardBinary`, `INT_LEFT`, `rangeutil.cc:1269–1270`) | A shift amount of 64 or more is undefined; g++ on x86-64 shifts modulo 64, Apple clang on AArch64 vectorises the two shifts into one `USHL` that reads the amount as a signed byte | The same Ghidra source gives different ranges on Linux x86-64 and macOS arm64 (834 of 152,913 oracle rows) | confirmed (two oracle tables) | `agents/decomp-range.md`, ADR-041 |
| 27 | Varnode bank (`varnode.cc:39`, `73`) | The offsets of `iop` and `fspec` varnodes and of `LOAD`/`STORE` space constants are heap pointers, and the bank's two orders compare them | `print tree varnode` lists varnodes in a different order in two runs of one binary (43 of the 93 data tests on macOS). No effect on decompiled output observed | confirmed (two runs compared) | `agents/spec-decomp-wave1.md`, `research/decomp-wave1/runs.md` R5, ADR-042 |
| 28 | Block ordering (`FlowBlock::compareFinalOrder`, `block.cc:718`; used by `orderBlocks`, `block.hh:448`) | Not a strict weak ordering: index 0 compares less than itself, and two blocks ending in `RETURN` compare equal | `std::sort` leaves the order of such blocks to the C++ library (same kind as entry 15) | read; how often a tie occurs is open | `agents/spec-decomp-wave1.md`, `features/decomp-cfg.md` §10 |

## Smaller observations

* The snippet compiler keeps only the first error and compiles on after
  errors that do not stop its parser; there is no check that a label is
  placed (`features/sleigh-snippet.md` §8 and "Spec items found wrong").
* `OrPattern::doOr` modifies its left operand (a negative shift); nothing
  observes it (`features/sleigh-compiler-back.md` §8).
* Label numbers are truncated to 32 bits in the engine (`addLabel(uint4)`,
  `uint4 id = ptr->offset`), so a hand-made `.sla` with label 2³²+n
  resolves as label n; a branch to a label that is never placed is
  caught only when p-code is built (`PcodeCacher::resolveRelatives`,
  `sleigh.cc` 96–110), not when the template is read
  (`agents/sleigh-fixups.md`).
* Both compilers reject a `.slaspec` that starts with a byte-order mark
  (`slghscan.l` has no rule for it; Java reads ISO-8859-1 and reports
  three unknown characters) — not a defect, but a file saved by a
  Windows editor fails with a bare "syntax error"
  (`agents/sleigh-fixups.md`; Basilisk ignores the mark).
* `defineBitrange` (`slgh_compile.cc` 2800–2822) computes
  `(size-bitoffset-numb)/8` in 32-bit unsigned arithmetic, wrapping like
  entry 13 (`agents/sleigh-fixups.md`).
* The two halves of a merged block edge can carry different labels
  (`block.cc:463`, 492), and different structuring rules read different
  halves (`isDecisionOut`, `isLoopDAGIn`); the structurer's results
  depend on it, so Basilisk reproduces it (the cause of entry 29).
* The virtual root of `calcForwardDominator` keeps index 0
  (`block.cc:65`), so with several roots the finger arithmetic
  (`block.cc:2022–2028`) treats it as list position 0 and an
  intersection that should reach the virtual root yields the first node.
  No effect on the single-root graphs of the pipeline
  (`agents/decomp-cfg.md`).
* The console's breakpoint specifiers cannot address an action or rule
  whose name occurs twice (`ActionGroup::getSubAction`, `action.cc:456`;
  `getSubRule`, 481, 777): `break start blockstructure` fails (ran;
  `agents/spec-decomp-wave1.md`). The oracle adds breakpoints by position.
* `BlockCondition` is created with opcode `INT_OR`/`INT_AND`, toggled
  between `BOOL_AND` and `BOOL_OR` and printed by testing `== BOOL_AND`
  (`block.cc:1790`, 3073, 3091, 3107; `printc.cc:3001`) — right only
  because `ruleBlockOr` always creates the `INT_OR` case; the encoded
  attribute shows `INT_OR`.
* `ruleCaseFallthru`'s comment "Check exit block matches the 1
  nonfallthru exit" (`blockaction.cc:1761`) has no code behind it.
* The SLEIGH compiler's token-mismatch message prints pointers
  (`features/sleigh-compiler-back.md` §8).
* `FileManage::matchListDir` (`filemanage.cc:177–203`) returns files in
  `readdir` order, so the order in which language definitions are
  listed depends on the filesystem (`agents/cspec-host.md`).
