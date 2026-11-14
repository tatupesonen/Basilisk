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
ADR-039 and ADR-040. Paths are relative to
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

## Results that depend on the host

| # | Component | Defect | Effect | Status | Source |
|---|---|---|---|---|---|
| 14 | SLEIGH compiler, `DecisionNode::getScore` | `sc -= p * log(p)` is left to the compiler's floating-point contraction and to the C library's `log` | 14 of the 150 shipped `.sla` differ between an AArch64 build that fuses and x86-64; the Java compiler's output depends on `Math.log` (ARM8_le, ARM8m_le differ between two JDK builds) | confirmed | ADR-029, ADR-032, ADR-034, ADR-039; `research/sla-host-dependence/` |
| 15 | Prototype models, effect lists and trials | `std::sort`, which is not stable, on elements that compare equal, and lookups answered from the resulting order: effect records at one address (`ProtoModel::decode`, `fspec.cc:2680`, comparator `fspec.hh:1786`), `lookupEffect` (`fspec.cc:2463`) returning the last tied record, identical trials (`sortTrials`, `fspec.hh:322`), trials without an entry (`fspec.cc:1881`). Latent in `intersectEffects` (`fspec.cc:2767`), `lookupRecord` (`fspec.cc:2501`), the `FuncProto` effect sort (`fspec.cc:3673`), `ScoreProtoModel::doScore` (`fspec.cc:2728`). The fix upstream is `std::stable_sort` | With libstdc++ and libc++ the decompiler's own tables differ in 119 of 152,046 rows: 56 reordered effect rows (NDS32, RISC-V gcc), 24 different `hasEffect` answers (3 on macOS, 1 or 2 on Linux), 39 trial results (tricore, Loongarch lp64f, x86-64 golang). Ghidra's Linux, macOS and Windows releases use three different libraries | confirmed (both tables generated 20 times each, byte-identical per library; valgrind clean) | `agents/cspec-host.md`, ADR-040 |
| 16 | P-code snippet lexer, numbers | An octal literal holding an 8 or a 9 (`09`) is read through the stream's number parser | 0 with libstdc++, an overflow error with libc++ | confirmed | `features/sleigh-snippet.md` §8 |

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
* The SLEIGH compiler's token-mismatch message prints pointers
  (`features/sleigh-compiler-back.md` §8).
* `FileManage::matchListDir` (`filemanage.cc:177–203`) returns files in
  `readdir` order, so the order in which language definitions are
  listed depends on the filesystem (`agents/cspec-host.md`).
