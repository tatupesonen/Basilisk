# Track `spec-sleigh` — final report (research; documents only)

Branch `spec-sleigh`, worktree `/Users/tatu/slop/basilisk-wt/spec-sleigh`.
No code was written. Everything is committed; nothing is pushed.

## Files written

| File | What it is |
|---|---|
| `docs/inventory/01-sleigh.md` | Inventory: the compiled-language model, the `.sla` format element by element, loading, context, decoding, disassembly text, p-code generation, undefined behaviour in the C++ engine, measured baselines, the compiler front half (sections 9) and back half (10), Java/C++ differences (11), corpus facts (12) |
| `docs/features/sla.md` | Spec: crate `bk-sla` — file model, reader, writers |
| `docs/features/sleigh-decode.md` | Spec: crate `bk-sleigh`, part 1 — language loading, context database, decoding, text |
| `docs/features/sleigh-pcode.md` | Spec: `bk-sleigh`, part 2 — p-code generation, `Translate`, `basilisk disasm` |
| `docs/features/sleigh-language.md` | **Draft** spec: `bk-sleigh` part 3 and crate `bk-language` — what Java adds (registers as a model, flow and operand types, overrides, compile on demand) |
| `docs/features/sleigh-compiler-front.md` | Spec: crate `bk-sleigh-compiler`, part 1 — symbols, constructors, templates, checks |
| `docs/features/sleigh-compiler-back.md` | Spec: `bk-sleigh-compiler`, part 2 — patterns, decision trees, writing, `basilisk sleigh compile` |
| `docs/features/sleigh-snippet.md` | Spec: crate `bk-sleigh-snippet` — p-code snippets for injection |

## Crate split and track order

**One crate for the compiled model: `bk-sla`.** It holds the model exactly
as the file has it, laid out for decoding (flat arenas, typed `u32`
indices, decision-node children as contiguous runs, immutable and
`Send + Sync`), the validating reader, and writers that reproduce
Ghidra's bytes. The runtime decodes straight from it; the compiler lowers
into it through a builder. Reasons: the two sides share a *format*, and
the strongest independent check of that format exists before either side
does (read all 150 reference files and write them back byte for byte;
reproduce `sleigh -y` text); it removes the dependency between the
runtime and compiler tracks, so they run in parallel; the compiler's
tests get a structural diff instead of "bytes differ at offset N". The
compiler keeps its own mutable working structures; only small value types
(`ConstTpl`, `VarnodeTpl`) are shared.

```
sla ──┬─> sleigh-decode ──> sleigh-pcode ──────────────┐
      │                                                 ├─> sleigh-language (draft; later wave)
      └─> sleigh-compiler-front ─┬─> sleigh-compiler-back ┘
                                 └─> sleigh-snippet
```

| Track | Crates | Depends on | Can start | Acceptance (independent of the implementer) |
|---|---|---|---|---|
| `sla` | `bk-sla` | merged M0 crates | **now** | all 150 reference `.sla`: packed stream re-encoded byte for byte; XML text equal to `sleigh -y`; validation passes; x86-64 read ≤ 25 ms and not slower than the reference loader |
| `sleigh-decode` | `bk-sleigh` | `sla` | after `sla` | `I`/`E`/`T` records equal to `pcodedump` for every language over directed samples (every root-table pattern), random bytes and real code, with coverage thresholds; decode speed ≥ reference |
| `sleigh-pcode` | `bk-sleigh`, `basilisk` (one subcommand) | `sleigh-decode` | after it | every record (`P`, `U` too) equal to `pcodedump`; `basilisk disasm` output byte-equal to the oracle's; decode+lift ≥ 1.5 M instructions/s |
| `sleigh-compiler-front` | `bk-sleigh-compiler` | `sla` | after `sla`, parallel with `sleigh-decode` | for all 150 specs: every symbol id, symbol content, print piece, context change and template equal to Ghidra's file in a canonical form keyed by operand symbol id; diagnostics equal to the C++ compiler's on per-message cases |
| `sleigh-compiler-back` | `bk-sleigh-compiler`, `basilisk` (one subcommand) | `sleigh-compiler-front` | after it, parallel with `sleigh-pcode` | all 150 specs compile to the **same inflated bytes** as Ghidra's; XML text and warning lines equal; three Ghidra test classes ported; no slower than the reference compiler |
| `sleigh-snippet` | `bk-sleigh-snippet`, one reference tool + `bk-testkit` module | `sleigh-compiler-front` | after it, parallel with `sleigh-compiler-back` and `sleigh-pcode` | every `<pcode>` body of every `.cspec`/`.pspec` compiles to the same template XML as Ghidra's `PcodeSnippet` (new oracle `snippetdump`); `PcodeParserTest` ported |
| `sleigh-language` | `bk-sleigh`, `bk-language` | `sleigh-pcode`, `sleigh-compiler-back` | later wave; spec is a draft | ported register and volatility tests; dump from full Ghidra for flow and operand types |

Tracks named in the same column of the diagram touch disjoint crates.
`bk-sleigh` is owned by one track at a time (decode → pcode → language),
`bk-sleigh-compiler` likewise (front → back).

## Decisions the coordinator should confirm (ADR candidates)

1. **`bk-sla` as the shared model crate**, and the new crates `bk-sla`,
   `bk-sleigh-snippet`, `bk-language` in the crate map of `PLAN.md`
   (`decodeSlaSpaces` moves from "`bk-sleigh`" — as
   `docs/agents/core-marshal.md` suggested — to `bk-sla`).
2. **Defined results where Ghidra's C++ SLEIGH engine is undefined**
   (extends ADR-021): expression shifts use the count modulo 64 with an
   arithmetic right shift; division by zero is a decode error (Java
   throws; C++ traps on x86-64 and yields 0 on AArch64); instruction
   bytes past index 15 read as zero when the read starts below 16;
   constructors with more than 20 operands are decoded (Ghidra's C++
   fails on them); recursion is bounded.
3. **No address-keyed parse cache**: a parse is never reused after the
   context changed. Differs from Ghidra only for an instruction that both
   uses `inst_next2` and commits context affecting the next instruction.
4. **After parsing, the C++ compiler is the oracle**, and the compiler's
   acceptance is equality of the inflated `.sla` stream. Two places
   follow Java instead: the unsigned range test in `EqualEquation`, and
   the command line (Java's options are a superset). `libm::log` in
   decision-tree scoring for host-independent output.
5. **Space-id constants are space indices with size 8** on every host
   (what `pcodedump` prints).
6. **A file accepted by Ghidra may be rejected by `bk-sla`'s validation**
   when using it would be undefined behaviour in Ghidra (dangling ids,
   operand-expression cycles, decision nodes wider than 8 bits); no
   compiler-produced file is rejected (checked on the 150).
7. **A new reference tool `snippetdump`** (C++, beside `pcodedump`),
   owned by the `sleigh-snippet` track; `pcodedump` itself is unchanged.
8. `basilisk disasm` writes `pcodedump`'s format by default, so the two
   tools' outputs are compared directly.

## What was verified, and how

**Read in the source (C++):** `slaformat.cc/.hh`, `sleighbase.cc`,
`sleigh.cc/.hh`, `context.cc/.hh`, `globalcontext.cc`, `partmap.hh`,
`semantics.cc`, `slghsymbol.cc` (all `encode`/`decode`, the runtime
methods, `addSyntax`, `orderOperands`, `buildPattern`, `purge`, the
decision-node runtime and — spot-checked — its construction), the runtime
parts of `slghpatexpress.cc` and `slghpattern.cc`, `translate.hh`
(interface), `slgh_compile.cc` 120–212 and 1777–4091 except `run_xml`,
`pcodecompile.cc`, `slghparse.y` (all actions), the layout trigger in
`slghscan.l`, `inject_sleigh.cc` (`inject`, `setupParameters`,
`parseInject`), `PcodeSnippet` in `pcodeparse.y`, `tools/reference/pcodedump.cc`.
**Java:** `PatternExpression.decodeExpression`, the shift and division
expressions, `PcodeEmit.java` 76–260 and 436–456, 770–894.

**Through a helper's line-cited notes (not read by me in full):** the
compiler back half — `TokenPattern`, the equations, the pattern classes,
decision-tree construction, `ConsistencyChecker` (inventory section 10).
I checked `getScore`, `chooseOptimalField`, the start of `orderPatterns`
and `OrPattern::doOr` against the source; the rest rests on the notes.
Partial helper notes on the Java side (`SleighLanguage`,
`SleighLanguageFile`, `SleighInstructionPrototype`, options) and on the
test inventory were used for `sleigh-language.md` and the test lists;
those helpers were stopped before finishing when the worker cap was set.

**By running the reference tools:** the element census and maxima of all
150 `.sla` (inventory 12); the operand and constructor validation rules
of `sla.md` on all 338,715 operands and 131,955 constructors (found:
`first` may equal the number of print pieces); `sleigh -y` output and
file naming; a plain compile being byte-identical to the reference
directory's file; `pcodedump` on x86-64, ARM, PowerPC samples (found:
`vadduhm` fails in Ghidra's C++ with "SLEIGH parser out of state
space"; a misaligned address disassembles and then reports
"unimplemented … not aligned"); per-phase speed of `libsla` (inventory
8a); the per-spec warning logs under `REF/logs/sleigh/`; the count of
`<pcode>` elements.

**Not verified:**
* Nothing Java was run. `sleigh-language.md` marks its [to verify] items
  (`RegisterValue`, `Constructor.java` separators and operand objects,
  `PcodeEmit.java` 259–410, volatility precedence, the Java
  disassembler's context flow).
* Whether the C++ compiler's output is identical across hosts: the
  x86-64 reference build (`../reference-x86_64`) had not completed. The
  one known hazard is a decision-tree score tie decided by the host's
  `log` (`sleigh-compiler-back.md` §4.3 and §6.2 handle it).
* `with` headers whose pattern would create an invisible operand
  (`sleigh-compiler-front.md` §4.1).
* The statement subset `pcodeparse.y` allows in a snippet and what
  `PcodeSnippet` does after parsing (`sleigh-snippet.md` §4.2, §4.4).
* Whether `bk-sleigh-syntax` skips a byte-order mark; CRLF handling is
  required to be tested end to end in `sleigh-compiler-back`.
* The baselines were taken at load average above 40; each track
  re-measures the reference in the same session as its own numbers.
* Java's `PcodeParser` temporaries (taken from the test's expectations).

## Found in Ghidra that the plan or earlier documents have wrong or miss

* **Ghidra's C++ engine cannot decode every shipped instruction**:
  constructors with more than 20 operands (PowerPC AltiVec `vadduhm`,
  `vsubuhm`, two sub-tables) fail. The M1 line "disassembly and p-code
  for every language match the reference tool" needs this exception.
* `PLAN.md` M2 lists `SleighCompileRegressionTest` under "compiler
  diagnostics": it does not test diagnostics; it requires the Java and
  C++ compilers to write the same `-y` text for every spec (white-space
  print pieces aside). It is the model for the byte-equality check.
* `features/sleigh-syntax.md` places the p-code snippet parser in M1; it
  needs the compiler's template builder, so it is its own track after
  `sleigh-compiler-front`.
* `PLAN.md` "Working in waves" has "SLEIGH runtime (M1), SLEIGH compiler
  semantic analysis (M2)" starting together; both now wait for `sla`,
  which is small.
* The shipped `.sla` files of a Ghidra release are compiled by the
  **Java** compiler; the reference directory's by the C++ one.
* The C++ `.sla` reader has no case for `next2_exp` (Java has).
* The compiler's `-y` output name gets `.sla` appended; `first` in a
  constructor can point one past the last print piece; `OrPattern::doOr`
  modifies its left operand; C++ `EqualEquation` compares signed where
  Java compares unsigned; snippet temporaries step by 16 in C++ and 0x100
  in Java.
* The reference build keeps each spec's compiler warnings
  (`REF/logs/sleigh/<Module>/<name>.log`) — a ready oracle for warnings.

## Gaps

* `sleigh-language.md` is a draft (see above).
* The three helpers stopped mid-way would have produced a full
  Java-versus-C++ comparison and a per-class table of every
  SLEIGH-related test in `docs/inventory/tests/`; the specs list the
  classes that were established, not a complete classification of the
  emulator, assembler and GUI tests that touch SLEIGH.
* The inventory's back-half section is long because it is the notes with
  citations; it has not been edited down.

## Measurements and how they were made
- **Element census of all 150 reference `.sla`**: a Python script inflates
  each file (`zlib.decompress(data[4:])`) and walks the packed stream
  (header byte: `0x40` element start, `0x80` end, `0xc0` attribute; 5 id
  bits, extension byte when `0x20`; attribute type byte: high nibble type,
  low nibble length; type 7 = string with a length integer), counting
  elements, attributes with their types, parent/child pairs and maxima.
  Results are in inventory sections 1 and 12.
- **Reference speed per phase**: a C++ program linked against
  `../reference/src/cpp/libsla.a` and `../reference/src/zlib/libz.a`
  (`g++ -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -I../reference/src/cpp`),
  loading `x86-64.sla`, setting `longMode=1 bit64=1 addrsize=2 opsize=1`
  over the code space, and sweeping 539 kB of x86-64 code (text sections of
  `ruleaction.cc`, `coreaction.cc`, `fspec.cc`, `type.cc` compiled
  `-O2 -arch x86_64`) calling `instructionLength`, `printAssembly`,
  `oneInstruction` in four combinations; best of 5. Results: inventory
  section 8a. Taken at load average > 40; re-measure on an idle machine.
- `REF/bin/sleigh -y in.slaspec out` writes XML to `out.sla` (the tool
  appends `.sla`); a plain compile of `toy_be.slaspec` is byte-identical to
  the reference directory's `toy_be.sla`.
- `REF/bin/pcodedump REF <lang> 0x1000 --hex …` on x86-64, ARM and PowerPC
  samples (inventory sections 6–8).
