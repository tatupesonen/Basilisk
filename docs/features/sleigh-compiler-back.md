# SLEIGH compiler, part 2: patterns, decision trees, the `.sla`, `basilisk sleigh compile` (`bk-sleigh-compiler`)

Track `sleigh-compiler-back`, milestone M2. Starts when
`sleigh-compiler-front` is merged (same crate). Format of this document:
`docs/LOOP.md`. Background this spec relies on and does not repeat:
`docs/inventory/01-sleigh.md` sections 2, 9.1, 9.10, 10 (a)–(c), (e),
and 11.

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`
under `../ghidra`; `REF` = `../reference`.

## 1. Purpose

Finish the compiler: turn each constructor's pattern equation into bit
patterns, work out where each operand's bytes start and in what order
operands are decoded, build the decision tree of every table, detect
patterns that cannot be told apart, write the result as a `.sla` that is
the same file Ghidra's compiler writes, and offer it all as
`basilisk sleigh compile` with Ghidra's options and messages.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/slghpatexpress.cc`, `.hh` | `TokenPattern` (constructors, `doAnd`/`doOr`/`doCat`, `commonSubPattern`, `resolveTokens`, block builders), `PatternEquation` and subclasses (`genPattern`, `resolveOperandLeft`, `operandOrder`), `OperandResolve`, the compile-time side of `PatternExpression` (`genMinPattern`, `genPattern`, `listValues`, `getMinMax`, `getSubValue`) |
| `CPP/slghpattern.cc`, `.hh` | `PatternBlock` and the four `Pattern` classes with all operations |
| `CPP/slghsymbol.cc` | `Constructor::buildPattern`, `orderOperands`; `SubtableSymbol::buildPattern`, `buildDecisionTree`; `DecisionNode` construction (`split`, `chooseOptimalField`, `getScore`, `getNumFixed`, `getMaximumLength`, `consistentValues`, `orderPatterns`); `DecisionProperties` |
| `CPP/slgh_compile.cc` | `buildPatterns`, `buildDecisionTrees`, `process`, `run_compilation`, `main`, `setAllOptions`, `findSlaSpecs` |
| `…/ghidra/pcodeCPort/slgh_compile/SleighCompileLauncher.java`, `SleighCompileOptions.java`, `…/slghpatexpress/EqualEquation.java` | Java's extra options; the unsigned range test |

**C++ is authoritative**; two places follow Java and are recorded in
section 8.

## 3. Scope

**In.** In crate **`bk-sleigh-compiler`** (owned by this track while it
runs): the pattern algebra; equations → patterns; operand offsets,
minimum lengths, reordering and the remapping it forces on templates,
print pieces and expressions; decision trees and their diagnostics;
lowering the whole elaborated specification to `bk_sla::Sla` and writing
it; the library entry point `compile(path, &Options, &mut FileLoader) ->
(Option<Sla>, Vec<Diagnostic>)`; the `basilisk sleigh compile`
subcommand in the binary crate; the differential and regression tests of
M2.

**Not in.** Anything of part 1; the file format (`bk-sla`); p-code
snippets (`sleigh-snippet`); compiling on demand when a language is
loaded (`sleigh-language`).

## 4. Behaviour

Inventory section 10 (a)–(c) is normative, including its iteration
orders and tie-breaks: they decide the bytes of the file.

### 4.1 Patterns
Implement the pattern algebra as plain values (blocks of 32-bit mask and
value words with a byte offset; instruction, context, combined, and
ordered lists of disjuncts) with exactly the operations and quirks of
10 (b): `normalize`; `intersect`; `commonSubPattern` including its
behaviour on false blocks; the operand order of `doOr` results (table in
b.5) — and `OrPattern::doOr`'s shift behaviour, which with a negative
shift alters the left operand's stored blocks (inventory 10 intro);
`simplifyClone` on every copy. Equations: 10 (a), in particular the
enumeration order of constraint values (`advance_combo`: first listed
value fastest, then the left-hand value ascending), which becomes the
order of disjuncts and so of decision-tree leaves.

Expression arithmetic at compile time (`getSubValue`) is signed 64-bit
with the same defined results as the runtime (`sleigh-decode` §4.4:
wrapping, shift counts modulo 64, arithmetic `>>`); division by zero in a
constraint is an error on the constructor ("Division by zero in pattern
expression").

`EqualEquation`'s range test follows **Java**: unsigned 64-bit comparison
(`isValueInRange`), so that a constraint on a 64-bit field can match;
the other five relations use the C++ signed loops. (For fields narrower
than 64 bits the two agree.)

### 4.2 Constructors and tables
`Constructor::buildPattern` (10 c.3) for every table reachable from
`instruction`, depth-first from the root in constructor and operand
order, with the recursion rule (one recursive operand, pattern gets a
right ellipsis); then offsets (`resolveOperandLeft`, the unravelling
loop), context-expression validation, and `orderOperands` (10 c.4) with
the remapping of handle indices in every template and export, operand
print pieces, operand `index`/`base`, and each operand's own
`operand_exp`. A table's own pattern is the running `commonSubPattern`
of its constructors (10 c.2). Tables never reached get no pattern, the
warning "Unreferenced table 'T'", and are purged (part 1 already
predicted the same set; assert that the two agree).

### 4.3 Decision trees
10 (c.6)–(c.9) exactly: pairs added in constructor order, disjuncts in
order; `split`; `chooseOptimalField` with its two passes, context before
instruction, strict comparisons; `consistentValues`; `orderPatterns` with
the identical check, the insertion pass and the conflict resolution;
`number` counted as Ghidra does.

**Floating point.** Scores are computed in `f64` in the C++'s order:
`p = count as f64 / total as f64`; `sc -= p * ln(p)` over bins in
ascending order; `sc / ln(2.0)`. Use `libm::log` (pure Rust, already a
workspace dependency), not the host's `ln`, so that basilisk's output is
the same on every platform. Ghidra's own result depends on its host's
`log` only when two candidate fields score within rounding error of each
other; acceptance 1 says how such a case is recognised if one exists.

### 4.4 Diagnostics
The messages of 10 (c) and 9.1: per-constructor pattern errors collected
per table ("Problem in table 'T':…" with the accumulated text), "No
patterns to match.", "Unreferenced table", identical patterns (always
errors, reported for both constructors), indistinguishable patterns
(errors only with `-l`), "Duplicate (offset,size) pair for registers".
Ghidra's unrecoverable errors here ("Child has as many Patterns as
parent", ellipsis errors escaping `commonSubPattern`) are ordinary
errors. `Mismatched tokens when combining patterns` prints two pointers
in Ghidra; basilisk prints the two token names.

### 4.5 Output
Lower to `bk_sla` through `SlaBuilder` and write with `bk_sla` (packed
container, or XML with `-y`). The inflated stream must equal the one in
Ghidra's file for the same source and options (acceptance 1). Output is
written to a temporary file in the destination directory and renamed, so
a failed compile leaves no partial file; nothing is written when there
are errors ("No output produced").

### 4.6 `basilisk sleigh compile`
Ghidra's command line (inventory 9.1): the C++ options `-a`,
`-DNAME=VALUE`, `-u`, `-l`, `-c`, `-n`, `-t`, `-e`, `-s`, `-y`, and
Java's `-f` (warn about unused token fields), `-dMODULE` (define MODULE
as that module's directory under the spec root), `-i FILE` (read options
from a file, one per line, `#` comments), and `-a DIR` in Java's form as
well as the C++ form. File-name rules of 9.1 with one correction:
extensions are tested at the **end** of the name, case-insensitively (as
Java), not anywhere in it. Standard error carries Ghidra's lines —
`FILE:LINE - ERROR TEXT`, `WARN  TEXT`, `No output produced` — with
`FILE:LINE` taken from the diagnostic's span (Ghidra's is the lexer
position, which for the late passes is the end of the file); exit status
0 on success, 2 on failure, 1 on a bad command line; all-mode continues
after a failure and returns the number of failures negated modulo 256 as
Java does. `-x` is accepted and ignored.

### 4.7 Platforms (ADR-022)
* Sources with CRLF line endings compile to the same file as with LF
  (tested end to end by converting a specification and its includes).
* A UTF-8 byte-order mark at the start of a source file is ignored
  [check `bk-sleigh-syntax`; if it is not, report to the coordinator].
* Recorded source-file names are base names; the output does not depend
  on the path spelling, separators, the current directory or the
  platform. `-a` walks directories in sorted order (Ghidra's order is the
  file system's).
* The temporary-file-and-rename works when the destination exists and is
  open elsewhere on Windows as far as the platform allows; a failure is
  reported, not ignored.

## 5. Design

* Modules added: `pattern/{block, disjoint, or, token_pattern}`,
  `equation/{gen, resolve, order}`, `build/{constructor, table, offsets,
  reorder}`, `decision/{node, score, order, properties}`, `lower`,
  `driver`, `options`; in the binary crate `cmd/sleigh_compile`.
* Patterns are small values: a block is `(offset: i32, nonzero: i32,
  words: SmallVec<[(u32, u32); 2]>)` — [census] at most 3 words in the
  shipped languages; disjunct lists are `Vec`s. No reference counting;
  clone where the C++ clones.
* Decision-tree construction is recursive in the C++; trees are at most
  19 deep in the corpus, but a specification is untrusted input, so use
  an explicit stack or a depth limit of 256 with an error.
* Tables are independent once the symbol table is fixed: patterns for
  different tables may be built in parallel only if the result is
  identical to the sequential order (diagnostics included). Not required;
  measure first.
* Budget: Ghidra's compiler takes 11.5–11.8 s for all 150 one at a time
  on the `PERF.md` machine (`RISCV/andestar_v5` 1.7–1.8 s; the MIPS
  family about 0.45 s each).

## 6. Tests

### 6.1 Ghidra tests to port
| Checklist line (`docs/inventory/tests/`) | What it becomes |
|---|---|
| `test-integrationtest.md`: `ghidra.pcodeCPort.slgh_compile.regression.SleighCompileRegressionTest` (slow, 1 tests) | It compiles every `.slaspec` with the C++ and the Java compiler (`-y`) and compares the texts, skipping `<print piece=" "/>` lines. Ported as 6.2, with basilisk in Java's place and a stricter comparison |
| `framework-softwaremodeling.md`: `ghidra.pcodeCPort.slgh_compile.SleighCompileOptionsTest` (slow, 5 tests) | Option parsing: an options file with `-x -u -l -n -t -e -c -f -s -DTESTNAME=TESTVALUE -dx86`, each flag's effect on the option set, `-i file input.slaspec` → output `input.sla`, a missing extension defaulting to `.slaspec`, an explicit output, `-a dir` |
| `framework-softwaremodeling.md`: `ghidra.pcodeCPort.slghpatexpress.EqualEquationTest` (unit, 3 tests) | The unsigned range test of 4.1: normal range, full-width range, range crossing the signed boundary |
| `framework-softwaremodeling.md`: `ghidra.app.plugin.processors.sleigh.SleighLanguageProviderTest` (slow, 4 tests) | Not here: needs compile-on-demand and locking (`sleigh-language`) |

### 6.2 Differential test — all 150 specifications, byte for byte
For each `.slaspec`, with its module's options (`bk-testkit`):
`compile` it and require the packed stream `encode_packed(result)` to
equal the inflated reference `.sla` **byte for byte**. On a mismatch the
test prints `bk_sla::diff` of the two models (table, constructor,
file:line, path), so a failure is diagnosable. Also required equal for
each: the `-y` XML text against `REF/bin/sleigh -y`; and the warning
lines, in order, against the reference build's log
(`REF/logs/sleigh/<Module>/<name>.log`, lines beginning `WARN  `), with
Ghidra's `FILE:LINE:` prefixes inside the messages kept (they are
constructor and table locations, which basilisk knows).

Tolerated differences: **none expected**. One class is admitted if it
occurs, recognised mechanically: a decision node where basilisk and the
reference chose different fields and basilisk's scores for the two
fields differ by at most 2 units in the last place — a tie decided by
the host's `log` in Ghidra. Each such node is listed in a checked-in
file with both scores; the affected language is then compared on
everything outside that table's tree, and in addition must decode
identically (next paragraph).

**Behavioural cross-check** (uses the merged runtime; skip if
`sleigh-pcode` is not merged yet, and then it becomes a merge condition
of whichever lands second): for 12 languages (the list of
`sleigh-decode` §6.2), decode the directed samples with basilisk's
runtime once from Ghidra's `.sla` and once from basilisk's; the outputs
must be identical. This is redundant when the files are equal and is
what stands behind an admitted tie.

### 6.3 Diagnostics against Ghidra's compiler
Part 1's harness, extended with a case for every message of this half
(impossible patterns, each ellipsis error, mismatched pattern sizes,
"missing '...'?", undefined operand, illegal recursion, unresolvable
operand offsets, circular offset dependency, operand in a context
expression that is not constructor-relative, identical patterns, and
indistinguishable patterns with and without `-l`), each compiled by
`REF/bin/sleigh` and by basilisk: same success or failure, same multiset
of (severity, message text); and the command's standard error and exit
status for a set of command lines (bad option, missing input, too many
parameters, unreadable file, `-a` over a directory with one failing
specification — where the C++ stops and basilisk, like Java, continues;
listed as expected).

### 6.4 Derived, property, fuzz
* Unit tests of the pattern algebra against hand-computed blocks: both
  block builders for fields inside a byte, across bytes, in big- and
  little-endian tokens of 1–8 bytes; `normalize`; each operation; each
  row of the `doOr` order table; `resolveTokens` cases; the six
  relations including an unsatisfiable one; ellipses and concatenation
  offsets; operand offsets relative to variable-length operands;
  `orderOperands` with dependent offsets; `chooseOptimalField` on small
  hand-made sets including a context-versus-instruction tie and the
  `maxfixed` reset; `orderPatterns` with nested, overlapping-resolved and
  conflicting patterns.
* `proptest`: for random small sets of disjoint patterns over 16 bits,
  the tree built resolves every bit string to the same constructor as a
  linear scan of the specialisation-ordered list (the tree is an index,
  not a different semantics); pattern operations satisfy their set
  meaning (`intersect` matches exactly the strings both match, …).
* Fuzz target `bk_sleigh_compiler_compile` (bytes → whole pipeline →
  `bk_sla` validation of the result: **whatever compiles must be a valid
  model**); 60 s without a finding.

### 6.5 Benchmarks (`#[ignore]` release tests; numbers in `PERF.md`)
Compile x86-64, AARCH64, `RISCV/andestar_v5`, and all 150 one after
another, against the reference compiler timed in the same session
(`tools/reference/measure.sh`). Required: each no slower than the
reference; all 150 on one thread in at most the reference's total.

## 7. Acceptance

1. 6.2 passes for all 150 specifications: packed stream equal, XML text
   equal, warnings equal; any admitted tie is in the checked-in file with
   its scores and the behavioural cross-check passes for its language.
2. The three ported test classes of 6.1 pass and are marked.
3. 6.3 and 6.4 pass with every message covered; fuzz target 60 s clean.
4. 6.5 meets its figures; the M2 lines of the plan can be ticked.
5. CRLF and path-independence tests of 4.7 pass. Gate green on macOS;
   `cargo check --target x86_64-pc-windows-msvc` passes; oracle-free
   tests pass on all three systems in CI.

## 8. Differences from Ghidra

* `EqualEquation` uses Java's unsigned range test (C++ compares signed,
  which makes constraints on 64-bit fields unsatisfiable).
* `log` from `libm`, for host-independent output.
* Command line: Java's options in addition to C++'s; extensions tested
  at the end of the name; all-mode continues after a failure.
* Diagnostics carry real locations; unrecoverable errors are ordinary
  errors; the token-mismatch message names tokens instead of printing
  pointers; division by zero in a constraint is an error instead of
  undefined behaviour.

(The implementing track appends.)

## 9. Status

Not started.
