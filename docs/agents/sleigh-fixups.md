# Track sleigh-fixups — status report

Small corrections the SLEIGH tracks left behind (brief items a–e). All five
are done; the coordinator merges, after which `scripts/remote.sh clean
sleigh-fixups` should be run (not run by this track).

## Progress

* (a) bit ranges wrap at 32 bits — done.
* (b) `bk-testkit` owns the snippetdump wrapper and `module_options` — done.
* (c) templates with a branch to an unplaced label are read — done.
* (d) byte-order mark — investigated: Ghidra rejects it, so nothing moved;
  documented as a difference.
* (e) Cargo manifest warnings — 4 of 8 removed; 4 remain on purpose.
* Gates: both green at `2ce04ae` (see Tests).

## Built

**(a) `bk-sleigh-compiler`, `pcode/bitrange.rs`, `compiler/define.rs`.**
What Ghidra's source says: `PcodeCompile::createBitRange`,
`assignBitRange` and `buildTruncatedVarnode`
(`Ghidra/Features/Decompiler/src/decompile/cpp/pcodecompile.cc` 702-916)
take `uint4 bitoffset, uint4 numbits`. The grammar truncates the parsed
64-bit integers to `uint4` (`pcodeparse.y` 114, 186-187; `slghparse.y`
236, 374, 454-455). Inside the functions:
* `createBitRange`: `uint4 finalsize = (numbits+7)/8` wraps. `uint4 insize =
  getReal()` truncates and `insize *= 8` wraps (Basilisk already did both).
* `assignBitRange`: `uint4 smallsize = (numbits+7)/8` wraps;
  `bitoffset+numbits > 64` is a `uint4` sum, so it wraps too.
* `buildTruncatedVarnode`: `byteoffset + numbytes` is a `uint4` sum widened
  only for the comparison with the `uintb` size. It is also used in the
  big-endian `fullsz - (byteoffset + numbytes)`, which the snippet report
  did not mention. Both operands are below 2²⁹, so this sum cannot actually
  wrap. Changing it is harmless and only makes the Rust match Ghidra's types.
* `SleighCompile::defineBitrange` (`slgh_compile.cc` 2800-2822): in `(size -
  bitoffset - numb)/8` all values are `uint4`. Basilisk subtracted in `u32`
  without wrapping, which **overflows in debug builds**:
  `define bitrange x=r0[8,0xfffffff8]` passes Ghidra's bounds check because
  the sum wraps to 0. Basilisk now wraps as Ghidra does.

The C++ is the oracle (`features/sleigh-compiler-back.md` 2). The Java
`PcodeCompile` uses signed `int` and would differ for widths ≥ 2³¹; it is
not followed. The snippet report's three proposals were right, apart from
the third one being a no-op as explained above.

**(b) `bk-testkit`.**
* `Tool::Snippetdump` and `ReferenceDir::snippetdump()`.
* `tools::snippetdump`: `Snippetdump` (`timeout`, `root`, `compile`,
  `compile_text`), `SnippetRecord`, `SnippetBase`, `SnippetParameter`,
  `SnippetOutcome`, `write_records`, `parse_outcomes`, `escape`/`unescape`.
* `SnippetParseError`, which becomes `ToolError::Snippet`.

The parser is stricter than the old test copy: unknown records, a missing
`T` line and wrong `T` counts are errors. `ReferenceDir::module_options(module)`
reads `.state/lang/<Module>.opts`, one option per line, as
`build-reference.sh`'s `compile_one` does. It replaces the private copies.
**There were two copies, not "four or more"**:
* `bk-sleigh-compiler/tests/common` (used by `reference_sla.rs` and
  `bench.rs`). It split on white space, which gives the same result for
  every `.opts` file the build writes.
* `bk-sla/tests/reference.rs`.

The snippet tests' `common/oracle.rs` now keeps only the test-side
`Record`, converted to `SnippetRecord`, and `run_basilisk`. The tests find
the tool with `bk_testkit::require_tool(Tool::Snippetdump)`. One
difference from before: with `BASILISK_REQUIRE_ORACLES` set, a reference
directory that lacks `snippetdump` now fails instead of skipping, as for
every other tool.

**(c) `bk-sla`, new `validate/labels.rs`.**
What Ghidra's source says:
* Reading checks nothing: `ConstructTpl::decode`/`OpTpl::decode`
  (`semantics.cc` 1000-1030) and Java's `template` package do not check
  label numbers.
* `numlabels` counts `LABELBUILD` ops (`semantics.cc` 842).
* `PcodeSnippet` produces `goto <L>;` with `<L>` never placed.
* The failure comes only when p-code is built, and only for an op's first
  input that is relative (`SleighBuilder::dump`, `sleigh.cc` 228-231).
  `PcodeCacher::resolveRelatives` (`sleigh.cc` 96-110) throws "Reference to
  non-existant sleigh label". Java's `PcodeEmitPacked.resolveRelatives`
  (line 83) throws the same message.

Changes:
* Reading (lone templates and whole `.sla` files) no longer checks label
  numbers. The `LABEL` directive still needs a constant input.
* `Template::check_labels()` and `Sla::check_labels()` are the explicit
  check. They require two things:
  * every `LABEL` number and `const_relative` is below the template's
    `labels`, which is the old rule;
  * every branch, meaning an op whose first input is a `const_relative`,
    names a label that a `LABEL` of the same template places. For a lone
    template this is exactly when Ghidra's injection succeeds.
* All 150 reference `.sla` files pass. `bk-sla`'s reference test now
  calls the check.
* `bk-sleigh` already failed such templates with
  `LiftError::MissingLabel` ("Reference to non-existant sleigh label"),
  bounded by `MAX_OPS`. A new test confirms it for label counts 0 and 1,
  label numbers up to `u64::MAX` and placed labels up to `u64::MAX`, with
  no panic, loop or large allocation.
* No consumer needs the check today: `bk-sleigh` handles the case at use
  time.

**(d) BOM: Ghidra rejects it, so `driver::WithoutBom` stays.**
* The C++ lexer (`slghscan.l` `INITIAL` rules, lines 491-504) has no rule
  for EF BB BF; the catch-all `.` returns the bytes as tokens.
* The reference `sleigh` on a file with a BOM prints `a.slaspec:1 - ERROR
  syntax error` and "No output produced" (exit 2). The same happens with a
  BOM before an `@define` line, and with a BOM at the start of an included
  `.sinc`, where it reports `inc.sinc:1`. The file without the BOM compiles.
* The Java compiler reads ISO-8859-1 (`SleighPreprocessor.java` 105), so
  the BOM becomes three characters. Its `UNKNOWN` lexer rule
  (`BaseLexer.g` 349) reports each one as an error.
* Nothing was moved into `bk-sleigh-syntax`. A note appended to
  `features/sleigh-compiler-back.md` 8 records that ignoring the BOM is a
  deliberate difference, kept per spec 4.7 / ADR-022.

**(e) Root `Cargo.toml`.** Cargo 1.100 printed 8 warnings:
* `workspace.package.authors` is unused: no crate inherits it and nothing
  reads `CARGO_PKG_AUTHORS`. Removed.
* `anyhow`, `memmap2` and `rayon` are unused workspace dependencies. No
  crate depends on them; `anyhow` and `rayon` are in `Cargo.lock` only
  through `egui_kittest`→`dify`. Removed. A binary or test that wants
  `anyhow`, which `LOOP.md` allows, must re-add the line.
* `bk-cspec`, `bk-decomp-types`, `bk-gnu-disasm` and `bk-sleigh-snippet`
  are unused internal crates. They are kept because `PLAN.md` gives them
  users: decompiler waves D02/D03 onward, D18 injection, and the GNU
  disassembler line. Cargo has a supported way to silence these warnings
  on stable 1.100: `[workspace.lints.cargo] unused_workspace_dependencies =
  "allow"`. I checked it in a scratch workspace, where members inherit with
  `[lints] workspace = true`. I did not add it, because lint configuration
  is the coordinator's (`LOOP.md`) and it would also hide real dead
  entries. **4 warnings remain.**

`Cargo.lock` is unchanged. `scripts/check-dep-age.py master` reports 0 new
packages.

## Tests

* **(a)**
  * `oracle_random` at `SNIPPET_RANDOM_CASES=200000` on the build host:
    "generated: 200000 bodies, 19625 compiled by Ghidra, 0 differ". The
    `wraps_32_bits` tolerance and its counter are gone.
  * `reference_sla`: both tests pass, so all 150 specifications compile
    byte-identical to the reference.
  * 15 hand-written snippet cases near 2³² in `tests/cases/fixture.txt`.
    `oracle_cases` reports "249 compared with snippetdump, 0 differ".
  * Two SLEIGH diagnostics cases, compared with the reference `sleigh`:
    * `bitrange_wrap.slaspec`: a `define bitrange` that wraps, and
      `sub[0,0xffffffff]`; both compilers accept it.
    * `assign_bitrange_wrap.slaspec`: `sub[8,0xfffffff9] = 1`. Ghidra
      gives "Could not resolve at least 1 variable size". The old code
      reported a different message and the case failed.
* **(b)**
  * 5 new unit tests in `bk-testkit` (`tools::snippetdump`).
  * `paths::module_options_are_read_one_per_line`; the tool-name test now
    covers `snippetdump`.
  * All `bk-testkit`, `bk-sleigh-snippet`, `bk-sla` and
    `bk-sleigh-compiler` tests pass on the host with the reference
    directory.
* **(c)**
  * `bk-sla`: `fixtures::a_branch_to_an_unplaced_label_reads_and_fails_the_label_check`,
    `validation::label_numbers_are_checked_apart_from_reading`; the "label
    number" case moved out of `each_xml_violation_is_rejected`.
  * `bk-sleigh`: `pcode_units::unplaced_labels_fail_with_ghidras_message`
    (30 cases). This is test-only code in a crate outside the track's
    list; the brief asked for it.
  * `bk-sleigh-snippet`: `properties::a_branch_to_an_unplaced_label_reads_back`.
    The skip in `check` is removed; the proptest regression seed
    (`goto <L>;`) is kept and now goes through the full read-back check.
* Windows: `cargo clippy -p bk-sleigh-compiler -p bk-sleigh-snippet -p
  bk-testkit -p bk-sla -p bk-sleigh --all-targets --target
  x86_64-pc-windows-msvc -- -D warnings` is clean on the Mac.
* Gates on the build host (Linux x86-64) at `2ce04ae`:
  * `scripts/remote.sh gate; echo $?` printed `tests: 2092 passed, 0 failed`
    and `remote: gate exit 0`, then `0`.
  * `scripts/remote.sh gate --no-ref; echo $?` printed `tests: 2092 passed,
    0 failed` and `remote: gate exit 0`, then `0`.

The hand-written snapshot updates (`oracle_cases`, the two diagnostics
cases) and three quick checks ran on the Mac against the arm64 reference
tools. Insta snapshots have to be written where the files are, and the
host was running this branch's job at the time. Everything else ran on
the host.

## Differences from Ghidra

* (d) A leading UTF-8 BOM is ignored by `bk_sleigh_compiler::compile`.
  Both Ghidra compilers reject it. This was documented before; it is now
  stated as a deliberate difference with the evidence.
* (c) No new difference: reading now matches Ghidra. `bk-sleigh` keeps a
  label number as a 64-bit value where Ghidra truncates it to `uint4` (see
  Follow-ups).

## Gaps

None of the brief's items is left undone. Item (b)'s "four or more copies"
was two. Item (d) turned out to be "Ghidra rejects", so nothing was moved.

## Follow-ups

* **Ghidra defect (resource exhaustion), `sleigh.cc` `PcodeCacher::addLabel`
  lines 69-74.** `while(labels.size() <= id) labels.push_back(0xbadbeef)`
  with `id` up to 2³²−1, taken from an untrusted `.sla`'s or snippet's
  `LABEL` constant, tries to grow the vector to 16 GiB. Found by reading
  the source; not run. Basilisk returns `MissingLabel` for any label number
  at or above `MAX_OPS`.
* **`bk-sleigh` (not this track's crate): label numbers are not truncated
  to 32 bits.** Ghidra's `addLabel(uint4 id)` and `resolveRelatives`
  (`uint4 id = ptr->offset`) truncate. A hand-made `.sla` whose label
  constant is 2³² + n therefore resolves to label n in Ghidra but fails in
  Basilisk. Neither compiler produces such numbers. Either truncate in
  `pcode/build.rs` and `buffer.rs`, or record it as an ADR-024 difference.
* The coordinator may want `[workspace.lints.cargo]
  unused_workspace_dependencies = "allow"` until the four planned crates
  get their users. Otherwise the 4 warnings stay until then.

## Commits

```
2ce04ae chore: drop manifest entries cargo reports unused (authors, anyhow, memmap2, rayon)
e1210c0 docs(sleigh-compiler): Ghidra's compilers reject a byte-order mark; Basilisk's stripping stays a documented difference
f15834a feat(sla): read templates whose branch names an unplaced label, as Ghidra does
c054e5c refactor(testkit): Snippetdump wrapper and ReferenceDir::module_options
ca2b4a7 test(sleigh-snippet): snapshots for bit ranges near 2^32; doc note that the wrap is fixed
334f5c4 fix(sleigh-compiler): bit range arithmetic wraps at 32 bits as in Ghidra
```
