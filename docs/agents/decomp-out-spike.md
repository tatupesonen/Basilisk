# Track `decomp-out-spike` (D16a) — status

Question: ADR-025 item 3c — can `PrintC`'s output be reproduced token for
token from a tree that is built first and printed afterwards?

## Status and how to continue

### (a) Done

- `1ec9500`, `787f5a3`: the hook patch
  `tools/reference/patches-instr/0001-printer-hooks.patch` (adds
  `cpp/bkinstr.hh` and hooks in `prettyprint.hh/.cc`, `printlanguage.hh/.cc`,
  `printc.cc`), the logger `tools/reference/patches-instr/bk_printlog.cc`, the
  build script `tools/reference/patches-instr/build-instr.sh OUT`.
- `89f9d2a`: the corpus runner
  `docs/research/decomp-out-spike/prototype/run_corpus.py`.
- Byte identity, build host, the whole corpus (165 scripts: 93 data tests,
  72 research fragments; the two `a07_switch.*-gcc-O2` fragments are skipped
  as bk-oracle skips them): 825 runs, 0 differences between the reference
  `bin/decomp` and the instrumented console with logging on — variants
  `orig` (also with logging off), `xml` (`print C xml` after every `print
  C`), `flat` (`print C flat`), `java` (`print language java`).

### (b) In progress

- Hooks that exist: entry/exit (`BK_SCOPE`) of 46 `PrintC` methods and
  `PrintLanguage::emitLineComment`; `pushOp`, `pushAtom`, `pushVn`;
  `pushMod`/`popMod`/`setMod`/`unsetMod`/`pushScope`/`popScope`; every public
  `EmitPrettyPrint` method used for printing and `Emit`'s non-virtual
  `openBraceIndent`, `openBrace`, `closeBraceIndent`, `setPendingPrint`,
  `cancelPendingPrint`, `hasPendingPrint`, `setIndentIncrement`; only the
  outermost Emit call is logged (a depth counter), so a helper is one record.
- The console is activated by `BK_PRINTLOG=<prefix>` (files `.tree`,
  `.emit`, `.diag`); without it the hooks do nothing.
- Prototype: `prototype/tree.py` builds the tree from `.tree` (structural
  nodes + expressions rebuilt from pushes by token arity). The printer
  (`printer.py`, mirroring `PrintC`'s emit methods and the RPN emission of
  `printlanguage.cc:129-407`) and the comparator are not written yet. No
  match counts yet.
- Scratch and logs: Mac `target/instr-work/` (a = Ghidra's files, b = patched
  copy; `edit_emit.py`/`edit_print.py` regenerate b from a); host
  `~/bk/wt/decomp-out-spike/target/instr` (build), `target/spike-run`
  (logs, 43 MB, `identity.txt`); the `orig` logs fetched to the Mac under
  `target/testbed/20261114-193407-run/logs-orig.tgz`.

### (c) Not started, in order

1. `printer.py` + `compare.py` (canonical ids by first appearance), run over
   all functions, list every mismatch with its source line.
2. Coverage tables (push kinds, tokens, modifier flags, block kinds) from the
   logs; extra console scripts for unreached ones in our own inputs.
3. `report.md`, README section "The printer log", a gzip sample of logs,
   `.gitattributes` if needed, final gate and dep check.

### (d) Learned from the source

- Pushes are not virtual (`printlanguage.hh:292-296`), hence the patch.
- The RPN tree is implicit: paren decisions at push time depend only on the
  parent token, the child index (`visited`) and, for `hidden`, the
  grandparent (`printlanguage.cc:270-324`); so they are a function of the tree.
- Direct emission outside the RPN: `opBranch`/`opCbranch`/`opBranchind`/
  `opReturn` (`printc.cc:539-610`, `773-803`, marked FIXME in Ghidra),
  `emitBlockCondition` calls `emitOp` on a fake entry (`printc.cc:2998-3005`).
  The logger counts direct emits made while the RPN stack is non-empty
  (`.diag`): 0 in the one test examined so far.
- `PendingBrace` is a stack local; `hasPendingPrint` is the only Emit query
  whose result feeds back into PrintC (`printc.cc:3043`). Its address is
  reused, so only the result is logged.
- `FlowBlock::typeToName` writes `ifelse` for `t_ifnoexit` (`block.cc:697`);
  the logger names block types itself.
- `BlockIf::lastOp` returns `getBlock(2)->lastOp()` (`block.hh:710`), out of
  range for a two-component `if`; the logger never calls it.
- `force_pointer`, `force_scinote`, `bestfit` are never set anywhere;
  `hide_thisparam` only by `PrintJava` (`printjava.cc:164`).
- Atom fields are partly uninitialised per constructor; only the fields
  `emitAtom` reads for the tag are valid (`printlanguage.cc:376-407`).
- Commands:
  ```
  # on the build host (scripts/remote.sh run -- bash -c '...'):
  tools/reference/patches-instr/build-instr.sh --jobs 20 target/instr
  python3 docs/research/decomp-out-spike/prototype/run_corpus.py \
      --instr target/instr/bin/decomp_instr --out target/spike-run --jobs 20
  ```
  `run` does not fetch results; `scripts/remote.sh log` afterwards copies
  `$BK_OUT` to `target/testbed/<job>/`.

### (e) Findings so far (provisional)

- Expected answer yes: every expression is built only through `pushOp`/
  `pushAtom`, block-level direct emission happens with an empty RPN stack
  (to be confirmed on the whole corpus from `.diag`), and the only emitter
  state read back is the pending-brace result, which the printer can
  simulate.

### (f) Open questions and Ghidra defects so far

- Possible defect (to confirm): `PrintC::emitPrototypeInputs`
  (`printc.cc:2312-2317`) prints the comma before testing whether the
  parameter is a hidden `this`, so a hidden `this` that is not first gives
  `a,,b`; reachable only with `hide_thisparam` (Java).
- Static `OpToken`s are shared by all printers and `adjustTypeOperators`
  rewrites `scope.print1`/`shift_right.print1` (`printc.cc:2424`,
  `printjava.cc:121`): two languages cannot be used at once.
