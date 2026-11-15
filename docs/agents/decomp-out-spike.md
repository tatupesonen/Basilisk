# Track `decomp-out-spike` (D16a) — status

Question: ADR-025 item 3c — can `PrintC`'s output be reproduced token for
token from a tree that is built first and printed afterwards?

## Status and how to continue

### (a) Done

- Hook patch, logger, build script: `tools/reference/patches-instr/`
  (`0001-printer-hooks.patch`, `bk_printlog.cc`, `build-instr.sh OUT`);
  `source/make-patch.sh` regenerates the patch from Ghidra's files
  (`BASILISK_GHIDRA_DIR` must be set in a worktree) and reproduces it byte for byte.
  Last fix `9e116d1`: push hooks sit after the `recurse()` in `pushOp`/`pushAtom`.
- Prototype `docs/research/decomp-out-spike/prototype/`: `run_corpus.py`
  (both consoles, byte identity, logs), `tree.py` (tree from `.tree` only),
  `printer.py` (tree -> Emit calls), `compare.py`, `rerun.sh` (all of it).
- Results (build host, job `20261114-194118-run`), copied to
  `docs/research/decomp-out-spike/results/`:
  - Byte identity: 165 scripts x 5 variants + `orig` without logging = 990
    runs, 0 differences (`orig`, `xml`, `flat`, `java`, `options`).
  - Comparison: every logged function matches, all calls:
    orig 397/397 functions, 76,719/76,719 Emit calls; xml 794/794, 153,438;
    flat 794/794, 153,290; java 794/794, 152,907; options 397/397, 78,003.
    Total 3,176 functions, 614,357 calls, 0 mismatches, 0 printer errors.
  - The modifier word recomputed by the printer equals the logged word at
    every structural node (0 differences).
  - Interleaving (`.diag`): 250,723 direct emits, 0 made while the RPN stack
    was non-empty or varnodes were pending; 0 structural events inside an
    unfinished expression.

### (b) In progress

- Nothing running. The report is not written.

### (c) Not started, in order

1. `docs/research/decomp-out-spike/report.md` (answer, node kinds and facts
   from `printer.py`'s `k_*` methods, log format, counts, coverage, what it
   means for D16b/D16c, Ghidra defects, open questions).
2. README section "The printer log" in `tools/reference/README.md`
   (formats `bkprinttree 1`, `bkprintemit 1`, `bkprintdiag 1`: see the header
   comment of `bk_printlog.cc` and its `facts()` function).
3. A small gzip sample of logs (e.g. `datatests.elseif.{tree,emit}`) and gzip
   reading in `tree.py`/`compare.py`.
4. Gate (`scripts/remote.sh gate`) and `scripts/check-dep-age.py master`.
5. `scripts/remote.sh clean decomp-out-spike` at the end.

Coverage not reached (unproven): tokens `unary_plus` (never pushed anywhere),
`boolean_xor`, `new_op`, `instanceof`, `remequal`, `leftequal`, `orequal`;
nodes `constructor`, `opBranch`, and the non-function entry points
(`docAllGlobals`, `docSingleGlobal`, `docTypeDefinitions`, struct/enum
definitions); modifier flags `force_pointer`, `force_scinote`, `bestfit`
(never set in Ghidra), `nofallthru` (only set by `emitBlockLs`, never reached
in flat mode: `printc.cc:2868-2884` is dead), `option_unplaced`
(`setDisplayUnplaced` has no caller), `hide_thisparam` with a `this` that is
not the first parameter. Everything else in `results/coverage.txt` is reached.

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
- Commands (build host; results land in `$BK_OUT`, fetched by
  `scripts/remote.sh log` into `target/testbed/<job>/`):
  ```
  scripts/remote.sh run -- docs/research/decomp-out-spike/prototype/rerun.sh
  scripts/remote.sh log
  ```
  Scratch on the host: `~/bk/wt/decomp-out-spike/target/spike/{instr,run,results}`.
  On the Mac: `target/testbed/20261114-194118-run/` (results + `logs-orig.tgz`).

### (e) Findings on 3c (provisional until the report is reviewed)

- Yes, on the whole corpus: the Emit call sequence of every function is a
  function of a tree built from the pushes and structural events alone.
  The tree is PrintC's emission tree (a block printed twice in two modes,
  e.g. a condition block under `no_branch` then `only_branch`, is two nodes),
  not the block hierarchy. The printer needs only node facts plus the
  printer options; modifier words are recomputable from the tree; the one
  Emit query read back (`hasPendingPrint`, `printc.cc:3043`) is simulated.

### (f) Open questions and Ghidra defects so far

- Defect: `print C flat` is broken. Label statements print a bare `:`
  (`emitLabel` calls `getFrontLeaf`, which returns null for a basic block:
  `block.cc:344-353`, `printc.cc:3322`); goto targets print as annotation
  names (`Ram00000000001006f6`); unconditional branches are never printed
  (`printc.cc:2844` skips every BRANCH; the `nofallthru` goto at
  `printc.cc:2868` is unreachable). Reproduce: any data test, `print C flat`
  after `decompile` (e.g. `elseif.xml`).
- Defect: `OptionHideExtensions` is declared (`options.hh:191`) but not
  registered (`options.cc:98-135`), so `hideextensions` cannot be set.

- Possible defect (to confirm): `PrintC::emitPrototypeInputs`
  (`printc.cc:2312-2317`) prints the comma before testing whether the
  parameter is a hidden `this`, so a hidden `this` that is not first gives
  `a,,b`; reachable only with `hide_thisparam` (Java).
- Static `OpToken`s are shared by all printers and `adjustTypeOperators`
  rewrites `scope.print1`/`shift_right.print1` (`printc.cc:2424`,
  `printjava.cc:121`): two languages cannot be used at once.
