# Runs against the reference tools

All on the development Mac (`../reference`, Darwin arm64, Apple clang 17,
libc++) unless marked. `CONSOLE` = `echo | SLEIGHHOME=../reference
perl -e 'alarm 300; exec @ARGV' ../reference/bin/decomp -i SCRIPT`.
`DT` = `../ghidra/Ghidra/Features/Decompiler/src/decompile/datatests`.

## R1. `print tree block` (elseif.xml)

Script: `load test file DT/elseif.xml`, `execute test command 1-7`,
`print tree block`, `decompile`, `print tree block`. Before `decompile`
nothing is printed (`Funcdata::printBlockTree` prints only when the
structured graph is non-empty). After: two spaces of indent per level,
`printHeader` per block (`List block 0`, `If/else block 5`,
`Condition block(&&) 27`, `If goto block 32`, `Whiledo block 34`,
`Basic Block 3 0x001006de-0x001006f4`). A `BlockCopy` prints as its basic
block (`BlockCopy::printTree` delegates).

## R2. `structure blocks` on a hand-written graph

`load test file DT/elseif.xml` (any architecture: `XmlDecode` needs one),
then `structure blocks g1.xml g1.out.xml` on a five-node graph (0→1,2;
1→3; 2→3; 3→4,0). Output: nested `<block index=…>` with `<bhead index
type>` children (`list`, `dowhile`, `ifelse`, `copy`), copies carry
`altindex` = the input block's index, `index` = the reverse-post-order
index structureLoops assigned. `orderBlocks` is not called by this
command (it is by `StructureGraph::rawAction`, ghidra_process.cc:352).

## R3. 3,000 random graphs through `structure blocks`

`python3 -I gen_graphs.py 1 3000 40 rand`, one console session with one
`structure blocks` per graph: 0.9 s in total, exit 0, no crash, no hang.
161 graphs end in `Could not finish collapsing block structure`
(`CollapseStructure::selectGoto`); 156 of them have nodes unreachable from
block 0 (an unreachable cycle has no root for `clipExtraRoots` or
`TraceDAG`); the other 5 are reachable graphs with two out-edges of one
block to the same target or with in-edges to the entry. Two runs:
outputs byte-identical (sha256 of all outputs `124c7654…`) and logs
identical.

## R4. The same 3,000 graphs on the build host

`scripts/remote.sh run -- bash -c '…'` with the host's reference
(`$BASILISK_REFERENCE_DIR`, Debian g++ 14.2, libstdc++): exit 0, 161
`Could not finish collapsing block structure`, sha256 of all outputs
`124c7654…` — byte-identical to the Mac (libc++).

## R5. Every data test, with `print raw`, `print tree varnode` and `print tree block` after each `decompile`

`dt_scripts.py` turns each `DT/*.xml` into a console script (commands as
`FunctionTestCollection` passes them: CDATA unwrapped, newlines to
spaces, `testfunction.cc:119`), adding the three prints after every
`decompile`/`dec`; `dt_run.sh REF GHIDRA OUT` runs them (93 files, 5.8 s
on the Mac, every script exit 0, 17,112 output lines) and replaces
`internal=0x…` by `internal=X`.

Two runs on the Mac (`dt_compare.py target/dt1 target/dt2`): 50 files
byte-identical; 43 differ, and only in (a) host pointers printed as
constants — `#0x104b42900`, `#0x…:8` (the `AddrSpace *` constant of
`LOAD`/`STORE`) and `i0x…:4c` (an `iop` varnode whose op is not a branch
prints the op's `SeqNum`… after the pointer-valued offset in `print tree
varnode`) — and (b) the **order** of lines for varnodes in the `fspec`
and `iop` spaces and of pointer-valued constants: `print tree varnode`
walks the bank's def order (`Funcdata::printVarnodeTree`,
funcdata.cc:576), which sorts free varnodes by address, and these
addresses are heap pointers. So the reference's own varnode order is not
reproducible between runs of the same binary (ASLR).

## R6. The same on the build host

Two runs (`dt_compare.py target/dth1 target/dth2`): 52 identical, 41
pointer-only, 0 other. Mac against host after dropping pointer lines,
fspec varnode lines and the lines naming the data-test path: every file
equal except `floatprint` (`floatv6 = NAN;` on the Mac, `-NAN` on the
host — ADR-021's known case).
