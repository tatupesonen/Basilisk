# Runs (D06)

Mac: `../reference` (Darwin arm64, Apple clang 17, libc++). Host: the
build host's reference (`$BASILISK_REFERENCE_DIR`, Debian g++ 14.2,
libstdc++), through `scripts/remote.sh run -- bash -c '…'`. Every run with
`LC_ALL=C`. `DT` = the data-test directory of the Ghidra tree.

## W1. Console: `print map` and `dump` (Mac)

`decomp_bk -i` with `load test file DT/elseif.xml`, `print map`,
`execute test command 1-6`, `print map`, `dump [ram,0x1006ca,32]`,
`dump [ram,0x100000,16]`. The global scope prints an empty name line,
its bounds (`OTHER: 0-ffffffffffffffff`, `ram: 0-ffffffffffffffff`,
`register: 1094-1097`) and `Scope ` with no entries: the x86-64 pspec
has no default symbols and elseif's image has no `<symbol>` (loader
symbols are read by `readLoaderSymbols` at load). After `lo fu`
`print map` prints the function's local scope:
`b : %0x00000030:4 int4 : ram: 1006c9-1006c9` (the parameters' use point
is the entry address minus one, `funcp.setScope(localmap,baseaddr+-1)`,
funcdata.cc:69). `dump` prints 16 bytes a line; an unmapped read prints
`Low-level ERROR: Bytes at 0x00100000 are not mapped` and aborts the
script.

## W2. `image_oracle` on all 93 data tests (Mac and host)

`sh build.sh REF image_oracle.cc OUT; OUT REF DT/*.xml`. 0.34 s on the
Mac. Output 8,435 rows: 93 `F`, 0 `E`, 349 `K` (chunks after `pad()`),
248 `Y`, 173 `R`, 93 `D`, 403 `P`, 273 `B`, 751 `M` (93 headers + 658
entries: 248 loader functions, 410 default symbols from the 8051, ARM,
AARCH64, 68000, MIPS, PowerPC pspecs), 3,784 `V`, 93 `c`, 180 `C`, 93
`t`, 158 `T`, 1,744 `L` (432 of them `err`). Host: two runs
byte-identical; after ordering by file (the shells expand `DT/*.xml` in
different orders) identical to the Mac. Architectures among the 93:
x86-64 gcc 71, x86-64 windows 3, x86-32 gcc/win/windows 1 each, AARCH64 3,
ARM v8 2, MIPS BE 3, MIPS LE 3, PowerPC BE 2, 68000 1, 8051 1, Toy 1.

## W3. `scope_oracle` (Mac and host)

`OUT REF DT/elseif.xml 1 2000` (seed 1, 2,000 cases). First version
crashed twice, both Ghidra defects:

* SIGSEGV in `FuncProto::encode` (`model->getName()` on a null model,
  fspec.cc:4569) when `ScopeInternal::encode` writes an instantiated
  `FunctionSymbol` whose `Funcdata` never got a prototype model. The
  oracle hides the `Funcdata` so the symbol encodes as `<functionshell>`.
* SIGSEGV in `rangemap::erase` (lldb) from `Scope::addMapSym`'s handler:
  a `<mapsym>` whose entry runs past the end of its space makes
  `ScopeInternal::addMapInternal` throw *after* pushing the entry onto
  the symbol's list (database.cc:2000 then 2010–2015); the handler's
  `removeSymbol` erases an entry that was never inserted (its
  `mapIterator` is indeterminate). The oracle keeps stack addresses
  clear of the wrap.

The first host run differed from the Mac from the first case: the
generator drew random numbers in function arguments, whose evaluation
order differs between clang and g++. With one draw per statement: 205,104
rows, two runs per host byte-identical, Mac and host byte-identical
(sha256 `9e35847e…`). Row kinds: +sym 13,852, +func 4,521, +label 4,557,
+extref 4,524, +equate 4,688, +mapsym 4,634, +map 3,789, rename 1,117,
retype 631 (212 `Unable to retype symbol`), remove 946, lock 1,119,
unlock 1,164, cat 990, 13 address-query kinds 6,072–6,264 each, name
queries 4,749–4,890 each, depth 11,314, buildVariableName 12,000, and per
scope print/xml/multi/cats 5,112 each; 1,451 warnings (`Function … overlaps
object`, `Codelabel … overlaps object`).

## W4. `context_oracle` (Mac and host)

`OUT REF DT/elseif.xml 1 2000`: 85,713 rows (6,988 variables, 10,926
operations, 32,000 look-ups, 32,000 tracked look-ups, 2,000 encodings,
1,799 re-decodings). Re-decoding equals the encoding except in 16 cases
where every tracked set is empty: `encode` writes `<context_points/>`
(the split points exist, `encodeTracked` skips empty sets), decoding it
creates nothing, and encoding again writes nothing. Host: two runs
identical; against the Mac the only difference was the oracle printing
the offset of an invalid `Address` (uninitialised), fixed afterwards.

## W5. Duplicate names in the `decompile` root (Mac)

`decomp_bk -i` with `load test file DT/elseif.xml` and `bk list
actions`: 243 lines; names (last path component) occurring twice:
`blockstructure`, `deadcode`, `directwrite`, `dynamicsymbols`,
`prefercomplement`, `structuretransform`, `unreachable` — seven, not the
nine the old `decomp-ir.md` stated.

## W6. Counts read with grep (no run)

* `TypeOp::registerInstructions` registers 73 opcodes (`inst[CPUI_…]`
  lines); typeop.cc defines 74 `TypeOp…::TypeOp…` constructors; the
  `OpCode` enum names 73 opcodes, `CPUI_MAX` = 75.
* `debugModCheck`: 12 calls in funcdata_op.cc, 1 in funcdata_varnode.cc
  (`destroyVarnode`), 0 in funcdata_block.cc.
* `PcodeOp::special` appears 15 times in typeop.cc.
* `Funcdata::newIndirect` callers: funcdata_op.cc:704, 729;
  coreaction.cc:1561; constseq.cc:456, 912; double.cc:1367;
  ruleaction.cc:1001; transform.cc:233. No `opSetOpcode(…, CPUI_INDIRECT)`.
