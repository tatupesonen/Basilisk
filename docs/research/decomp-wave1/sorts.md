# `std::sort` and pointer-keyed containers in the decompiler engine

Generated with
`grep -nE "[^_a-z]sort\(" CPP/*.cc CPP/*.hh` and
`grep -nE "(set|map|multiset|multimap)<[^>]*\*[^>]*>" CPP/*.hh CPP/*.cc`
over the `DECCORE` files (SLEIGH, compiler, console and BSim files
excluded), commit `42db038f3c`. `list::sort` and `stable_sort` are stable
and not listed. "Dump path" = the state dump of
`docs/features/decomp-oracle.md` walks the result.

## `std::sort` (34 sites)

| Site | Comparator | Ties possible? | Dump path |
|---|---|---|---|
| block.hh:448 `orderBlocks` | `compareFinalOrder` | yes: two blocks ending in `RETURN` | structure section (top-level order) |
| block.cc:3830 `BlockMap::sortList` | index | only for duplicate indices (hostile XML) | no |
| blockaction.cc:1142 `labelLoops` | head, first tail | yes, unobservable (decomp-cfg.md 4.6) | no |
| funcdata.cc:516 `sortCallSpecs` | block index, op order | no (distinct ops) | callspecs order |
| fspec.cc:2680, 3673 effect lists; fspec.hh:322 trials; fspec.cc:2728 | see ADR-040 | yes (ADR-040) | callspecs/proto sections |
| fspec.cc:2681, 2682, 3694 (`likelytrash`, `internalstorage`: `VarnodeData`), 115, 151, 5906 | value order | equal values are identical | proto sections |
| architecture.cc:675, interface.cc:346 | space index, command name | no | no |
| bitfield.cc:64, constseq.cc:65, 859, cover.cc:630, coreaction.cc:4325, dynamic.cc:148, flow.cc:869, expression.cc:292, jumptable.cc:90, 2616, merge.cc:282, 822, 1308, ruleaction.cc:9354, prefersplit.cc:659, varmap.cc:804, fspec.hh:323 | various | **to be classified by the track that ports the module** (ADR-040: sort stably where ties are possible) | indirectly (results reach ops and varnodes) |

## Pointer-keyed containers that are iterated

None on a dump path. `VarnodeBank`'s two trees are keyed by `Address`,
which for `iop`, `fspec` and `LOAD`/`STORE` space constants holds a host
pointer (varnode.cc:39, 73) — the order is by heap address (runs R5, R6).
`map<HighVariable *,OpRecommend>` (coreaction.cc:3031) is only searched
(the loop at 3049 walks `varlist`); `map<Varnode *,ReplaceVarnode>` is
iterated only to clear marks (subflow.cc:1426); `map<Datatype *,string>`
(type.cc:3752), `map<Varnode *,uintb>` (jumptable.cc:186),
`map<PcodeOp *,…>` (constseq.cc:412, funcdata_block.cc:1098,
subflow.cc:3137) are looked up, not iterated. `SymbolNameTree
multiEntrySet` (database.hh:884) is ordered by name and dedup number
(database.hh:440), not by pointer.
