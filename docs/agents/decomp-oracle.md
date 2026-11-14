# Track `decomp-oracle` (D00) — final report

Contract: `docs/features/decomp-oracle.md` (sections 8–10 appended).
Branch `decomp-oracle`. `bk structure`/`bk cfg` and their formats have
been usable since commits `98733d5`/`a82eeb8`; both shared reference
directories now have `decomp_bk`, `decomp_bk_dbg` and `decomp_dbg`.

## Built

- **Reference build** (`scripts/build-reference.sh`, step `[1b/5]`):
  `bin/decomp_dbg` (`make decomp_dbg`, same overrides, own fingerprint),
  and the extension compiled outside Ghidra's Makefile with the Makefile's
  own flags (read from make through `tools/reference/consoleext/vars.mk`)
  plus `-fno-access-control`, linked with exactly the objects of
  `decomp_opt`/`decomp_dbg` into `bin/decomp_bk`/`bin/decomp_bk_dbg`
  (fingerprint over sources, tools and Ghidra commit). STAMP lists all
  eight tools and `console_extension: <sha256>`.
- **Console extension** (`tools/reference/consoleext/`, 11 C++ files, all
  under 600 lines): `bk version`, `bk list actions`, `bk break
  start|action|clear` (positional), `bk dump blocks|structure|state`, `bk
  cfg analyze`, `bk structure [bare|asgiven] [finish] [trace] [xml f]` (a
  logging replica of `collapseAll` checked against Ghidra's own on a
  second copy), `bk capture structure` (new: every structuring run of one
  decompilation), `bk pcode record|replay|stop` (proxy `Translate`),
  `bk trace stream`.
- **Formats**, all documented in `tools/reference/README.md`: `bkgraph 1`,
  `bkcfg 1`, `bkstruct 1`, `bkactions 1`, `bkstate 1`, `pcoderec 1`, the
  trace.
- **`bk-testkit`**: `Tool::{DecompDbg, DecompBk, DecompBkDbg}` (enum now
  `#[non_exhaustive]`, open for `GhidraHeadless`), `ReferenceDir::
  {decomp_dbg, decomp_bk, decomp_bk_dbg}`, `Decomp::current_dir`, `LC_ALL=C`
  on every console run; `oracle::{graph, cfgdump, structure, actions,
  state, trace, pcoderec}` — typed readers with line-numbered `thiserror`
  errors, size limits, no recursion, byte-identical writers;
  `oracle::generate` (SplitMix64 graph generator, R3's shape);
  `oracle::host` (library detection, FNV digests, grouped digest tables,
  ADR-040 named-cause classifier with causes `nan-sign`, `nan-order`);
  `oracle::capture` and the binary `bk-oracle` (`capture`, `compare`,
  `check`). No new dependency (flate2, already in the workspace, added to
  bk-testkit).
- **Nightly**: item `oracle` (`tools/testbed/oracle.sh`), every night after
  gate and wine.
- **Fixtures**: `fixtures/decomp-oracle/` (summary, both builds' digest
  tables, hostdiff, README). Repository size added: 364 kB of data files
  (fixtures 130 kB, samples ~230 kB, fuzz regressions); about 15,300
  source lines.

## Acceptance evidence

1. **Build** — both shared references rebuilt by the new script (Mac:
   direct run; host: `scripts/remote.sh setup`). Every file hashed before
   and after (1,986 files each, 400 `.sla/.ldefs/.pspec/.cspec`, all of
   `bin/`, `src/`, `.state/`, `logs/`): round 1 changed **only `STAMP`**
   among existing files and added 221 files (3 bin, 3 .state, 2 logs, 22
   extension objects, 190 `com_dbg/` objects, `src/cpp/decomp_dbg`); round 2
   (one extension source changed) changed only STAMP and my own round-1
   files (`decomp_bk`, `decomp_bk_dbg`, two `bk_capture.o`,
   `.state/consoleext.fp`). `bin/decomp` byte-identical:
   Mac `3f6606af…71ae5`, host `a6183fe3…ccdc04`. Test 6.7 on scratch copies:
   second run does no work ("nothing to do", 2 s); an extension source
   change relinks only `decomp_bk*`; `decomp_bk` is byte-reproducible, the
   Mac's `decomp_bk_dbg` is not (Apple ld's debug map records object
   time stamps). STAMP tools blocks: Mac `decomp_dbg 329ed29f…`,
   `decomp_bk c70b17b5…`, `decomp_bk_dbg 32c6033c…`; host `decomp_dbg
   a5f6f14f…`, `decomp_bk 1dc6ea59…`, `decomp_bk_dbg 743bafbb…` (round 1;
   round 2 changed only the `_bk` lines); `console_extension b1b3c1b3…`.
2. **Completeness** (6.2) — `bk-oracle capture all`, both builds: 167
   scripts (93 data tests, 74 research fragments; 2 fragments skipped
   because they fail in plain `decomp` too: `a07_switch.{a64,x64}-gcc-O2`,
   `map addr … CSWTCH.4[40]` does not parse), 607 decompilations
   (193 data-test, 414 research), every end dump complete: 11,005 ops and
   18,134 varnodes checked against `print raw`/`print tree varnode`
   (`summary.txt`).
3. **Replay** (6.3) — every recording replayed: identical `print raw` after
   `start` for every decompilation of every script, both builds; no
   context-dependent address in any recording.
4. **Readers** — 145 unit/property tests in the lib; fuzz 300 s × 5 targets
   on the host: first run 5 findings (one real identity break: raw NUL in a
   text field; four OOM/timeouts caused by the harness), fixed, saved under
   `fuzz/regressions/bk_testkit_*`, replayed by `tests/fuzz_regressions.rs`;
   second run **0 findings** (graph 2.5 M, structure 1.9 M, state 120 k,
   trace 11.7 M, pcoderec 126 k executions).
5. **Formats documented** — README sections for all seven.
6. **Optional logs** — not delivered; reasons in the feature doc §10.2
   (hooks needed in ~60 non-virtual `Funcdata` methods, several inline;
   `PrintLanguage` pushes likewise; an `Emit` wrapper is not transparent at
   the `PrintLanguage`→`Emit` boundary because `Emit` keeps non-virtual
   state — it would be below `EmitPrettyPrint`).
7. **6.4–6.7 and determinism** — 6.4: 3,000 generated graphs, `structure
   blocks` XML = `bk structure … xml` byte for byte, 165 end in Ghidra's
   error, the replica never differs (Mac and host, `tests/oracle_cfg.rs`).
   6.5: every capture twice per build, identical (8,536 files); Mac
   against host: 5 files differ, all `floatprint`, all recognised: nan-sign
   48 lines, nan-order 8 (pinned in `tests/oracle_state.rs`). 6.6:
   `decomp_dbg` = `decomp` for every script, both builds. 6.7: above.
   Also: all 767 captured structuring runs are reproduced exactly by `bk
   structure … asgiven` (checked by the driver every capture).
8. **Nightly** — `tools/testbed/oracle.sh` run from this branch on the host
   through `scripts/remote.sh run`: exit 0, 0 failures, no drift against
   the fixtures, 31 s. `scripts/remote.sh nightly run oracle` ran once; it
   tests the host's `master`, which does not have the item yet, so its
   report says `oracle SKIP unknown item` (report 2026-11-14T173802). After
   the merge and `publish`, the nightly runs it every night.
9. **Gates** — see the end of this report.

Other checks: Windows clippy (`--target x86_64-pc-windows-msvc`) clean;
`scripts/remote.sh wine -- -p bk-testkit`: 168 passed, 0 failed (an earlier
run caught a test that assumed `/` separators: fixed);
`scripts/check-dep-age.py master`: 0 new packages; `cargo metadata
--manifest-path fuzz/Cargo.toml` fine. valgrind (host) on five data tests
through every dump point, recording and `bk capture structure`: clean after
the three fixes below.

## Differences from Ghidra / spec items found wrong (source wins)

Recorded in the feature doc §8. In short:
1. `list action` numbers are padded with the stream's sticky fill (spaces in
   a fresh console), not zero-filled; `bk list actions` uses a fresh stream.
2. 4.4 `@callspecs` `matchCallCount`: never initialised or set
   (`countMatchingCalls` has no caller) — left out.
3. 4.4 `@jumptables` `maxtablesize/maxaddsub/maxleftright/maxext` are not
   `JumpTable` state; `recoverCount`, `displayFormat`, `block2addr`,
   load tables, original model written instead.
4. 4.4 `@heritage` has no `disjoint` member (local to `heritage()`).
5. 4.4 `@c` "when processing_complete": the flag survives
   `Funcdata::clear`; also requires the root action not stopped mid-way.
6. 4.4 `Action::count/lcount` and `FuncProto::extrapop` are uninitialised
   until Ghidra sets them (valgrind on the host; the Mac showed zeros) —
   written `-` until then.
7. 4.3: an `fspec` varnode may point at a deleted call spec (`call:-`); a
   space constant's `nzm` is the pointer (written as the key).
8. 4.7 fact blocks: kept `t_plain`, not `t_basic`.
9. 4.7 `bk dump structure` leaves: position in `bblocks` (= index after
   `structureReset`).
10. 4.10 `bk break start` on a rule never stops in Ghidra: an error here.
11. 4.10 needs a command for every structuring run (`bk capture structure`).
12. 4.2 "one make invocation for all targets": a separate `make decomp_dbg`
    — putting it in step 1 would rerun step 1 on every existing reference.
13. 5.3 `dump_state_at/trace/record_pcode` helpers on `Decomp`: done as
    `oracle::capture` (scripts by positions), which the driver and tests use.

## Open items settled (feature doc §10)

1. Field lists = class members at `42db038f3c`; jump-table models by kind
   only (D13 amends to v2 if it needs `JumpBasic` internals).
2. Hook patches: not practical in this track (above).
3. `orderBlocks` ties in the corpora: **0** — in all 607 decompilations the
   final top level is a single node, so `orderBlocks` sorts nothing.
4. No output dependence on pointer order seen (two builds × two runs agree
   except NaN sign).

## What D04 and D05 should be told

- **D04**: the shared references have `decomp_bk`; `bk capture structure`
  gives the corpus graphs: **767 structuring runs over 607 decompilations**
  (both corpora). Its `.blocks.bkg` files carry the switch-default labels
  (`installSwitchDefaults` is applied as `ActionBlockStructure` does next);
  plain `bk dump blocks` at a `blockstructure` stop does **not** — 9 switch
  runs differed by the `0x4` default label until this was done. With them,
  `asgiven` reproduces Ghidra's hierarchy in all 767 runs. decomp-cfg.md
  6.3 item 2 could be amended to: "D00's capture driver runs `bk capture
  structure` at each `decompile`; it writes `<prefix>.<k>.blocks.bkg` (with
  the switch defaults installed) and `<prefix>.<k>.structure.bks` per
  structuring run, and `.final.*`/`.end.*` structure and state." Graph
  readers: `bk_testkit::oracle::{GraphFile, CfgDump, StructureDump}`;
  `GraphFile::to_ghidra_xml` / `from_out_edges` for generated graphs.
- **D05**: dumps at the four standard points come from `oracle::capture`
  (positions by path; `universal:start`'s successor, first `oppool1`,
  `cleanup`, `stop`); `StateDump` gives typed records; varnode and op ids,
  both bank orders with canonical keys (`DeadCall` sorts last); count and
  extrapop may be absent. The mutation log is not available — use the
  fall-back (re-dump comparison). The `@c` caveat (stale
  `processing_complete`) matters for re-decompilation.

## Follow-ups (Ghidra defects and notes for docs/GHIDRA-BUGS.md)

1. **Dangling call-spec pointer in an `fspec` varnode** —
   `Funcdata::blockRemoveInternal` (`funcdata_block.cc` ~333) calls
   `deleteCallSpecs` (`funcdata.cc:521`, `delete fc`), but the call's `fspec`
   varnode stays in the bank with the freed pointer as its offset; `print
   tree varnode` then dereferences it (`FspecSpace::printRaw`,
   `fspec.cc:2152`) — use after free. Seen in `inline.xml` (decompilations
   1 and 2, at the action after `start`). The oracle writes `call:-` and
   never dereferences.
2. **`processing_complete` survives `Funcdata::clear`** (`funcdata.cc`, the
   `flags &= ~(…)` list omits it): during a second decompilation of a
   function `isProcComplete()` is true at every stop, and `print C` there
   throws "No structure present". Only the consoles read it.
3. **Uninitialised members** (not read by Ghidra before set, but by any
   inspector): `Action::count`/`lcount` (`action.cc:27`),
   `FuncProto::extrapop` until `setModel` (`fspec.cc` constructor),
   `FuncCallSpecs::matchCallCount` never set (`fspec.hh:1678`).
4. `list action` output depends on earlier commands (sticky stream fill).

## Gaps

- Optional logs (4.12) not delivered (reasons above).
- The nightly item has run only from the branch; the master nightly will run
  it after merge + publish.

## Commits

`git log --oneline master..HEAD` (22 commits, `98733d5` … plus this report).

## Gates

(filled in below)
