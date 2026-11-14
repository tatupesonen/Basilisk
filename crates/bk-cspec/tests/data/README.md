# Test data for `bk-cspec`

| File | What it is | Provenance |
|---|---|---|
| `cspec_oracle.libcxx.txt.gz` | What Ghidra's compiled reader made of every language/compiler pair the reference build's `.ldefs` list (294 pairs, 107 `.cspec` files; two V850 pairs fail in Ghidra itself and are recorded as `PAIRERR`): spaces, the registers the file names, data-organisation alignment, every model with its lists, entries, rules, shared actions, effects, likely trash, internal storage and ranges, payloads, defaults; and for one pair per `.cspec` file (the first in byte order of pair id that Ghidra builds): storage assignment of every signature of `../oracle/signatures.txt` under every non-alias model, trial classification of generated trial sets (inputs and outputs), the list queries over a grid around every entry, `checkJoin`/`checkSplit`, and `hasEffect` around every effect. 152,046 lines, 857 kB compressed. Format at the top of `../oracle/cspec_oracle.cc`. Read by `../oracle_replay.rs` (and, for decode records, the other G tests). | `../oracle/regen.sh /path/to/reference` from Ghidra commit `42db038f3c` (reference build, `scripts/build-reference.sh`, objects with `-ffp-contract=off`), Apple clang 17.0.0 with **libc++**, macOS AArch64, 2026-11-14. Uncompressed sha256 `5b7fe23acdc8cef0…`. |
| `cspec_oracle.libstdcxx.txt.gz` | The same, from the same Ghidra commit built against **libstdc++**. Same pairs, records and line count; 119 rows differ (below). 859 kB compressed. | Same script on the Linux build host (a 20-vCPU x86-64 VM), Debian g++ 14.2.0 with libstdc++, 2026-11-14. Uncompressed sha256 `48c44f43da7d5185…`; identical before and after the host's CPU gained FMA/AVX2. |

The generator is compiled with `-std=c++11 -O1 -fno-access-control
-fsigned-char -ffp-contract=off`. `regen.sh` names the output by the
library the compiler uses; `REGEN_RUNS=20 regen.sh …` runs the generator
20 times and requires byte-identical output (done on both machines,
20/20). `../oracle_regen.rs` regenerates the table of the host's library
when `BASILISK_REFERENCE_DIR` is set and requires it to equal the
checked-in one.

## Host dependence

No value involves floating point, `long`, or an unordered or pointer-keyed
container; pairs are in byte order of their id (Ghidra's own list follows
the filesystem's `readdir` order), models in name order, everything else in
list order, and no record depends on the order C++ evaluates arguments. The
generator defines the four fields Ghidra leaves uninitialised in a merged
model's parameter list before using it (see `cspec_oracle.cc`,
`defineMergedFields`).

What remains is Ghidra's own use of `std::sort` on elements that compare
equal, whose order the C++ standard leaves to the library. The two tables
differ in exactly these rows, each recognised by `../oracle_common/host.rs`
and counted by `../oracle_replay.rs` (ADR-040):

| Cause | Ghidra | Rows | Basilisk |
|---|---|---|---|
| A. effects at one address | `ProtoModel::decode`, fspec.cc:2680 | 56 `EFFECT` (28 lists: NDS32 ×2, RISC-V gcc ×12; `__stdcall`, `__thiscall`) | document order, the default return address last |
| B. `hasEffect` at such an address | `ProtoModel::lookupEffect`, fspec.cc:2463 (last of the tied records) | 24 `EFF` | the last record in document order |
| C. two trials with one address, size and entry | `ParamActive::sortTrials`, fspec.hh:322, from `buildTrialMap`, fspec.cc:921; first kept by `forceExclusionGroup`, fspec.cc:1017 | 38 `TRES` (tricore 24, Loongarch lp64f 14) | the earlier registered (lower slot) first |
| D. trials without an entry | same sort; operator<, fspec.cc:1881, calls them equal | 1 `TRES` (x86-64 golang `abi-internal out` set 107) | the order before the sort (stable) |

Rows where the tables agree must equal Basilisk's. In the libc++ table, A–C
equal Basilisk's rule (an outcome of libc++'s algorithm on these inputs,
not a guarantee); D equals neither table. The 89 effect ties of the earlier
table are 83 tie groups in non-merged models, each checked against the
`.cspec` document order, plus 6 in merged models (intersections of those
lists; both tables agree). The one trial row tolerated before is D's.
