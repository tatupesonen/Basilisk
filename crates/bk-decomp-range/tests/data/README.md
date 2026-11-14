# Test data for `bk-decomp-range`

| File | What it is | Provenance |
|---|---|---|
| `circlerange_oracle.libstdcxx.txt.gz` | The results of Ghidra's compiled `CircleRange` (`rangeutil.cc`) for 152,913 cases over every method in scope (rows below), each row **marked** where the C++ is undefined (` #ub=…`) or reads the uninitialised fields of an empty range (` #uninit`). 2.5 MB compressed. Read by `../oracle_replay.rs`: every row must equal Basilisk's. | `../oracle/regen.sh --marks /path/to/reference` from Ghidra commit `42db038f3c` (reference build, `scripts/build-reference.sh`), on the Linux build host (a 20-vCPU x86-64 VM), Debian g++ 14.2.0 with **libstdc++**; marks from Debian clang 19.1.7 (UndefinedBehaviorSanitizer, minimal runtime) and valgrind 3.24.0; 2026-11-14. Uncompressed sha256 without marks `b4710189e2c81270…`. |
| `circlerange_oracle.libcxx.txt.gz` | The same cases from the same Ghidra commit built by Apple clang 17.0.0 with **libc++** on macOS AArch64, without marks. 834 rows differ from the x86-64 table, all for one cause (below). 2.4 MB compressed. | `../oracle/regen.sh /path/to/reference` on macOS AArch64, 2026-11-14. Uncompressed sha256 `981082dc4ee47519…`. |

The generator (`../oracle/circlerange_oracle.cc`) is compiled with
`-std=c++11 -O1 -fno-access-control -fsigned-char -ffp-contract=off` and
linked against the reference build's objects. Every input comes from a
fixed-seed splitmix64 generator whose draws are sequenced one per statement
(C++ leaves the order of function arguments unspecified, and g++ and clang
differ), so the output is a function of the compiled code alone:
`REGEN_RUNS=3` gave byte-identical output on both hosts, for the base and
the extended case set. `../oracle_regen.rs` (kind L) regenerates the table
of the host's library, requires it to equal the checked-in one (marks
ignored), and replays the **extended** case set live (the full counts of
`docs/features/decomp-range.md` 6.2, 592,213 rows, about 21 MB compressed,
not checked in).

## Rows

A range is written `l,r,m,s` — left, right and mask in lower-case hex, the
step in decimal — with a leading `!` when empty. Every row is
`<tag> <inputs> = <results>`, then the marks. A result `f:R` is a boolean
or code `f` and the range `R` the method left behind. Push-forwards start
from the receiver `!5a,a5,ff,3`, so what a method leaves of it shows.

| Tag | Rows | Inputs | Results |
|---|---|---|---|
| `Q` | 88,041 | a range: all 87,040 1-byte ranges with step 1, 2, 4 or 8 and aligned bounds, the empty range, and 1,000 random ranges of 2, 4 or 8 bytes | `getSize`, `getMaxInfo`, `getMax`, `isSingle` and `isFull`, `getNext` from `getMin` (value and flag), `translate2Op` (code, and opcode:constant:slot when 0), `invert` (old step and range), `printRaw`, and `contains(v)`: for 1-byte ranges a 256-bit map of every value, otherwise 8 probes (left, right, left−1, right−1, left+1, 0, the sign bit, the mask) |
| `S` | 2,000 | a range of set B (1,000 from the 1-byte set, 1,000 random) | `setStride` for steps 1, 2, 4, 8, 16 × remainders 0, 1, 3 |
| `UP` | 8,000 | a range of set B, input and output size (each input size 1, 2, 4, 8 with the range's own as output) | `pullBackUnary` of `BOOL_NEGATE`, `COPY`, `INT_2COMP`, `INT_NEGATE`, `INT_ZEXT`, `INT_SEXT`, then the flag of the unhandled `INT_ADD` |
| `UF` | 8,000 | as `UP` (the range's size as input, each output size) | `pushForwardUnary` of `CAST`, `COPY`, `INT_ZEXT`, `INT_SEXT`, `INT_2COMP`, `INT_NEGATE`, `BOOL_NEGATE`, `FLOAT_NAN`, then the flag of the unhandled `POPCOUNT` |
| `P` | 20,000 | two ranges: a 100-range sample of the 1-byte set against itself, then 10,000 random pairs (one in five of mixed sizes) | `intersect`, `circleUnion` (code:range), `contains` and `==`, `minimalContainer(…, 32)`, `widen` (right stable, left stable), `pushForwardBinary` of `INT_ADD` and `INT_MULT` |
| `K` | 2,000 | two random ranges | `pushForwardBinary` of the 16 boolean-valued ops, `PTRSUB` and the unhandled `INT_XOR` |
| `M` | 1,083 | two single values of 1, 2 or 8 bytes | `minimalContainer` for step bounds −1, 0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256 |
| `N` | 8,505 | a mask and a size (every 1-byte value; every run of ones at sizes 2, 4, 8; 2,000 random; odd sizes 0, 3, 9) | `setNZMask` on the receiver `11,33,ffff,2` |
| `B` | 7,184 | a range, opcode, slot, input and output size | `pullBackBinary` with each of 28 constants (0–4, 7, 8, 15, 16, 31, 32, 63–65, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x1234, 0x7fffffff, 0x80000000, 0xffffffff, and the 8-byte signed edges and all-ones): `INT_ADD`, `INT_SUB` (both slots), the unhandled `INT_MULT` over 300 ranges; `INT_RIGHT`, `INT_SRIGHT` over the same ranges at each input size; the seven comparisons over 64 ranges (both outcomes, both, neither), each slot and input size |
| `F` | 6,100 | a range, opcode, input and output size, step bound | `pushForwardBinary` with each of 30 second inputs (single values 0–5, 7–9, 15–17, 24, 31–33, 48, 56, 63–65, 127, 128, 0x20000000, 0x7fffffff, 0x80000000, 0xffffffff, 2^32, all-ones; and a range that is not single): `INT_LEFT`, and `SUBPIECE`, `INT_RIGHT`, `INT_SRIGHT` at each output size, over 400 ranges; and `INT_LEFT` with step bounds −1, 0, 1, 4, 2^20, 2^30 over 150 ranges (these rows: shifts up to 128 only, 24 results) |
| `T` | 2,000 | three random ranges (the second often a single value, the third a small one) | `pushForwardTrinary` of `PTRADD`, then the flag of `INT_ADD` (unhandled) |

## Marks (x86-64 table)

` #ub=<check>@<file>:<line>` — UndefinedBehaviorSanitizer reported `<check>`
at that line of the reference copy of Ghidra's source while computing the
row (`rangeutil.cc:pullBackBinary` is the shift of both bounds by the
constant at lines 961–962 and 989–990, merged by the compiler). Basilisk
computes the value x86-64 produces for every one of these rows (all agree).

| Mark | Rows | What is undefined |
|---|---|---|
| `shift_out_of_bounds@address.cc:1003` | 5,364 | `sign_extend(in, sizein, sizeout)` with `sizeout < sizein`: a negative shift (from the extensions of `pullBackUnary` and `pushForwardUnary` asked to narrow) |
| `shift_out_of_bounds@address.hh:605` | 396 | `sign_extend(intb, bit)` left-shifting a negative value (`INT_SRIGHT` push-forward of an 8-byte range) |
| `shift_out_of_bounds@rangeutil.cc:pullBackBinary` | 2,716 | `left << val`, `right << val` with `val` of 64 or more (`INT_RIGHT`, `INT_SRIGHT`) |
| `shift_out_of_bounds@rangeutil.cc:949` | 712 | `calc_mask(inSize) >> val`, `val` ≥ 64 (`INT_RIGHT` pull-back) |
| `shift_out_of_bounds@rangeutil.cc:975` | 712 | `rightb >> (val + 1)`, `val + 1` ≥ 64 (`INT_SRIGHT` pull-back) |
| `shift_out_of_bounds@rangeutil.cc:696` | 570 | `step <<= shift` in `setNZMask` with a shift of 31 or more on an `int4` |
| `shift_out_of_bounds@rangeutil.cc:1269`, `1270` | 1,227 each | `in1.left << sa`, `in1.right << sa`, `sa` ≥ 64 (`INT_LEFT` push-forward) — the rows that differ on macOS |
| `mul_overflow@rangeutil.cc:1283` | 1,500 | `(int4)in2.left * 8` overflows (`SUBPIECE` push-forward, offsets of 2^28 and more) |
| `shift_out_of_bounds@rangeutil.cc:1288`, `1292`, `1293` | 1,424 each | `SUBPIECE` shifts by `sa` ≥ 64 or negative |
| `shift_out_of_bounds@rangeutil.cc:1308`, `1309`, `1313` | 776, 776, 724 | `INT_RIGHT` push-forward shifts by `sa` ≥ 64 |
| `add_overflow@rangeutil.cc:1331` | 184 | `valRight + 1` with `valRight` = 2^63−1 (`INT_SRIGHT` push-forward to 8 bytes, wrapping input) |
| `shift_out_of_bounds@rangeutil.cc:1334`, `1335` | 1,500 each | `INT_SRIGHT` push-forward shifts by `sa` ≥ 64 |

` #uninit` (2,777 rows) — run under valgrind with the fields of every empty
input range left undefined, the row's printed results depended on them:
`getMax` and `getMaxInfo` of an empty range (119 `Q` rows), `setStride` of
one (119 `S`), and `minimalContainer` and `widen` with an empty range on
either side (2,539 `P`); none of the four looks at `isempty` before reading
the bounds. The table was generated with the fields Basilisk gives an empty
range (0, 0, 0, step 1), so these rows replay exactly.

## Host dependence

The macOS table differs from the x86-64 table in 834 rows (5,185 of the
extended set), all `F` rows of `INT_LEFT` whose shift amount is 64 or more,
recognised by `../common/host.rs` and counted by `../oracle_replay.rs`:
Apple clang vectorises the two shifts at `rangeutil.cc:1269–1270` into one
AArch64 `USHL`, which takes the low byte of the amount as a signed count
(64–127 give 0; 128–255 shift right), where g++'s `shl` on x86-64 takes the
amount modulo 64. Basilisk computes the x86-64 result. Every other row,
including the other undefined ones, is the same on both hosts.
