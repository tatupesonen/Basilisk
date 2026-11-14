# Why Ghidra's C++ SLEIGH compiler gives different `.sla` on two hosts

Track `sla-host-diff`, 2026-11-14. Question from ADR-029: 14 of the 150
reference `.sla` files differ between the macOS AArch64 build
(`../reference`, Apple clang 17, libc++) and the x86-64 Linux build
(`../reference-x86_64/x86_64-linux`, GCC 14.4, libstdc++). What differs,
why, does it matter, and what should Basilisk do?

Each claim is marked **[measured]** (command or experiment given),
**[source]** (file and line read) or **[judgement]**. Tools:
`tools/sla-host-diff/` (README lists every command); container scripts and
patches in `tools/sla-host-diff/containers/`. Raw evidence checked in
under `docs/research/sla-host-dependence/`: `classify-mac-vs-x86.txt`,
`trace-ties.txt` (the 25 ties), `equiv-mac-vs-x86.txt`,
`java-tie-nodes.txt`, `pcodedump-compare.txt`, `logtables.txt` and
`logtable-glibc.txt.gz` (the proposed test table). Paths below abbreviate
`T=tools/sla-host-diff/target/release/sla-host-diff`,
`MAC=/Users/tatu/slop/reference/Ghidra`,
`X86=/Users/tatu/slop/reference-x86_64/x86_64-linux/Ghidra`,
`CPP=/Users/tatu/slop/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
(Ghidra commit `42db038f3c`, version 12.3-DEV).

## Summary

* **Cause: floating-point contraction of one line**, `sc -= p * log(p)` in
  `DecisionNode::getScore` (`CPP/slghsymbol.cc:2135`). Compilers targeting
  AArch64 fuse it into one multiply-subtract (`fmsub`, a single rounding);
  x86-64 compilers without `-mfma` round the product first. At 25 decision
  nodes in the 150 specifications two candidate fields have *mathematically
  equal* scores (the same multiset of bin counts, summed in a different
  order); the last-bit difference between fused and unfused arithmetic
  decides which field `chooseOptimalField`'s strict `sc > score`
  (`slghsymbol.cc:2172`, `:2189`) keeps. Not the standard library, not
  `std::sort`, not pointer order, not the operating system.
* **Isolated by experiment** [measured]: same machine and toolchain, only
  the contraction changed, flips the output both ways — macOS clang with
  `-ffp-contract=off` gives x86-64's bytes for all 150; GCC on emulated
  x86-64 with `-mfma` gives macOS's bytes for all 14; a one-line patch that
  rounds the product, with default flags on macOS, gives x86-64's bytes.
  Every AArch64 build (macOS clang/libc++, Linux GCC/libstdc++, Linux
  clang/libc++) gives macOS's bytes; every unfused build gives x86-64's.
* **What differs** [measured]: only decision trees, in 1–2 tables per
  file, at exactly those 25 nodes and the subtrees below them. Symbols,
  ids, constructors, operands, print pieces, context changes, templates
  and pattern blocks are identical. Not a renumbering or reordering: the
  tied node tests a different field, so the subtree below it has a
  different shape, but the same set of (constructor, pattern) pairs.
* **Behaviour is identical** [measured]: each of the 25 differing subtrees
  resolves every input (every assignment of every bit any of its patterns
  constrains, exhaustively, up to 2^25 inputs) to the same constructor in
  both variants; with identical constructors and templates the p-code is
  therefore identical. Reference `pcodedump` on 2 MB of random bytes per
  language (plus all 65,536 first words for MSP430) gives byte-identical
  output with either variant.
* **`log` matters too** [measured]: with unfused arithmetic, Apple's
  `log` and glibc's (both its FMA and non-FMA variants) give x86-64's
  bytes for all 150, but **fdlibm's `log` — the `libm` crate ADR-024
  chose — changes ARM8_le and ARM8m_le** (one more tied node each). The
  four `log`s disagree in the last bit on most of the inputs the compiler
  can give them.
* **Ghidra's shipped files** (compiled by the Java compiler) agree with
  x86-64 at all 25 contraction nodes: Java never contracts [source]. But
  Java's `Math.log` is host-dependent: the official 11.4.2 release agrees
  with glibc at the ARM8 `log`-sensitive node, while Homebrew's 12.0
  (built from source on Apple silicon) agrees with fdlibm [measured].
* **Recommendation**: keep x86-64 Linux as the byte oracle for all 150 —
  its result is now a defined computation (unfused IEEE `f64` arithmetic,
  glibc's `log`), not an accident. Basilisk must compute the score
  without contraction (Rust never contracts) and with a `log` bit-equal to
  glibc's on every `k/n` the compiler can produce, checked by an exhaustive
  test; not `libm::log`. Add `-ffp-contract=off` to the reference build so
  every host produces the x86-64 bytes. ADR-029 revision text in the last
  section.

## 1. What differs

**Verification of the 14/136 split** [measured]:
`T scan $MAC $X86` pairs the 150 files by name and compares the inflated
streams: 136 identical, 14 differ, the 14 of ADR-029.

| file | stream length mac → x86 | first difference | `bk_sla::diff` entries | tables | tied nodes |
|---|---|---|---:|---|---:|
| AARCH64 | 4,049,360 → 4,049,320 | 86.6 % | 2 | fcvt_vmnemonic | 1 |
| AARCH64BE | 4,051,737 → 4,051,697 | 86.6 % | 2 | fcvt_vmnemonic | 1 |
| AARCH64_AppleSilicon | 4,059,932 → 4,059,732 | 62.9 % | 8 | instruction, fcvt_vmnemonic | 2 |
| ARM8_le | 2,252,470 (same) | 40.9 % | 26 | instruction | 2 |
| ARM8m_le | 2,533,408 (same) | 41.9 % | 26 | instruction | 2 |
| mips32le | 1,374,729 (same) | 56.6 % | 5 | instruction | 1 |
| mips32R6le | 1,364,151 (same) | 56.4 % | 5 | instruction | 1 |
| ppc_64_isa_le | 1,709,606 (same) | 80.6 % | 6 | instruction | 1 |
| ppc_64_isa_altivec_le | 1,519,274 (same) | 77.3 % | 6 | instruction | 1 |
| TI_MSP430 | 230,440 → 229,872 | 60.3 % | 14 | DEST_W_AD, DEST_B_AD | 2 |
| TI_MSP430X | 705,759 → 705,191 | 72.3 % | 14 | DEST_W_AD, DEST_B_AD | 2 |
| tricore | 1,812,759 → 1,812,779 | 90.2 % | 27 | instruction | 1 |
| x86 | 3,508,655 → 3,508,935 | 71.1 % | 24 | instruction | 4 |
| x86-64 | 4,470,295 (same) | 70.5 % | 16 | instruction | 4 |

Commands: `T scan $MAC $X86` (lengths, offsets), `T classify $MAC $X86`
(entries by path kind, tree analysis), `T trees A.sla B.sla -v`.

**Classification** [measured, `T classify`]: every `bk_sla::diff` path in
all 14 files has the form `table "<T>" decision…` (the node heads, the
pair counts and pairs of leaves below the tied node). No difference in
header, spaces, scopes, symbol table (names, ids, kinds), constructors
(operands, print pieces, context changes, templates) or any pattern
outside the trees. `T trees` walks both trees in parallel: they are
identical (same node heads, same leaf pair lists in the same order)
everywhere except at the tied nodes, where the field differs — e.g.
TI_MSP430 `DEST_W_AD` node `root/1/9` tests instruction bits 4..6 on macOS
and 6..7 on x86-64; x86 `instruction` `root/2/12/2` tests context bits
34..35 on macOS and 12..15 on x86-64. No leaf anywhere is merely
reordered. Below a tied node the subtrees differ in shape (node counts
differ, e.g. `fcvt_vmnemonic` 23 vs 19 nodes) but contain the same set of
(constructor, pattern) pairs (`T equiv`, "same set").

So the two models are **not** equal up to renumbering or reordering; they
are equal except for the choice of split field at 25 decision nodes (and
the subtrees that choice induces), and the subtrees are equal as
functions (section 4).

## 2. The cause, isolated by experiment

All builds use `scripts/build-reference.sh`'s make line (`-O2 -std=c++11
-w -DLOCAL_ZLIB -fsigned-char`) on a copy of `../reference/src` (Ghidra's
sources plus the reference patch), via
`tools/sla-host-diff/containers/build-sleigh.sh` (`run.sh` for
containers: `--cpus 3`, self-killing after a time limit, `--rm`). Images:
`2534543d1c5c` (`gcc:14`, linux/amd64, GCC 14.4.0, glibc 2.41, run under
emulation), `bk-sla-host-diff/gcc14:arm64` (`gcc@sha256:2bafb163…`, the
arm64 variant of the same `gcc:14` release: GCC 14.4.0, glibc 2.41),
`ubuntu:26.04` arm64 + `clang`/`libc++` (clang 21.1.8, glibc 2.43),
`alpine:3.22` (musl 1.2.5) for `log` tables only. "= x86" means
byte-identical inflated streams to `../reference-x86_64` (`T scan`).

| # | host | compiler, C++ library | `log` | flags / patch | 14 specs | all 150 |
|---|---|---|---|---|---|---|
| E1 | macOS arm64 (native) | Apple clang 17, libc++ | Apple | reference | = mac | — |
| E2 | Linux arm64 (container) | GCC 14.4, libstdc++ | glibc | reference | = mac | — |
| E3 | Linux amd64 (emulated) | GCC 14.4, libstdc++ | glibc (FMA ifunc) | reference | = x86 | = x86 |
| E4 | Linux arm64 | clang 21, libc++ | glibc | reference | = mac | — |
| E5 | macOS arm64 | Apple clang 17, libc++ | Apple | `-ffp-contract=off` | = x86 | = x86 |
| E6 | Linux arm64 | GCC 14.4, libstdc++ | glibc | `-ffp-contract=off` | = x86 | — |
| E7 | Linux amd64 | GCC 14.4, libstdc++ | glibc | `-mfma` | = mac | — |
| E8 | macOS arm64 | Apple clang 17 | Apple | `patches/unfused-getscore.patch` (rounds the product in `getScore` only) | = x86 | — |
| E9 | Linux amd64 | GCC 14.4 | glibc non-FMA (`GLIBC_TUNABLES=glibc.cpu.hwcaps=-FMA,-AVX2,-FMA4`) | reference | = x86 | = x86 |
| E10 | macOS arm64 | Apple clang 17 | Apple | `score-config.patch`, unfused | = x86 | = x86 |
| E11 | macOS arm64 | Apple clang 17 | Apple | `score-config.patch`, fused (`std::fma`) | = mac | = mac |
| E12 | macOS arm64 | Apple clang 17 | fdlibm | `score-config.patch`, unfused | 12 = x86 | 148 = x86; ARM8_le, ARM8m_le differ |
| E13 | macOS arm64 | Apple clang 17 | fdlibm | `score-config.patch`, fused | — | 144 = mac; ARM7_be/le, ARM8_be/le, ARM8m_be/le differ |
| E14 | Linux arm64 | GCC 14.4 | glibc | `score-config.patch`, unfused / fused / fdlibm unfused | — | = x86 / = mac / as E12 (ARM8_le byte-identical to E12's) |

Reading the table [measured]:

* E1 reproduces the macOS reference and E3 the x86-64 reference, so the
  build recipe is faithful on both sides.
* Standard library and compiler family are ruled out: E2 (libstdc++, GCC)
  and E4 (libc++, clang) on Linux arm64 both give macOS's bytes.
* Operating system and `libm` are ruled out as the cause of the 14: E2
  (glibc) equals E1 (Apple libm); E5/E10 (Apple libm, unfused) equal x86.
* Architecture as such is ruled out: E7 is x86-64 and gives macOS's
  bytes once FMA is enabled; E5/E6 are AArch64 and give x86-64's bytes
  once contraction is off.
* E8 localises it to the one statement: a patch that only rounds the
  product in `getScore` (default flags) turns macOS output into x86-64's.
* E10/E11 (one binary, run-time switch) reproduce both hosts' 150 files
  exactly from the fused/unfused choice alone.

**Object code** [measured, `objdump -d` of `slghsymbol.o`, function
`DecisionNode::getScore`]: E1 `fmsub d11, d9, d0, d11` after the `log`
call; E5 `fmul` then `fsub`; E2 (GCC, aarch64) `fmsub d14, d0, d15, d14`;
E7 (`-mfma`) `vfnmadd231sd`. Clang's default is `-ffp-contract=on`
(contract within an expression); GCC 14 contracts too under
`-std=c++11` on these targets [measured].

**The ties** [measured, `patches/trace-score.patch`, build `mac-trace`,
`SLEIGH_TRACE_SCORE=1`]: the patch reruns each node's field choice with
explicit fused (`std::fma(-p, log(p), sc)`) and unfused (product stored to
a `volatile`) arithmetic and prints every node where the two choose
differently. It prints exactly 25 nodes over the 14 files — one per
shape difference of section 1, none elsewhere — and at each the native
build matched the fused choice. In every case the two fields have the
**same multiset of bin counts**, so their entropies are mathematically
equal, and the computed scores differ by 1–2 units in the last place.
Example, TI_MSP430 `DEST_W_AD root/1/9` (7 patterns):

```
fused   picks ins[4..+3] score 0x1.859d146267a17p+0 (1.5219280948873626)
unfused picks ins[6..+2] score 0x1.859d146267a17p+0 (1.5219280948873626)
field ins[4..+3]: fused 0x1.859d146267a17p+0 unfused 0x1.859d146267a17p+0 counts [0]=2 [1]=2 [4]=1
field ins[6..+2]: fused 0x1.859d146267a15p+0 unfused 0x1.859d146267a17p+0 counts [0]=2 [1]=1 [2]=2
```

Counts {2,2,1} in bin order (2,2,1) vs (2,1,2): unfused, both sums round
to the same value, the 2-bit field (scanned first) is kept and the 3-bit
one does not beat it; fused, the 2-bit field's sum comes out 2 ulp lower
and the 3-bit field wins. All 25 are in `sla-host-dependence/trace-ties.txt`.

Not every tie is resolved "first field wins" by x86-64 either: at x86
`root/2/12/2` the unfused score of the later field is 1 ulp higher, so
x86-64 picks the later one. No simple rule ("keep the first", "prefer
smaller") reproduces x86-64; only its arithmetic does [measured, trace].

**The `log` dimension** [measured]. `containers/logtable/logtable.c`
hashes the bits of `log(k/n)` for 1 ≤ k < n ≤ 16,384 (the largest table
has about 9,356 distinct patterns, so `total` stays below that: `T maxpatterns $MAC`), one line per n; `T logtable
libm|std 16384` does the same in Rust; `crlog.py` computes the correctly
rounded values (60-digit `decimal`). Lines (values of n) whose hash
differs from glibc on arm64:

| `log` | n differing from glibc (of 16,383) |
|---|---:|
| glibc 2.41 amd64, FMA variant (emulated CPU has FMA) | 0 |
| glibc 2.41 amd64, non-FMA variant (E9 tunable) | 8,688 (identical to musl amd64) |
| musl 1.2.5 arm64 | 1,135 |
| Apple libm (macOS 26) = Rust `f64::ln` on macOS | 15,641 |
| fdlibm = `libm` crate 0.2.16 `log` (C transcription in `score-config.patch` verified bit-equal) | 16,366 |
| correctly rounded (first 300 n only) | glibc 21 of 300, Apple 30, fdlibm 282 |

None of these is correctly rounded on the domain, and they disagree with
each other on most n. E5/E9/E10 show that glibc-FMA, glibc-non-FMA and
Apple's `log` happen to give the same 150 files; E12/E14 show fdlibm does
not (one extra tie flips in ARM8_le and ARM8m_le, at `root/1/0/6/1/0`
resp. `root/0/1/6/1/0`: x86-64 `ins[13..+3]`, fdlibm `ins[12..+4]`).

**Where the x86-64 result could still vary** [judgement, from E9]: glibc
selects its `log` by CPU (`ifunc`); the two variants differ in the last
bit on half the domain. They give the same 150 files today, but a future
specification could separate them; "x86-64's bytes" should be pinned to
"glibc's FMA-variant `log`", which is also what every AArch64 glibc and
every x86-64 CPU since 2013 runs.

**A decisive run on real x86-64 hardware** (only to confirm emulation is
faithful; E3/E9 already agree with the lent box's files): in the lent
box's container, `WORK=… tools/sla-host-diff/containers/build-sleigh.sh
$WORK fma-check g++ "-mfma" TI_MSP430` — `TI_MSP430.sla` equal to the
macOS reference confirms the mechanism on real hardware; equal to the
x86-64 reference would mean the compiler did not contract (check
`objdump` for `vfnmadd`).

## 3. The mechanism in the source

[source] `CPP/slghsymbol.cc`:

* `DecisionNode::getScore` (2110–2138): bins the patterns that fully
  specify the field, then `for i in 0..numBins: if count[i] > 0: p =
  count[i]/total; sc -= p * log(p);` (**2135**), `return sc / log(2.0)`
  (2137). Bins are visited in value order, so two fields with the same
  count multiset sum the same terms in different orders.
* `DecisionNode::chooseOptimalField` (2140–2201): first pass over 1-bit
  fields, context then instruction, ascending start bit, with the
  "more patterns fixed and positive score resets" rule (2163); second
  pass over sizes 2..8, context then instruction, ascending start bit.
  Both keep the earlier field unless `sc > score` (**2172**, **2189**) —
  a strict comparison of two doubles that are equal in exact arithmetic
  at the 25 nodes.
* `DecisionNode::split` (2221–2257) recurses with the chosen field;
  `orderPatterns` (2259) orders each leaf.

The candidates ADR-029 listed are excluded by source reading as well as
by experiment: the back half has no `std::sort` (the only sort in these
files is `stable_sort` of the context table, `slgh_compile.cc:2523`, which
is stable and keyed by value), and pointer-keyed containers are used for
lookup only (`inventory/01-sleigh.md` 10(e)3). `log` is the only host
library call in the computation, and contraction of 2135 the only
compiler freedom (the C++ standard permits contraction within an
expression; `FP_CONTRACT` defaults are implementation-defined).

Proof by instrumented build: `patches/trace-score.patch` (prints the
tie, section 2) and `patches/unfused-getscore.patch` (E8: changing only
line 2135 flips the output).

## 4. Does it change behaviour?

**Argument** [judgement]: identical constructors, operands and templates
mean identical p-code for the same constructor choices; the trees differ
only below the 25 nodes, and above them both trees route every input the
same way. Below a node N, a leaf reached by input x holds the patterns of
N's list consistent with x on the tested bits; every pattern that
*matches* x is in that leaf in both variants. The variants can disagree
only if the leaves' `orderPatterns` orders put different matching
patterns first, which requires non-nested overlapping patterns.

**Exhaustive check** [measured, `T equiv $MAC $X86`,
`tools/sla-host-diff/src/equiv.rs`]: for each of the 25 nodes, the
subtrees are compared as functions by Ghidra's `resolve` rules
(`context.cc` bit order, `PatternBlock::isInstructionMatch`), over every
assignment of the union of bits constrained by any pattern under the node
(the compiler splits only on fully specified fields, so no other bit can
matter), with the path's bits fixed. Result: 25 of 25 subtrees equal on
every input (6 to 25 free bits; up to 33,554,432 inputs per node), same
pattern set in both. Sanity check: the same command on unrelated pairs
(ARM8_le vs ARM7_le under one name) reports mismatches.

**Reference decoder** [measured,
`tools/sla-host-diff/scripts/pcodedump-compare.sh target/sla-host-diff/pcodedump 2`]:
the reference `pcodedump` run on the same bytes with the macOS `.sla` and
with the x86-64 `.sla` (a mirror of the reference root whose `.sla` links
point at `../reference-x86_64`): 2 MB of seeded random bytes per language,
plus every 16-bit first word for TI_MSP430/X — byte-identical output for
all 14 (between 362,798 and 825,088 instructions each). For `mips32le`
`pcodedump` itself segfaults part-way through the random input, at the
same point with both files (a reference-tool robustness issue; reported
as a follow-up). Random bytes need not reach the 25 nodes; the
exhaustive check above is the proof, this is the cross-check through
Ghidra's own decoder.

So the 14 macOS files and the 14 x86-64 files are **behaviourally
identical**: same constructor for every instruction, same p-code.

## 5. What Ghidra ships

[source] Release builds compile `.sla` with the Java compiler
(`ghidra.pcodeCPort.slgh_compile`). Its `DecisionNode.getScore`
(`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcodeCPort/slghsymbol/DecisionNode.java:97–132`)
and `chooseOptimalField` (134–200) are line-for-line the C++ algorithm:
same scan order, `sc -= p * Math.log(p)` (129), `sc / Math.log(2.0)`
(131), strict `sc > score` (165, 185). Java never contracts a
multiply-add (JLS §15.4; only `Math.fma` fuses), so Java's arithmetic is
x86-64's at the 25 contraction ties on every host. `Math.log`, unlike
`StrictMath.log`, is only specified to 1 ulp and is a JIT intrinsic that
differs between platforms, so Java is **not** guaranteed host-independent.

[measured, `T node FILE TABLE PATH`, against two installed Ghidra
releases on this Mac; their `.sla` are format 4 and readable by `bk-sla`]:

* `ghidra_11.4.2_PUBLIC` (official release zip) and Homebrew's 12.0
  (built from the source tarball on Apple silicon: its decompiler is
  `mac_arm_64`; its `INSTALL_RECEIPT.json` names the GitHub source
  archive) both choose **x86-64's field at all 25 contraction nodes**
  (`sla-host-dependence/java-tie-nodes.txt`; at every one of the 25
  nodes the pattern set under the node is the same in the x86-64 C++ file
  and both releases, so the node's input is the same despite the source
  changes between versions). TI_MSP430's
  sources are identical between the releases and the reference commit,
  and there the release decision trees equal the x86-64 C++ trees
  exactly (`T trees`: 0 tables differ); the Java files differ from C++
  elsewhere (unique-space offsets, `uniqbase`), a known Java/C++
  difference outside this question.
* At the ARM8 `log`-sensitive node (same 18-pattern set in all four
  files), 11.4.2 chooses glibc's field (`ins[13..+3]`) and Homebrew's
  12.0 on AArch64 chooses fdlibm's (`ins[12..+4]`). So the Java compiler
  on AArch64 macOS gives different bytes from the official release for
  ARM8_le and ARM8m_le, through `Math.log`.

[judgement] The official release is presumably built on x86-64 Linux; its
trees agree with the x86-64 C++ reference at every node examined. The
x86-64 C++ result is therefore also the result Ghidra users get from the
release, which supports keeping it as the oracle.

## 6. Recommendation

### 6.1 What Basilisk's compiler does

Compute the score exactly as x86-64 C++ (and Java) does, as a defined
computation:

1. `p = count as f64 / total as f64`; `sc = sc - p * log(p)` with the
   product and the subtraction rounded separately (Rust never contracts;
   never write `mul_add` here), bins in ascending value order; result
   `sc / log(2.0)`; scan order and strict `>` as `chooseOptimalField`.
2. `log` **bit-equal to glibc's `log` (FMA variant, glibc ≥ 2.28)**,
   verified on every argument the compiler can produce today: `k/n`,
   1 ≤ k < n ≤ 16,384 (the largest table has about 9,356 patterns; a
   table above the bound is reported with a warning so the verified
   domain can be extended).
   glibc's `log` is Szabolcs Nagy's algorithm from Arm's
   optimized-routines (MIT OR Apache-2.0 WITH LLVM-exception; musl
   carries the same code), so a Rust port is licence-clean; the port must
   follow the FMA path with a correctly rounded fused multiply-add (e.g.
   `libm::fma`, not the platform's) and no other fusion. Not `libm::log`
   (fdlibm: measured to change ARM8_le and ARM8m_le), not the host's
   `f64::ln` (Apple's and MSVC's differ from glibc's).
3. Test (oracle-free, all platforms): the checked-in table
   `logtable-glibc.txt` (16,384 lines; produced by
   `containers/logtable/logtable.c` in the `gcc:14` container, md5
   `a9e120b2c0f1bd977abb3f70640effbb`) must equal Basilisk's `log` hashed
   the same way. Under a second exhaustively; it pins the arithmetic that
   decides the 25 ties without needing the reference.

Fallback if the port is judged too costly: any `log` that reproduces
the 150 files passes the acceptance test today (Apple's does; fdlibm
does not), but then the byte oracle is only guaranteed for the current
corpus; the glibc-equal `log` makes "x86-64's bytes" a property of the
algorithm.

### 6.2 Oracle for the acceptance test

* **All 150, byte equality with the x86-64 Linux build**
  (`../reference-x86_64/x86_64-linux`). No admitted ties: with 6.1 none is
  expected, and the "within 2 ulp" escape of
  `sleigh-compiler-back.md` 6.2 is unnecessary.
* **Make the macOS reference produce the same bytes**: add
  `-ffp-contract=off` to `CXX_EXTRA_FLAGS` in `scripts/build-reference.sh`
  (E5: macOS then equals x86-64 for all 150). Then `../reference` is
  again a valid byte oracle for all 150 on every host, and ADR-029's
  split oracle can be dropped. The `reference-tools` track should rerun
  the unit and data tests with the flag (it may change float results in
  the decompiler tests; expected only for the NaN-sign cases ADR-021
  already lists).
* **For anyone comparing against an unpatched AArch64 build** (the old
  `../reference` .sla, a colleague's build): the difference is confined
  and checkable. With `bk_sla::diff(&basilisk, &mac_reference, cap)`
  every difference path must start with `table "` and contain
  ` decision` (no other kind); and for every node where the trees first
  differ, the subtrees must be equal as functions —
  `tools/sla-host-diff`'s `equiv` procedure (enumerate the union of
  pattern bits under the node, resolve in both, compare constructors).
  That is a diagnostic, not the acceptance test.

### 6.3 Changes to `docs/features/sleigh-compiler-back.md`

* 4.3 "Floating point": replace "Use `libm::log` … host-independent" by
  6.1 items 1–2 (unfused arithmetic; glibc-equal `log` with the bound),
  cite this document.
* 6.1 or a new 6.x: the `log` table test (6.1 item 3).
* 6.2: oracle = `../reference-x86_64/x86_64-linux` (or `../reference`
  once rebuilt with `-ffp-contract=off`); delete "One class is admitted…"
  and its checked-in tie file; keep the behavioural cross-check as is.
* 7 acceptance 1: drop "any admitted tie…".
* 8: replace "`log` from `libm`, for host-independent output" by "the
  score's `log` is glibc's, reimplemented; the arithmetic is unfused as on
  x86-64 and in Java, so output is the same on every host" and note that
  Ghidra's own C++ output depends on the compiler's contraction setting
  and its Java output on `Math.log`.
* `inventory/01-sleigh.md` 10(e)1: add contraction as the second host
  dependence of the float tie-breaks.

### 6.4 Proposed ADR-029 revision (ready to paste)

```markdown
## ADR-029 — Ghidra's SLEIGH compiler output depends on floating-point contraction; Basilisk computes the score as x86-64 does
(Coordinator, 2026-11-14; revised 2026-11-14 from the `sla-host-diff`
track, evidence in `docs/research/sla-host-dependence.md`. Follows
ADR-021; replaces ADR-024's `libm` bullet.)

14 of the 150 reference `.sla` files differ between macOS AArch64 and
x86-64 Linux. Cause, established by experiment: `DecisionNode::getScore`
computes `sc -= p * log(p)` (`slghsymbol.cc:2135`), which AArch64
compilers (clang and GCC, any C++ library, any OS) fuse into one
multiply-subtract while x86-64 compilers without FMA round the product.
At 25 decision nodes two candidate fields have mathematically equal
scores (same bin-count multiset); the last-bit difference decides
`chooseOptimalField`'s strict `>`. macOS with `-ffp-contract=off`
reproduces x86-64 for all 150; x86-64 with `-mfma` reproduces macOS. Only
the decision trees below those nodes differ, and they resolve every input
to the same constructor (checked exhaustively): the two variants decode
identically. Ghidra's Java compiler never contracts and agrees with
x86-64 at all 25 nodes, but its `Math.log` is host-dependent (Homebrew's
12.0 built on Apple silicon differs from the 11.4.2 release in ARM8_le
and ARM8m_le).

* **Basilisk's score** is unfused IEEE `f64` arithmetic in Ghidra's
  order, with a `log` bit-equal to glibc's (FMA variant) on every `k/n`,
  1 ≤ k < n ≤ 16,384, verified against a checked-in table. Not
  `libm::log`: fdlibm's `log` changes ARM8_le and ARM8m_le. The output is
  then the same on every host and equals x86-64 Linux's.
* **Oracle**: byte equality with the x86-64 Linux build for all 150
  specifications, no tolerated ties. The reference build adds
  `-ffp-contract=off`, after which a build on any host gives those bytes
  and `../reference` serves again; until it is rebuilt,
  `../reference-x86_64/x86_64-linux` is the oracle for the 14.
* `bk-pcode`'s oracle-table item (x86-64 NaN results, queue item
  `x86-oracle`) is unchanged.
```

And in ADR-024 replace the bullet "Decision-tree scoring uses a
host-independent `log` (the `libm` crate…)" by "Decision-tree scoring
follows ADR-029."
