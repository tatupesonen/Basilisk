# sla-host-diff

Investigation tool for `docs/research/sla-host-dependence.md`: compares two
builds of Ghidra's compiled SLEIGH files with `bk-sla`, and rebuilds
Ghidra's C++ `sleigh` under controlled compilers, flags and patches.

Standalone Cargo project (own `[workspace]`, own `Cargo.lock`): not a
member of the basilisk workspace, not built by the gate.

```sh
cd tools/sla-host-diff
CARGO_BUILD_JOBS=2 cargo build --release
T=$PWD/target/release/sla-host-diff
MAC=/Users/tatu/slop/reference/Ghidra
X86=/Users/tatu/slop/reference-x86_64/x86_64-linux/Ghidra
```

## Comparing files

| command | what |
|---|---|
| `$T scan $MAC $X86` | pair `.sla` by name under two trees; inflated streams equal or not, lengths, first differing offset |
| `$T classify $MAC $X86` | per differing pair: `bk_sla::diff` entries counted by path kind; decision-tree analysis |
| `$T diff A.sla B.sla [CAP]` | every `bk_sla::diff` difference |
| `$T trees A.sla B.sla [-v]` | parallel walk of every table's tree: shape differences, leaves equal / reordered / different |
| `$T equiv $MAC $X86` | each subtree where the trees differ, compared as a function (exhaustive over the constrained bits when ≤ 26) |
| `$T node FILE TABLE root/1/9` | field tested at a node, and a hash of the pattern set under it |
| `$T maxpatterns $MAC` | largest number of distinct leaf patterns in one table |
| `$T logtable libm\|std N` | hash of `log(k/n)` bits per n, Rust `libm` crate or `f64::ln` (compare with `containers/logtable/logtable.c`) |
| `$T logdump libm\|std N FILE` | the raw values |

## Rebuilding `sleigh`

Work directory (git-ignored): `target/sla-host-diff/work` with `src/`
(copy of `../reference/src/{cpp,zlib}` without objects), `langs/<Module>/`
(copies of the reference's `Ghidra/Processors/*/data/languages` without
`.sla`), `opts/` (copy of `../reference/.state/lang/*.opts`), and
`patches-<NAME>/` for patches applied to the build `<NAME>`:

```sh
W=target/sla-host-diff/work   # from the worktree root
mkdir -p $W/src $W/langs $W/opts
rsync -a --exclude 'com_*' --exclude '*.o' --exclude '*.a' --exclude '*_opt' --exclude '*_dbg' \
  /Users/tatu/slop/reference/src/cpp /Users/tatu/slop/reference/src/zlib $W/src/
for d in /Users/tatu/slop/reference/Ghidra/Processors/*/; do
  rsync -a --exclude '*.sla' $d/data/languages/ $W/langs/$(basename $d)/; done
cp /Users/tatu/slop/reference/.state/lang/*.opts $W/opts/
cp tools/sla-host-diff/containers/build-sleigh.sh $W/
```

`build-sleigh.sh WORK NAME CXX "EXTRA" [SPEC…|all]` builds `sleigh_opt`
into `WORK/build-NAME` and compiles into `WORK/out-NAME` (the 14
host-dependent specifications by default). `SKIP_BUILD=1 OUT=dir` reuses
a build. Experiments of the research document (section 2):

```sh
cd $W
./build-sleigh.sh $PWD mac-clang g++ ""                          # E1
./build-sleigh.sh $PWD mac-clang-nocontract g++ "-ffp-contract=off" all   # E5
mkdir -p patches-mac-local && cp ../../../tools/sla-host-diff/containers/patches/unfused-getscore.patch patches-mac-local/
./build-sleigh.sh $PWD mac-local g++ ""                          # E8
mkdir -p patches-mac-trace && cp ../../../tools/sla-host-diff/containers/patches/trace-score.patch patches-mac-trace/
./build-sleigh.sh $PWD mac-trace g++ ""                          # trace: TIE lines in out-mac-trace/*.log
mkdir -p patches-score-config && cp ../../../tools/sla-host-diff/containers/patches/score-config.patch patches-score-config/
./build-sleigh.sh $PWD score-config g++ "-ffp-contract=off" all
SKIP_BUILD=1 OUT=out-mac-fdlibm-fuse0 SLEIGH_LOG=fdlibm SLEIGH_FUSE=0 \
  ./build-sleigh.sh $PWD score-config g++ "-ffp-contract=off" all  # E12 (E10/E11/E13 likewise)
$T scan out-mac-local $X86
```

Containers (`containers/run.sh IMAGE PLATFORM NAME CXX "EXTRA" SECONDS
[SETUP]`: `--cpus 3`, kills itself after SECONDS, `--rm`; images by id
or this track's tag `bk-sla-host-diff/gcc14:arm64`, which is
`gcc@sha256:2bafb163aaa91eef7856f17ff0abf69144ebe3218a4eea75c043bb3043b9ecfa`):

```sh
cd tools/sla-host-diff/containers
./run.sh bk-sla-host-diff/gcc14:arm64 linux/arm64 linux-arm64-gcc g++ "" 1500                    # E2
./run.sh 2534543d1c5c linux/amd64 linux-amd64-gcc g++ "" 3600                                   # E3 (gcc:14 amd64)
./run.sh ubuntu:26.04 linux/arm64 linux-arm64-clang-libcxx "clang++ -stdlib=libc++" "" 2400 \
  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libc++-dev libc++abi-dev make patch"  # E4
./run.sh bk-sla-host-diff/gcc14:arm64 linux/arm64 linux-arm64-gcc-nocontract g++ "-ffp-contract=off" 1500   # E6
./run.sh 2534543d1c5c linux/amd64 linux-amd64-gcc-mfma g++ "-mfma" 3000                          # E7
# E9: reuse the E3 build with glibc's non-FMA log
docker run --rm --platform linux/amd64 --cpus 3 -v $PWD/../../../target/sla-host-diff/work:/work 2534543d1c5c \
  sh -c "SKIP_BUILD=1 OUT=out-linux-amd64-gcc-nofma GLIBC_TUNABLES=glibc.cpu.hwcaps=-FMA,-AVX2,-FMA4 sh /work/build-sleigh.sh /work linux-amd64-gcc g++ '' all"
```

`log` tables: `cc -O2 -ffp-contract=off containers/logtable/logtable.c -lm
-o lt && ./lt 16384 > table.txt` on each host (in the containers as
above); `python3 -I containers/logtable/crlog.py N` for correctly rounded
values.

Behaviour through Ghidra's decoder:
`scripts/pcodedump-compare.sh target/sla-host-diff/pcodedump 2` (2 MB of
random bytes per language, both `.sla` variants, outputs compared).
