# Decompiler quality — experiment inputs and outputs

Evidence for `../decompiler-quality.md`: 36 small C files (104 functions),
compiled for up to four targets (67 builds, 188 decompiled functions) and run
through Ghidra's reference `decomp` console (Ghidra commit `42db038f3c`, built by `scripts/build-reference.sh`).
It is laid out so that the weakness catalogue can become a test corpus.

| Path | What it is |
|---|---|
| `src/<case>.c` | One case: a few functions that show one class of weakness. `a*` cases are about accuracy, `r*` about readability, `t_smoke` is the first harness check (a loop on four targets). Directives in `//!` lines say how to build and run the case |
| `src/libc.h`, `src/stubs.c`, `src/libc.proto` | Declarations, trivial bodies and console prototypes for the few library functions the cases call |
| `frag/<case>.<target>.xml` | The fragment fed to `decomp`: a `<binaryimage>` in the form Ghidra's own data tests use (bytes of the loaded sections, function symbols) |
| `frag/<case>.<target>.script` | The console commands run on that fragment |
| `out/<case>.<target>.c` | What the console printed: Ghidra's output |
| `tools/run.py` | Builds and runs everything (or the named cases) |
| `tools/elf2frag.py` | Static ELF executable → `<binaryimage>` XML and a list of data symbols |
| `tools/metrics.py` | Text counters over `out/` (gotos, casts, loop shapes, …) |
| `build/` | Objects and executables; not checked in |

A target is `<arch>-<compiler>-<level>`: `x64`, `x86`, `a64` (and `arm`) with
`clang` (LLVM 20, cross) or `gcc` (GCC 14 from the `gcc:14` container, whose
native target here is AArch64), at `O0`…`O3`.

## Reproduce

```sh
scripts/build-reference.sh                         # once: Ghidra's decomp into ../reference
cd docs/research/decompiler-quality
tools/run.py                                       # all cases (about 100 s; one container start per gcc target)
tools/run.py a16_retval r02_loops                  # named cases, output printed
tools/metrics.py                                   # counters over out/
```

Needs: `clang`, `ld.lld` and `llvm-objdump` (paths in `BK_CLANG`, `BK_LLD`,
`BK_OBJDUMP`; the defaults are Homebrew's `llvm@20` and `lld@20`), Docker with
a `gcc:14` image for the `gcc` targets (`BK_GCC_IMAGE`), Python 3. The reference
tools are found beside the basilisk checkout or through `BK_REFERENCE`.

## What the harness does and does not model

The console is the decompiler **engine alone**. A full Ghidra gives the engine
more than bytes, and the harness stands in for the parts that matter here:

| A full Ghidra supplies | The harness does |
|---|---|
| Prototypes of imported library functions (data-type archives) | `src/libc.proto`: `parse line extern …` for each library function, `option noreturn` for `exit`, `abort`, `__stack_chk_fail` |
| Names (not types) of data symbols | `map addr` with an unknown type of the symbol's size (`xunknownN`, or an `xunknown1` array) |
| Read-only memory treated as constant | `option readonly on` |
| A jump to another function's entry marked call-then-return (`SharedReturnAnalyzer`) | `override flow <addr> callreturn` for every unconditional jump to a function symbol, found with `llvm-objdump` |
| Non-returning functions discovered by analysis (`FindNoReturnFunctionsAnalyzer`) | **Nothing** for program-defined functions: `a05_noreturn` shows the engine without that help |
| Stored prototypes of the program's own functions (`Decompiler Parameter ID`; off by default except for small PE files) | **Nothing**, as in a default analysis of an ELF file; `a15` and `a17` give prototypes explicitly |
| Strings defined in the listing | **Nothing**: a pointer is printed as a string only where its type is `char *` |

Two details of the console matter when reading the scripts:

* The console's built-in types are `int4`, `uint8`, `float8`, `xunknown4`, …;
  the Ghidra GUI would print `int`, `ulong`, `double`, `undefined4`.
* `load function` follows control flow at once and a flow override is only
  read while flow is followed, so for a function with overrides the script
  runs `decompile` twice: the second run clears the analysis (overrides are
  kept, everything unlocked is reset) and follows flow again. The functions
  printed as `void` in the catalogue were re-run by hand with a single
  `decompile` and print the same.

## Limits

No x86-64 GCC (no cross compiler on the machine), no MSVC, C only. The cases
are written to show weaknesses, so counts over them are not rates for real
programs.
