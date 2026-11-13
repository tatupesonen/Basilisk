# Fuzzing

One `cargo fuzz` crate for the whole workspace. It is outside the Cargo
workspace (`exclude = ["fuzz"]` in the root manifest) because fuzzing needs
a nightly toolchain and sanitizer flags.

| | |
|---|---|
| Add a target | `fuzz_targets/<crate>_<what>.rs` (for example `elf_parse.rs` → `bk_elf_parse.rs`), plus the crate under `[dependencies]` and a `[[bin]]` entry in `Cargo.toml`, alphabetically |
| List targets | `cargo +nightly fuzz list` (from the repository root) |
| Run one | `cargo +nightly fuzz run <target> -- -max_total_time=60` |
| Run all briefly | `scripts/fuzz-smoke.sh [seconds-per-target]` |
| A crash | fix it, save the input as `fuzz/regressions/<target>/<short-name>`, and add a normal test in the crate that replays every file in that directory |

`corpus/`, `artifacts/` and `target/` are git-ignored. `Cargo.lock` is
committed; when two branches both change it, do not merge it by hand — the
coordinator regenerates it.

## `bk_binutils_sys_disassemble`

Arbitrary bytes for every architecture binutils 2.41 knows, through the raw
interface of `bk-binutils-sys` (the C under test is binutils itself; the
safe layer above it adds no parsing). Input: two bytes choose the
architecture, one the byte order and whether an option string follows, eight
the address; the rest is disassembled.

**The C must be instrumented, or the fuzzer is blind to it.** `cargo fuzz`
instruments only the Rust; binutils is compiled by the `cc` crate, which
takes its flags from `CFLAGS`. Use clang, matching sanitizers, and Linux
(Apple clang's runtimes do not mix with Rust nightly's; this was done in a
`rustlang/rust:nightly` container with Debian's `clang`):

    CC=clang \
    CFLAGS="-fsanitize=fuzzer-no-link,address,undefined \
            -fno-sanitize-recover=bounds,null,vla-bound,return,unreachable,builtin \
            -fno-omit-frame-pointer -g" \
    cargo +nightly fuzz run bk_binutils_sys_disassemble -- \
        -timeout=10 -detect_leaks=0 -rss_limit_mb=1536 -max_len=512

Check the instrumentation took: `nm` on `libbk_binutils.a` under the fuzz
target directory must show `__sanitizer_cov_8bit_counters_init` and
`__asan_report_load*` references. Rust nightly's AddressSanitizer runtime
contains the UndefinedBehaviorSanitizer handlers, so no other runtime is
linked. UB that means memory unsafety stops the run; other UB (shifts,
signed overflow, pointer arithmetic on null) is printed once per site and
triaged by hand. Leak detection is off: binutils keeps small allocations
for the life of the process by design (option strings, lazily built
tables); `-rss_limit_mb` catches unbounded growth.

Environment: `BK_FUZZ_FAMILY=<family>` (`i386`, `arm`, ...) restricts a run
to one BFD architecture family; `BK_FUZZ_ABORTS=panic` turns an `abort()`
or failed assertion inside binutils, which the shim normally turns into an
error, into a finding.

This target makes every `cargo fuzz build` of this crate compile binutils
(about 280 C files), whichever target is asked for.
