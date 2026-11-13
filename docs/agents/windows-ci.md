# windows-ci — status report

Goal: make the Windows test job green without weakening a test (ADR-022).

## Failing Windows tests (CI run 43279380556)

The run used `--no-fail-fast`; its summary lists three failing targets and
no others (`-p bk-lang --test registry`, `-p bk-lang --test root_spelling`,
`-p bk-sleigh-syntax --test preprocessor`), one failing test in each. All
tests that need the Ghidra tree or the reference tools skipped on CI.

| Test | Cause |
|---|---|
| `bk-lang` `registry::a_language_with_a_missing_file_is_reported_and_left_out` | Test assumption: expected messages hard-coded `<dir>/c.ldefs`; the product correctly prints `<dir>\c.ldefs` (`Path::display`). |
| `bk-lang` `root_spelling::every_spelling_of_a_root_gives_the_same_registry` | Test assumption: `expected.contains("/Ghidra/Processors/Zeta/...")` against text holding `Debug` of a Windows path (backslashes, and doubled by `Debug`). The assertion stopped the test before its loop over spellings, so the loop never ran on Windows. |
| `bk-sleigh-syntax` `preprocessor::file_identity_does_not_depend_on_how_a_path_is_spelled` | Test assumption: the cycle message shows the joined path, `d\../d/./self.sinc` on Windows; the test expected `d/../d/./self.sinc`. Identity (one file for both spellings, the cycle caught) already worked on Windows. |

None of the three was a product bug. Reasoning through the root-spelling
loop on Windows (canonical roots are verbatim, `\\?\C:\…`; `PathBuf::push`
onto a verbatim path removes `.`/`..` and splits at `/`; a failed
`canonicalize` falls back to that lexical form) shows it should pass, but
it rests on CI.

## Product bugs found while checking (fixed)

1. **Verbatim spellings on Windows** (`bk-lang` registry roots,
   `bk-sleigh-syntax` `FsLoader` and include resolution). A verbatim path
   reaches the file system as written: `/` is part of a name and `.`/`..`
   are names. So a root or specification spelled `\\?\C:\x\..\y` or
   `\\?\C:\x/y` reached no file. Worse, `including.parent()` for
   `\\?\C:\d/a.slaspec` is `\\?\C:\`, so includes were looked up in the
   wrong directory. New `windows_spelling(path)`: for a prefixed path,
   removes `.`/`..` lexically from a verbatim path, splitting at both
   separators (as Windows does for every other spelling), and upper-cases
   the drive letter. It is applied before `canonicalize`, before reading,
   and to the including file before resolving an include. Any path without
   a prefix, which covers all paths on Unix, is returned unchanged
   (borrowed). Existing files already converged through `canonicalize`
   for ordinary/verbatim/drive-case/8.3 spellings; the upper-casing also
   makes two spellings of a *missing* path compare equal.
   The function is duplicated in `bk-lang/src/registry/paths.rs` and
   `bk-sleigh-syntax/src/loader.rs` (about 40 lines each). The two crates
   share no dependency that could hold it (see Follow-ups).
2. **Ambiguous file names with a directory part on Windows** (`bk-lang`
   `FileIndex::resolve`). When several modules hold a file of the name,
   Ghidra takes the first one only if the absolute path it looked for
   ends with the name as written. On Windows that path has `\` and the
   name has `/`, so `sub/x.cspec` never matched. Ghidra has the same flaw
   on Windows (`File.getAbsolutePath().endsWith(...)`). A `/` in the name
   now stands for the platform separator, which gives Ghidra-on-Unix
   behaviour everywhere. This is a deliberate difference from Ghidra on
   Windows; the coordinator may want it added under "Differences from
   Ghidra" in `docs/features/` for the language registry.

## What changed

- `crates/bk-lang/tests/registry.rs`: expected messages are built from
  `Path::new("<dir>").join(..)`. A new language `Omega:LE:32:subdir`
  (`nowhere/shared.cspec`) covers bug 2 on every platform.
- `crates/bk-lang/tests/root_spelling.rs`: the overlay `.sla` check
  compares the `Debug` of a path built by joining components. There is a
  new `#[cfg(windows)]` test with plain, lower-case drive, verbatim
  lower-case, `/`-separated, and verbatim with `.`/`..`/`/` spellings.
  The symbolic-link test now runs on Windows too (`symlink_dir`). It
  skips with a printed `SKIPPED …` line when a link cannot be created
  (no admin rights and no Developer Mode).
- `crates/bk-lang/src/registry/paths.rs`: `windows_spelling`,
  `canonical_root` uses it, `ends_with_name`. Unit tests: all-platform
  (`ends_with_name`, unprefixed paths unchanged) and `#[cfg(windows)]`
  (10 spellings).
- `crates/bk-sleigh-syntax/src/loader.rs`: `windows_spelling` (crate
  visible), used by `FsLoader::load` and `FsLoader::identity`. Same unit
  tests.
- `crates/bk-sleigh-syntax/src/preprocess/include.rs`: resolves relative
  includes against `windows_spelling(including)`.
- `crates/bk-sleigh-syntax/tests/preprocessor.rs`: the expected message
  is built from `Path::new("d").join("../d/./self.sinc")`.
- `crates/bk-sleigh-syntax/tests/fs_spelling.rs` (new): `FsLoader` end to
  end with a real tree. The all-platform test covers canonical, as-created
  (macOS `/var` link), `.` and `sub/..` spellings. The `#[cfg(windows)]`
  test covers verbatim, plain, lower-case drive, verbatim lower-case,
  `/`-separated, and verbatim with `.`/`..`/`/`.
- `crates/bk-marshal/tests/corpus.rs`: the white-space-difference count
  compares our content with CRLF/CR read as LF (roxmltree normalises line
  endings as XML requires; the decoder keeps text as written). Without
  this, a CRLF checkout of Ghidra (Windows with `core.autocrlf`) fails
  `agrees_with_an_independent_parser` with hundreds of "differences"; this
  was reproduced locally. The content equality assertion is unchanged.
- `.gitattributes` (new): `* text=auto`; `*.sh`, `*.patch` as
  `text eol=lf`; `*.so *.o *.gz *.png` as `binary`. Text otherwise keeps
  native endings, so the CRLF handling of product and tests stays
  exercised on Windows. The index needed no renormalisation.
- No change to `.github/workflows/ci.yml`.

## Workspace sweep (all crates on master)

- Hard-coded `/` in expected paths: only the three failures above. The
  other uses are `Path::ends_with("a/b")`, which compares components and
  works on Windows, or strings that are never joined (`/nowhere/ghidra`,
  `/tmp/a.xml`, `/proc/MIPS` in a `MemoryLoader`), whose `display()` is
  unchanged on Windows.
- `starts_with('/')`: only `include::is_absolute`, which mirrors Ghidra
  and also accepts `\` and drive prefixes.
- `/tmp`, `:`-separated path lists, `PATH` parsing: none in product code.
- `std::os::unix`: `bk-bin` positional reads have a Windows `seek_read`
  counterpart inside a short-read loop. `bk-testkit` process tests are
  `#[cfg(unix)]` (`/bin/sh`) and belong to the reference tooling, which
  ADR-022 allows to stay Unix-only.
- Symbolic links: one test, now cross-platform with a printed skip.
- File permissions: no tests.
- Case sensitivity: the registry's exact-case check (`exists_exact`)
  passed on Windows. No test creates names that differ only in case.
- Line endings: rustc normalises CRLF in `.rs` sources and there is no
  `include_str!`. insta snapshots passed on Windows CI with an autocrlf
  checkout. The preprocessor and lexer handle `\r\n`. Ghidra-dependent
  tests were run against a CRLF copy of the Ghidra tree (below), and that
  found the `bk-marshal` corpus issue.
- Other trap noted, not changed: `bk-testkit` canonicalises the Ghidra and
  reference directories (`tidy`), which yields verbatim paths on Windows.
  It only feeds messages and the reference tools, which are Unix-only.

## Verified locally (macOS) and what rests on CI

- `cargo clippy --workspace --all-targets --all-features --locked
  --target x86_64-pc-windows-msvc -- -D warnings`: clean. This
  type-checks and lints all the `#[cfg(windows)]` code; there is no C code
  on master.
- `cargo test` for `bk-lang`, `bk-sleigh-syntax`, `bk-marshal` with
  `BASILISK_GHIDRA_DIR`/`BASILISK_REFERENCE_DIR` set, unset, and spelled
  `/Users/tatu/slop/basilisk-wt/../ghidra`: 650 passed, 0 failed each
  time.
- The whole workspace's tests were run against a CRLF copy of the Ghidra
  tree, in `target/`: Processors, SoftwareModeling, Decompiler datatests,
  FileFormats, Emulation, GnuDisassembler data and ExerciseFiles, with
  every text file converted to CRLF. After the `bk-marshal` fix all pass.
  Earlier failures in `bk-lang` corpus and `bk-elf` real files came from
  directories missing in the copy and passed once those were copied.
- Rests on CI: actually running the three fixed tests and every
  `#[cfg(windows)]` test on Windows. That means the verbatim and
  drive-case spellings, `symlink_dir` on the runner (expected to work:
  hosted runners are administrators), and `Path::push` normalisation of
  verbatim UNC paths in the unit tests' `\\?\UNC\server\share` case.
  Ghidra-dependent tests on a Windows machine are not covered by CI.

## Gate

The result line is given in the final message; it comes from
`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`.

## Follow-ups

- `windows_spelling` exists twice. A small shared foundation crate (or
  `bk-core`, if `bk-lang` and `bk-sleigh-syntax` may depend on it) should
  hold it.
- Product paths on Windows are reported verbatim (`\\?\C:\…`), which is
  what `canonicalize` returns. Reporting the simplified form when it is
  safe (like the `dunce` crate does) would read better in messages and the
  UI. This needs an ADR-011 evaluation and would change the tests' own
  `canonical` helpers to match.
- Bug 2 is a documented difference from Ghidra on Windows (see above).
