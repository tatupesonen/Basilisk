# spec-plugin experiments

Throwaway programs that settle claims in `docs/features/plugin-api.md`.
Each Cargo project has its own `[workspace]` table, so it is not a member
of the basilisk workspace and does not touch the root `Cargo.lock`. Build
with a target directory outside the repository.

Environment of the runs below (2026-11-14): macOS 26 on Apple silicon,
rustc 1.97.1, PyO3 **0.30.1** (released 2026-10-14, crates.io), Homebrew
CPython 3.11.13, 3.12.11, 3.13.7, 3.14.9, pyenv CPython 3.10.11, Apple's
CPython 3.9.6.

## `script-census/`
Classifier of Ghidra's bundled scripts; see its README.

## `pyo3-abi3/` — one abi3 extension module, many Pythons

    cd pyo3-abi3
    PYO3_PYTHON=/opt/homebrew/bin/python3.12 PYO3_BUILD_EXTENSION_MODULE=1 \
      CARGO_TARGET_DIR=$T CARGO_BUILD_JOBS=2 cargo build --release
    cp $T/release/libbkdemo.dylib $M/bkdemo.abi3.so
    python3.X check.py $M

Built once (`abi3-py310`), against 3.12. `otool -L` shows no libpython
dependency (extension modules resolve the C API from the host process;
on macOS through `-undefined dynamic_lookup`, which a plain `cargo build`
only passes when `build.rs` calls
`pyo3_build_config::add_extension_module_link_args()` — the first build
without it failed to link).

Result, identical on 3.10, 3.11, 3.12, 3.13 and 3.14 (callback timings
20–32 ms):

    two threads x 300 ms: GIL held 600 ms, GIL released 300 ms
    parallel_callback: [0, 1, 4, 9, 16, 25, 36, 49] 21 ms, 8 distinct OS threads
    call_and_catch: caught ZeroDivisionError: division by zero
    callback exception propagated: ZeroDivisionError
    NoSuchAddress: address 00401000 is not in the program's memory | is BasiliskError: True
    long_task: cancelled after 16 steps | progress seen from Python: 16
    comments: [(16, 'kept')] | undo stack: ['Set comment']

On 3.9 the import fails cleanly: `ImportError: … symbol not found in flat
namespace '__Py_DecRef'`.

What this shows: abi3 gives one binary for every supported minor version;
`py.detach` really lets other Python threads run (two 300 ms calls take
300 ms together instead of 600); Rust threads can call a Python callable
with `Python::attach` while the caller is detached, and get its result or
its exception as a value; cancellation set from another Python thread is
seen by Rust work that holds no GIL; a Rust error enum maps onto a Python
exception hierarchy; a transaction context manager commits on normal exit
and rolls back on an exception; `frozen` pyclasses holding `Arc`s are
`Send + Sync` (checked at compile time).

## `pyo3-embed/` — embedding with `auto-initialize`

    cd pyo3-embed
    PYO3_PYTHON=/opt/homebrew/bin/python3.12 CARGO_TARGET_DIR=$T CARGO_BUILD_JOBS=2 cargo build --release
    otool -L $T/release/bkembed
    $T/release/bkembed; $T/release/bkembed --python
    cp $T/release/bkembed $T/bkembed-moved
    install_name_tool -change /opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12/Python \
      /nonexistent/Python.framework/Versions/3.12/Python $T/bkembed-moved
    codesign -f -s - $T/bkembed-moved; $T/bkembed-moved

Result: the binary links
`/opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12/Python`
by absolute path. With it present, both modes work (`running without
python`; `embedded python 3.12.11 …`). With the library missing (simulated
by rewriting the load command), **the binary does not start at all**,
even in the mode that never touches Python:

    dyld[65766]: Library not loaded: /nonexistent/Python.framework/Versions/3.12/Python
    exit=134

So a `basilisk` binary that embeds CPython by linking libpython is not a
single binary that runs where Python is absent, and it is tied to one
minor version and, on macOS, one installation path. (Linux and Windows
behave the same way through their loaders — `error while loading shared
libraries` and the missing-DLL dialog — but that was not run here.)

Which local Pythons have a shared libpython at all (`sysconfig`):
Homebrew 3.11–3.14 are framework builds (`Python.framework/.../Python`),
Apple's 3.9 likewise, pyenv's 3.10.11 has `libpython3.10.dylib`; a default
pyenv build without `--enable-shared` and Debian's `/usr/bin/python3.X`
(statically linked) have none — not checked here, stated from their build
defaults.

## `pyo3-abi3/` under `#![forbid(unsafe_code)]`

With `#![forbid(unsafe_code)]` prepended to `src/lib.rs` (every
`#[pyclass]`, `#[pymethods]`, `#[pyfunction]`, `#[pymodule]` and
`create_exception!` of the experiment in use), the crate still builds;
adding one explicit `unsafe {}` block fails with `error: usage of an
unsafe block`. So PyO3 0.30.1's macros put no `unsafe` into the user's
crate: a binding crate can keep the workspace's `unsafe_code = "forbid"`,
and all `unsafe` stays inside `pyo3` and `pyo3-ffi`.
