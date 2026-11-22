---
title: Build and run
description: Build Basilisk from source, open the interface, and get the language files the command line needs.
sidebar:
  order: 2
---

There are no releases yet; Basilisk is built from source. Windows, macOS and Linux are all supported, and
all three are tested on every change.

## Requirements

- **Rust**, installed with [rustup](https://rustup.rs). The repository's `rust-toolchain.toml` pins the
  toolchain version, and rustup installs it on first use.
- **git**, to clone the repository.

Java, Gradle and Python are not needed. Cargo downloads the Rust libraries Basilisk uses on the first build.

## Build and run

```sh
git clone https://github.com/tatupesonen/Basilisk
cd Basilisk
cargo run --release -p basilisk
```

`basilisk` with no arguments (or `basilisk gui`) opens the desktop interface on its built-in demo program.
`basilisk --version` prints the version.

The binary is `target/release/basilisk` (`basilisk.exe` on Windows). The examples on these pages call it
`basilisk`; copy it somewhere on your `PATH`, or write `cargo run --release -p basilisk --` in its place.

## Ghidra's language files

The interface needs nothing more. The command line's [`sleigh decode`](/docs/cli/sleigh-decode/) and
[`sleigh compile`](/docs/cli/sleigh-compile/) work on Ghidra's processor descriptions, which Basilisk reads
unchanged and does not copy into its own repository. Get them once:

```sh
git clone --depth 1 https://github.com/NationalSecurityAgency/ghidra
export BASILISK_GHIDRA_DIR="$PWD/ghidra"
```

On Windows PowerShell the second line is `$env:BASILISK_GHIDRA_DIR = "$PWD\ghidra"`.

Basilisk looks for the files under `Ghidra/Processors/<module>/data/languages/` in that directory, which is
where both a Ghidra source tree and an installed Ghidra release keep them. A release already contains the
compiled `.sla` files; a source tree contains only the `.slaspec` sources, which
[Basilisk compiles itself](/docs/getting-started/first-disassembly/).

## First steps in the interface

The interface follows Ghidra's CodeBrowser and its default key bindings. Ctrl is Cmd on macOS, as in Ghidra.

| Action | Key |
|---|---|
| Command palette | Ctrl+Shift+P |
| Go To | G |
| Rename (label, function, variable) | L |
| Set comment | ; |
| Previous / next location | Alt+Left / Alt+Right |
| Show references to | Ctrl+Shift+F |
| Search program text | Ctrl+F |

More on [the interface](/docs/interface/).

## For contributors

The quality gate runs formatting, lints, documentation and every test:

```sh
scripts/gate.sh > gate.log 2>&1; echo $?
```

The whole workspace also needs a **C compiler** (`cc`, `clang` or MSVC): one crate builds the GNU
disassembler from source that is included in the repository. The `basilisk` binary itself does not.

Tests that compare against Ghidra expect its source tree at `../ghidra` (or `BASILISK_GHIDRA_DIR`) and skip
themselves when it is absent. [How results are checked](/docs/internals/verification/) explains what those
tests compare. This website is built in a container with `scripts/site.sh`; Node.js is not needed on your
machine.
