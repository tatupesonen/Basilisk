---
title: Build and run
description: Build Basilisk from source and open the interface.
sidebar:
  order: 2
---

There are no releases yet; Basilisk is built from source. Windows, macOS and Linux are all supported.

## Requirements

- **Rust**, installed with [rustup](https://rustup.rs). The repository's `rust-toolchain.toml` pins the
  toolchain version, and rustup installs it on first use.
- **git**, to clone the repository.

## Build and run

```sh
git clone https://github.com/tatupesonen/Basilisk
cd basilisk
cargo run --release -p basilisk
```

`basilisk` with no arguments (or `basilisk gui`) opens the desktop interface on its built-in demo program.
`basilisk --version` prints the version.

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

The full key-binding reference will be generated from the program's action registry.

## For contributors

The quality gate runs formatting, lints, documentation and every test:

```sh
scripts/gate.sh > gate.log 2>&1; echo $?
```

Tests that compare against Ghidra expect its source tree at `../ghidra` (or `BASILISK_GHIDRA_DIR`) and skip
themselves when it is absent. This website is built in a container with `scripts/site.sh`; Node.js is not
needed on your machine.
