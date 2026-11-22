---
title: The command line
description: The Basilisk command and its subcommands — what exists today and what is planned.
sidebar:
  order: 1
  label: Overview
---

Basilisk ships as one binary, `basilisk`. With no arguments it opens the desktop interface; subcommands do
headless work, and more arrive with the milestones.

## Today

| Command | What it does |
|---|---|
| `basilisk` | Opens the desktop interface |
| `basilisk gui` | The same |
| [`basilisk sleigh decode`](/docs/cli/sleigh-decode/) | Disassembles bytes with a SLEIGH language and prints each instruction with its p-code |
| [`basilisk sleigh compile`](/docs/cli/sleigh-compile/) | Compiles a `.slaspec` to a `.sla` file, as Ghidra's `sleigh` does |
| `basilisk --version` | Prints the version (also `-V`, `version`) |

`sleigh decode` and `sleigh compile` print their help with `-h` or `--help`.

## Planned

| Command | What it will do | Milestone |
|---|---|---|
| `basilisk decompile` | Decompile from one of Ghidra's decompiler test files | M3 |
| `basilisk import` | Import a binary into a program database | M4 |
| `basilisk disasm` | Disassemble a loaded program by following the flow of control, as Ghidra does | M5 |
| `basilisk analyze` | Headless import, analysis and export, like Ghidra's headless analyzer | M5 |

## The environment

| Variable | Meaning |
|---|---|
| `BASILISK_GHIDRA_DIR` | The directory that holds Ghidra's language files under `Ghidra/Processors/`: a Ghidra source tree or an installed release. `sleigh decode` uses it when `--root` is not given; `sleigh compile -dMODULE` resolves modules in it. See [Ghidra's language files](/docs/getting-started/build/#ghidras-language-files) |

## Exit status

Every subcommand exits with 0 on success. The other values differ between `sleigh decode` and `sleigh compile`,
because `sleigh compile` keeps the exit statuses of Ghidra's compiler so that build scripts written for it
keep working. Each command's page lists its values.
