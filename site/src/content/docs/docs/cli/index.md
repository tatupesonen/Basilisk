---
title: The command line
description: The Basilisk command and its subcommands — what exists today and what is planned.
sidebar:
  order: 1
  label: Overview
---

Basilisk ships as one binary, `basilisk`. With no arguments it opens the desktop interface; subcommands for
headless work arrive with the milestones.

## Today

| Command | What it does |
|---|---|
| `basilisk` | Opens the desktop interface |
| `basilisk gui` | The same |
| `basilisk --version` | Prints the version (also `-V`, `version`) |

## Planned

| Command | What it will do | Milestone |
|---|---|---|
| `basilisk disasm` | Disassemble bytes with a SLEIGH language and print p-code | M1 |
| `basilisk sleigh compile` | Compile a `.slaspec` to `.sla`, byte-identical to Ghidra's compiler | M2 |
| `basilisk decompile` | Decompile from one of Ghidra's decompiler test files | M3 |
| `basilisk import` | Import a binary into a program database | M4 |
| `basilisk analyze` | Headless import, analysis and export, like Ghidra's headless analyzer | M5 |

Command-line help on these pages will be generated from the binary itself.
