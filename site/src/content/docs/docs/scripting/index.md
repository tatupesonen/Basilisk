---
title: Scripting and plugins
description: Extending basilisk with Python — scripts, analyzers, loaders, exporters — through PyO3. Designed; planned for milestone M9.
sidebar:
  order: 1
---

:::caution[Planned]
The plugin system is designed (its specification is in the repository) but not built. Most of it is
milestone M9; parts start earlier, as the program model exists.
:::

basilisk's extension language is **Python 3**, embedded through PyO3. A Python package, `basilisk`, will
expose the program model, analysis, the decompiler and interface hooks.

## What you will be able to write

- **Scripts** that run against the open program, from the interface or headless.
- **Analyzers** that take part in auto-analysis.
- **Loaders** for new binary formats, and **exporters**.
- **Interface actions and views**, later.

## Coming from Ghidra

A flat scripting layer keeps the names of Ghidra's `FlatProgramAPI` and `GhidraScript`, so existing Python
scripts port with small, mechanical changes. Java scripts and Ghidra's Java plugins do not run in basilisk.

The same package is importable from any Python process, to drive basilisk as a library — the role PyGhidra
plays for Ghidra.
