---
title: Analysis
description: Disassembly and auto-analysis in basilisk — planned for milestone M5.
sidebar:
  order: 1
---

:::caution[Planned]
Analysis arrives with milestone M5, after the SLEIGH runtime (M1), the program model and loaders (M4).
Nothing on this page exists yet.
:::

Auto-analysis turns an imported binary into functions, references and data. As in Ghidra:

- A **flow-following disassembler** decodes instructions from the entry points and follows branches and
  calls, propagating processor context.
- An **auto-analysis manager** schedules analyzers by priority over the addresses that changed, so each
  analyzer sees the results of the ones before it.
- **Analyzers** run in Ghidra's priority order: entry points, function starts from pattern files,
  references, switch tables, stack, data and strings, non-returning functions, call fixups, demanglers and
  format-specific analyzers.
- The **decompiler** is wired in for parameter identification and switch analysis.

basilisk's addition is parallelism: analysis runs in parallel where that is safe, and the interface never
waits for it. Results are checked against Ghidra's headless analyzer on whole binaries.
