---
title: Coming from Ghidra
description: What Basilisk keeps from Ghidra, what it changes on purpose, and how Ghidra's names map to Basilisk's.
sidebar:
  order: 4
---

Basilisk is meant to be familiar to anyone who knows Ghidra. This page says what carries over, what does
not, and where Basilisk differs on purpose.

## What is the same

- **The processor descriptions.** Basilisk reads Ghidra's SLEIGH specifications, language definitions,
  processor specifications and compiler specifications as they are. A processor Ghidra supports is a
  processor Basilisk supports, and a specification you wrote for Ghidra works without changes.
- **P-code.** The same operations, address spaces and varnodes. A p-code listing from Basilisk equals one
  from Ghidra.
- **The interface.** The windows of the CodeBrowser in the same places, Ghidra's window and action names,
  its menus and its default key bindings.
- **Results.** Where Ghidra gives an answer, Basilisk aims to give the same answer, and tests compare the
  two directly. See [how results are checked](/docs/internals/verification/).

## What differs on purpose

| | Ghidra | Basilisk |
|---|---|---|
| Language | Java, with the decompiler and SLEIGH compiler in C++ | Rust throughout |
| Delivery | A directory with a Java runtime requirement | One binary |
| The decompiler | A separate process, one per client | In process; functions decompile in parallel |
| Scripts and plugins | Java, Python through PyGhidra or Jython | Python 3 only (planned, M9) |
| Program database | Ghidra's own database format | Its own format, chosen by experiment (planned, M4) |
| Interface toolkit | Swing | egui, with dark and light themes designed together |

Every deliberate difference in behaviour is recorded as a decision in the repository
(`docs/DECISIONS.md`), with the reason.

### Where Ghidra's own answer is not fixed

Sometimes Ghidra's result depends on things outside Ghidra: the C++ standard library it was built with, the
order a file system lists a directory, or arithmetic the C++ language leaves undefined. The same Ghidra
source then gives different answers on different machines. In those places Basilisk picks one answer — the
one Ghidra gives on x86-64 Linux — and gives it everywhere. Each such place is documented.

Defects found in Ghidra while porting it are listed in `docs/GHIDRA-BUGS.md` in the repository, each with
what Basilisk does instead. Where a defect is a crash or a read of uninitialised memory, Basilisk returns
an error or a defined value. Where it only shapes the output, Basilisk's default output still equals
Ghidra's, because parity is the first goal; improvements to the decompiler's output are planned as separate,
named profiles that you choose.

## What does not carry over

- **Java scripts and Java plugins** do not run in Basilisk. A Python layer with the names of Ghidra's
  `FlatProgramAPI` is planned so that Python scripts port with small changes. See
  [Scripting and plugins](/docs/scripting/).
- **Ghidra project files and program databases** are not read directly. Exchange through Ghidra's export
  formats is planned with the loaders and exporters (M4, M6).

## Names

| Ghidra | Basilisk |
|---|---|
| `sleigh` (the SLEIGH compiler) | [`basilisk sleigh compile`](/docs/cli/sleigh-compile/), with the same options |
| `analyzeHeadless` | `basilisk analyze` (planned, M5) |
| The decompiler process `decompile` | The `bk-decomp-*` crates, in process (M3) |
| `.sla`, `.slaspec`, `.sinc`, `.ldefs`, `.pspec`, `.cspec`, `.opinion` | The same files, unchanged |
| CodeBrowser | The main window; views keep Ghidra's names |
| PyGhidra | The `basilisk` Python package (planned, M9) |
