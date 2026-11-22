---
title: How results are checked
description: How Basilisk is compared with Ghidra — reference tools built from Ghidra's source, differential tests, ported tests, fuzzing — and what happens where Ghidra's own answer is not fixed.
sidebar:
  order: 5
---

A reimplementation is only useful if it gives the same answers. Basilisk does not rely on reading Ghidra's
code carefully and hoping; each part is run against Ghidra itself, on the same input, and the outputs are
compared.

## The reference

The project builds a set of **reference tools** from Ghidra's own source at one pinned commit: Ghidra's
SLEIGH compiler, its decompiler, and a few small programs that link Ghidra's C++ code and print what it
computes in a form that can be compared.

| Reference tool | Built from | Basilisk is compared on |
|---|---|---|
| `sleigh` | Ghidra's SLEIGH compiler | The compiled `.sla` of every specification |
| `pcodedump` | Ghidra's SLEIGH engine | Every decoded instruction and p-code operation |
| `snippetdump` | Ghidra's p-code snippet compiler | The snippets inside `.cspec` and `.pspec` files |
| The decompiler consoles | Ghidra's decompiler, with commands added to dump its internal state | The decompiler's state after each stage, not only its final text |
| Generated tables | Ghidra's implementations of each p-code operation, value ranges, calling conventions, type rules | The same computations in Basilisk, case by case |

The tools add printing around Ghidra's code; they do not change it. The decompiler's own binary is checked
to be identical with and without the additions.

## Kinds of test

**Differential tests** run Basilisk and a reference tool on the same input and compare the outputs. Where
possible the comparison is of bytes, with no tolerance: all 150 compiled languages, every record of the
disassembly of test streams in all 150 languages.

**Ghidra's own tests, ported.** Ghidra's unit tests for a part are translated when that part is ported, and
the repository keeps a checklist of every Ghidra test class and its state. The decompiler's 93 data tests
(a few bytes of code, a language, and the expected output) are the acceptance test for the decompiler.

**Stage-by-stage comparison for the decompiler.** A decompiler has dozens of passes, and a difference in
the final C says little about where it arose. The reference consoles therefore dump Ghidra's internal
state — operations, variables, blocks, symbols — at chosen points. Each Basilisk pass is tested by loading
Ghidra's state before the pass and comparing with Ghidra's state after it.

**Property tests and generated cases** cover what example files do not: hundreds of thousands of generated
expressions, ranges and bit patterns, each checked against the reference.

**Fuzzing.** Every parser of untrusted input has a fuzz target. The rule is that malformed input gives an
error: no panic, no overflow, no unbounded allocation.

**Checks on the code itself.** Unsafe code is confined to a short list of crates, and those run under Miri
and the sanitizers. Lints forbid arithmetic that can overflow silently and indexing that can panic.

## Where it runs

Every change is built and tested on Linux, macOS and Windows before it is merged. A nightly run on a
separate machine repeats the tests and adds the slow ones: long fuzzing runs, Miri, the sanitizers, the
Windows build under Wine with Microsoft's C runtime, 64-bit ARM under emulation, and a fresh capture of the
decompiler reference to detect drift.

## When Ghidra has no single answer

Comparing against Ghidra turned up places where Ghidra's result depends on something outside its source:

- **The C++ standard library.** An unstable sort of items that compare equal gives one order with one
  library and another order with another.
- **The compiler's floating-point settings.** The SLEIGH compiler's output differs between x86-64 and
  64-bit ARM builds of the same source in 14 of 150 files.
- **Undefined behaviour.** Shifts by more than the width, reads of uninitialised fields, signed overflow.
- **The order a directory is listed in.**

In each such place Basilisk gives one defined answer on every machine: the one Ghidra's build for x86-64
Linux gives, when there is one. Each case is recorded as a decision in `docs/DECISIONS.md`, with the
evidence.

## Defects found in Ghidra

Running Ghidra's code against generated input finds defects in it: crashes, out-of-bounds reads, results
that change from run to run. They are collected in `docs/GHIDRA-BUGS.md` in the repository — about forty so
far — each with its location in Ghidra's source and what Basilisk does instead. None has been reported
upstream yet; the list is kept so that they can be.

## What is not claimed

- Equality is shown for the inputs that were tested. The test sets are large and generated, but they are
  not proofs.
- A part that is not listed as done in the [status matrix](/status/) has not been compared with anything.
- Speed is measured, not assumed; the figures and how they were taken are in `docs/PERF.md`.
