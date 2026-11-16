#!/usr/bin/env python3
"""Every concrete Analyzer in Ghidra: type, priority, default, what it imports.

Usage: analyzers.py <ghidra root> <extension-classes.tsv>  > analyzers.tsv

For each concrete class under the root `Analyzer` in extension-classes.tsv
the script reads the source file and extracts, textually:

* the AnalyzerType named in the file (BYTE_ANALYZER, INSTRUCTION_ANALYZER,
  FUNCTION_ANALYZER, FUNCTION_MODIFIERS_ANALYZER,
  FUNCTION_SIGNATURES_ANALYZER, DATA_ANALYZER) - the first one mentioned;
  "inherited" when the file names none (the super class decides);
* the first `setPriority(...)` argument, with white space removed;
* whether `setDefaultEnablement(true)` appears;
* which subsystems the file imports, as flags:
    D  the decompiler (ghidra.app.decompiler)
    E  emulation (ghidra.pcode.emu, ghidra.app.emulator, ghidra.pcode.emulate)
    S  symbolic propagation (SymbolicPropogator / ConstantPropagation)
    P  PDB (ghidra.app.util.pdb, ghidra.pdb)
    W  DWARF (ghidra.app.util.bin.format.dwarf)
    M  demangler (ghidra.app.util.demangler)
    B  byte-pattern search (ghidra.util.bytesearch, ghidra.app.analyzers patterns)
    F  a binary-format package (ghidra.app.util.bin.format.*) other than dwarf
    G  graph / block models (ghidra.program.model.block)

Output rows: class, module, package, lines, type, priority, default, flags, supers.
"""
import csv
import os
import re
import sys

ROOT, TSV = sys.argv[1], sys.argv[2]
FLAGS = [
    ("D", r"import ghidra\.app\.decompiler"),
    ("E", r"import ghidra\.(pcode\.emu|app\.emulator|pcode\.emulate)"),
    ("S", r"SymbolicPropogator|ConstantPropagationAnalyzer|ConstantPropagationContextEvaluator"),
    ("P", r"import (ghidra\.app\.util\.pdb|ghidra\.pdb|ghidra\.app\.util\.bin\.format\.pdb)"),
    ("W", r"import ghidra\.app\.util\.bin\.format\.dwarf"),
    ("M", r"import ghidra\.app\.util\.demangler"),
    ("B", r"import ghidra\.util\.bytesearch|import ghidra\.app\.plugin\.core\.searchmem"),
    ("F", r"import ghidra\.app\.util\.bin\.format\.(?!dwarf)"),
    ("G", r"import ghidra\.program\.model\.block"),
]
TYPE = re.compile(r"AnalyzerType\.(\w+)")
PRIO = re.compile(r"setPriority\(\s*([^;]*?)\)\s*;", re.S)

print("class\tmodule\tpackage\tlines\ttype\tpriority\tdefault\tflags\tsupers")
with open(TSV) as f:
    for row in csv.DictReader(f, delimiter="\t"):
        if row["root"] != "Analyzer" or row["abstract"] == "1":
            continue
        path = os.path.join(ROOT, row["module"], "src", "main", "java",
                            row["package"].replace(".", os.sep), row["class"] + ".java")
        try:
            with open(path, encoding="utf-8", errors="replace") as src:
                text = src.read()
        except OSError:
            text = ""
        t = TYPE.search(text)
        p = PRIO.search(text)
        flags = "".join(k for k, pat in FLAGS if re.search(pat, text))
        print("\t".join([
            row["class"], row["module"], row["package"], row["lines"],
            t.group(1) if t else "inherited",
            re.sub(r"\s+", "", p.group(1)) if p else "inherited",
            "1" if re.search(r"setDefaultEnablement\(\s*true\s*\)", text) else "0",
            flags or "-", row["supers"]]))
