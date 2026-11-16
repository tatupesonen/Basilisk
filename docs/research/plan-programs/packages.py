#!/usr/bin/env python3
"""Java packages of one or more Ghidra modules: files, lines, top-level types.

Usage: packages.py <ghidra root> <depth> <module dir>...  > packages.tsv

Reads `src/main/java` of each module. A package deeper than <depth>
components is folded into its ancestor at that depth (depth 0: no
folding). Lines are physical lines. "types" counts files (one top-level
public type per file in Ghidra's code); "abstract" and "interfaces" count
files whose primary declaration is an abstract class or an interface.

Output rows: module, package, files, lines, interfaces, abstract, enums.
"""
import os
import re
import sys

ROOT, DEPTH = sys.argv[1], int(sys.argv[2])
DECL = re.compile(
    r"^((?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)\s+)*)"
    r"(class|interface|enum|record|@interface)\s+(\w+)", re.M)

print("module\tpackage\tfiles\tlines\tinterfaces\tabstract\tenums")
for mod in sys.argv[3:]:
    base = os.path.join(ROOT, mod, "src", "main", "java")
    acc = {}
    for dirpath, _dirs, files in os.walk(base):
        pkg = os.path.relpath(dirpath, base).replace(os.sep, ".")
        if DEPTH:
            pkg = ".".join(pkg.split(".")[:DEPTH])
        for fn in files:
            if not fn.endswith(".java"):
                continue
            with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
                text = f.read()
            a = acc.setdefault(pkg, [0, 0, 0, 0, 0])
            a[0] += 1
            a[1] += text.count("\n")
            m = DECL.search(text)
            if m:
                if m.group(2) == "interface":
                    a[2] += 1
                elif "abstract" in m.group(1):
                    a[3] += 1
                elif m.group(2) == "enum":
                    a[4] += 1
    for pkg in sorted(acc):
        print("\t".join([mod, pkg] + [str(x) for x in acc[pkg]]))
