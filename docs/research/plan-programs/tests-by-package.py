#!/usr/bin/env python3
"""Ghidra's JUnit tests by package, from the project's test checklist.

Usage: tests-by-package.py <docs/inventory/tests dir> <depth>  > tests-by-package.tsv

Reads every checklist file (`- [ ] `pkg.Class` (kind[, GUI], N tests)`),
folds the package to <depth> components (0: no folding), and prints per checklist file
and package: classes, @Test methods, GUI classes. The checklist is
generated from the Ghidra tree by scripts/gen-test-inventory.py.
"""
import os, re, sys
D, DEPTH = sys.argv[1], int(sys.argv[2])
LINE = re.compile(r"^- \[.\] `([\w.$]+)` \(([^)]*)\)")
print("file\tpackage\tclasses\ttests\tgui_classes")
for fn in sorted(os.listdir(D)):
    if not fn.endswith(".md") or fn == "README.md":
        continue
    acc = {}
    for line in open(os.path.join(D, fn), encoding="utf-8"):
        m = LINE.match(line)
        if not m:
            continue
        pkg = ".".join(m.group(1).split(".")[:-1])
        if DEPTH:
            pkg = ".".join(pkg.split(".")[:DEPTH])
        info = m.group(2)
        n = re.search(r"(\d+) tests?", info)
        a = acc.setdefault(pkg, [0, 0, 0])
        a[0] += 1
        a[1] += int(n.group(1)) if n else 0
        a[2] += 1 if "GUI" in info else 0
    for pkg in sorted(acc):
        print("\t".join([fn[:-3], pkg] + [str(x) for x in acc[pkg]]))
