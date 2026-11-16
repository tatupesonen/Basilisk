#!/usr/bin/env python3
"""Which classes of one Ghidra module are imported by a set of source directories.

Usage: class-uses.py <ghidra root> <target module dir> <source dir>...

Lists every top-level class of <target module>/src/main/java that a file
under one of the source directories imports explicitly or uses through a
wildcard import (the class name appears as a word in the file), with the
number of importing files and the class's own size. Shows what a port of
the source directories really needs from the target module.
Output rows: importing files, class lines, package.Class
"""
import os, re, sys
ROOT, TARGET = sys.argv[1], sys.argv[2]
IMPORT = re.compile(r"^import\s+(?:static\s+)?([\w.]+?)(\.\*)?;", re.M)
PKG = re.compile(r"^package\s+([\w.]+);", re.M)
WORD = re.compile(r"[A-Za-z_]\w*")
classes, bypkg = {}, {}
base = os.path.join(ROOT, TARGET, "src", "main", "java")
for dp, _d, fs in os.walk(base):
    for fn in fs:
        if fn.endswith(".java"):
            pkg = os.path.relpath(dp, base).replace(os.sep, ".")
            n = open(os.path.join(dp, fn), "rb").read().count(b"\n")
            classes[(pkg, fn[:-5])] = n
            bypkg.setdefault(pkg, []).append(fn[:-5])
uses = {}
for src in sys.argv[3:]:
    for dp, _d, fs in os.walk(os.path.join(ROOT, src)):
        for fn in fs:
            if not fn.endswith(".java"):
                continue
            text = open(os.path.join(dp, fn), encoding="utf-8", errors="replace").read()
            words = None
            hit = set()
            for name, wild in IMPORT.findall(text):
                if wild and name in bypkg:
                    if words is None:
                        words = set(WORD.findall(text))
                    hit.update((name, c) for c in bypkg[name] if c in words)
                    continue
                parts = name.split(".")
                while len(parts) > 1:
                    key = (".".join(parts[:-1]), parts[-1])
                    if key in classes:
                        hit.add(key)
                        break
                    parts.pop()
            for k in hit:
                uses[k] = uses.get(k, 0) + 1
tot = 0
for k, n in sorted(uses.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"{n}\t{classes[k]}\t{k[0]}.{k[1]}")
    tot += classes[k]
print(f"# {len(uses)} classes of {len(classes)}, {tot} lines of {sum(classes.values())}")
