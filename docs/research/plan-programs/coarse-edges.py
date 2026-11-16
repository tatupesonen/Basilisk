#!/usr/bin/env python3
"""Folds deps-edges.tsv into coarse buckets, for the roadmap check.

Usage: coarse-edges.py deps-edges.tsv deps-groups.tsv  > coarse-edges.txt
For each module-level group (`X:other`, `fw.*`) and each coarse bucket of
the program side, prints the buckets it imports with the number of
importing files (a file is counted once per fine group it imports, so a
bucket's figure can exceed the group's file count).
"""
import csv, re, sys
def bucket(g):
    for pat, b in [(r"^model\.", "model"), (r"^pdb\.", "progdb"), (r"^fmt\.", "formats"),
                   (r"^ui\.|\.ui$", "ui"), (r"^analysis\.", "analysis"), (r"^cmd", "cmd"),
                   (r"^sm\.", "sm-misc"), (r"^base\.", "base-misc"), (r"^sleigh\.", "sleigh-java")]:
        if re.search(pat, g):
            return b
    return g.replace(":other", "")
sizes = {}
for r in csv.DictReader(open(sys.argv[2]), delimiter="\t"):
    b = bucket(r["group"]); s = sizes.setdefault(b, [0, 0]); s[0] += int(r["files"]); s[1] += int(r["lines"])
e = {}
for r in csv.DictReader(open(sys.argv[1]), delimiter="\t"):
    a, b = bucket(r["from"]), bucket(r["to"])
    if a != b:
        e.setdefault(a, {}); e[a][b] = e[a].get(b, 0) + int(r["files"])
for a in sorted(e):
    deps = " ".join(f"{b}({n})" for b, n in sorted(e[a].items(), key=lambda kv: -kv[1]))
    print(f"{a} [{sizes[a][0]} files, {sizes[a][1]} lines] -> {deps}")
