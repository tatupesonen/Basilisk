#!/usr/bin/env python3
"""Which Ghidra modules do PARITY.md and PLAN.md name?

Usage: roadmap-coverage.py modules.tsv <PARITY.md> <PLAN.md>  > roadmap-coverage.tsv

For every module of modules.tsv (a directory with a Module.manifest)
prints whether its name occurs as a word in PARITY.md and in PLAN.md,
with its Java main lines and other source lines. Processor modules are
summarised by PARITY's "39 processor modules" row and are marked `group`.
A name can occur without the module being planned (`Base`); the table is
a first filter, read by hand in roadmap-check.md.
"""
import csv, re, sys
parity = open(sys.argv[2], encoding="utf-8").read()
plan = open(sys.argv[3], encoding="utf-8").read()
print("module\tjava_main\tother_src\tin_PARITY\tin_PLAN")
for r in csv.DictReader(open(sys.argv[1]), delimiter="\t"):
    name = r["module"].split("/")[-1]
    other = sum(int(r[k]) for k in ("cpp", "c", "python", "java:other", "java:scripts"))
    pat = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])")
    if "/Processors/" in r["module"]:
        a = b = "group"
    else:
        a = "yes" if pat.search(parity) else "NO"
        b = "yes" if pat.search(plan) else "NO"
    print(f"{r['module']}\t{r['java:main']}\t{other}\t{a}\t{b}")
