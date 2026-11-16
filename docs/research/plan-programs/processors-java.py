#!/usr/bin/env python3
"""Java under Ghidra/Processors by kind of class (file-name suffix).

Usage: processors-java.py <ghidra root>  > processors-java.tsv
Kinds: ELF/Mach-O/COFF relocation handlers and their type enums and
contexts, ELF extensions, analyzers, emulate-state modifiers, loaders,
and the rest. Rows: kind, files, lines; then one row per module.
"""
import os, re, sys
ROOT = os.path.join(sys.argv[1], "Ghidra", "Processors")
KINDS = [("elf-relocation", r"Elf.*Relocation|ElfRelocation"), ("macho-relocation", r"MachoRelocation"),
         ("coff-relocation", r"CoffRelocation"), ("elf-extension", r"ElfExtension|ElfConstants|ElfProgramBuilder"),
         ("analyzer", r"Analyzer"), ("emulate-state", r"Emulate\w*StateModifier|EmulateInstructionStateModifier"),
         ("loader", r"Loader"), ("pcode-inject", r"Inject|Payload"), ("other", r"")]
tot, mods = {}, {}
for dp, _d, fs in os.walk(ROOT):
    if "/src/main/java" not in dp.replace(os.sep, "/"):
        continue
    mod = os.path.relpath(dp, ROOT).split(os.sep)[0]
    for fn in fs:
        if fn.endswith(".java"):
            n = open(os.path.join(dp, fn), "rb").read().count(b"\n")
            kind = next(k for k, p in KINDS if re.search(p, fn))
            t = tot.setdefault(kind, [0, 0]); t[0] += 1; t[1] += n
            m = mods.setdefault(mod, {}); m[kind] = m.get(kind, 0) + n
print("kind\tfiles\tlines")
for k, _p in KINDS:
    if k in tot:
        print(f"{k}\t{tot[k][0]}\t{tot[k][1]}")
print("\nmodule\t" + "\t".join(k for k, _ in KINDS))
for mod in sorted(mods):
    print(mod + "\t" + "\t".join(str(mods[mod].get(k, 0)) for k, _ in KINDS))
