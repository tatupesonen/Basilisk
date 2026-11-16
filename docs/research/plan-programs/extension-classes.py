#!/usr/bin/env python3
"""Loaders, analyzers, relocation handlers, exporters, file systems: every class.

Usage: extension-classes.py <ghidra root>  > extension-classes.tsv

Ghidra discovers its extension points by class-name suffix
(`Ghidra/Framework/Generic/data/ExtensionPoint.manifest` in each module)
and by super-type. This script walks every `src/main/java` tree, reads
each file's primary type declaration, and follows `extends`/`implements`
transitively (by simple name; a clash of simple names between packages
would be reported under both) to list every concrete class under these
roots:

  Loader, Analyzer, ElfRelocationHandler, MachoRelocationHandler,
  CoffRelocationHandler, ElfExtension, Exporter, GFileSystem, Demangler,
  FunctionStartAnalyzer-style subclasses come out under Analyzer,
  DataType (model types), BackgroundCommand / Command, PeMarkupable-free.

Output rows: root, class, abstract (0/1), module, package, lines,
direct super types.
"""
import os
import re
import sys

ROOT = sys.argv[1]
ROOTS = ["Loader", "Analyzer", "ElfRelocationHandler", "MachoRelocationHandler",
         "CoffRelocationHandler", "ElfExtension", "ElfLoadAdapter", "Exporter",
         "GFileSystem", "Demangler", "Command", "BuiltInDataType", "PcodeInjectLibrary",
         "ExceptionHandlerFrame", "OldLanguageMappingService", "Validator",
         "FunctionSignatureParser", "Recognizer", "ByteProvider", "LibrarySymbolTable",
         "EmulateInstructionStateModifier", "ParallelInstructionLanguageHelper",
         "DataTypeArchiveTransformer", "AnalysisWorker", "DebugInfoEntryProcessor"]

DECL = re.compile(
    r"^((?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)\s+)*)"
    r"(class|interface|enum|record)\s+(\w+)(?:<[^{]*?>)?"
    r"([^{;]*)\{", re.M | re.S)
PKG = re.compile(r"^package\s+([\w.]+);", re.M)


def supers(tail):
    tail = re.sub(r"<[^<>]*>", "", tail)
    tail = re.sub(r"<[^<>]*>", "", tail)
    names = []
    for kw in ("extends", "implements", "permits"):
        m = re.search(r"\b" + kw + r"\b(.*?)(?=\bextends\b|\bimplements\b|\bpermits\b|$)", tail, re.S)
        if m and kw != "permits":
            for n in m.group(1).split(","):
                n = n.strip().split(".")[-1]
                if re.fullmatch(r"\w+", n or ""):
                    names.append(n)
    return names


types = {}  # simple name -> list of (abstract, module, package, lines, supers, kind)
for top in ("Ghidra", "GPL"):
    for dirpath, dirnames, files in os.walk(os.path.join(ROOT, top)):
        dirnames[:] = [d for d in dirnames if d != "build"]
        norm = dirpath.replace(os.sep, "/")
        if "/src/" not in norm + "/" or "/java" not in norm:
            continue
        m = re.search(r"^(.*?)/src/([\w.]+)/java", os.path.relpath(norm, ROOT))
        if not m or m.group(2) not in ("main", "dmg"):
            continue
        module = m.group(1)
        for fn in files:
            if not fn.endswith(".java"):
                continue
            with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
                text = f.read()
            pm = PKG.search(text)
            dm = DECL.search(text)
            if not dm:
                continue
            name = dm.group(3)
            if name != fn[:-5]:
                # primary declaration search: find the one named after the file
                for dm2 in DECL.finditer(text):
                    if dm2.group(3) == fn[:-5]:
                        dm = dm2
                        name = fn[:-5]
                        break
            types.setdefault(name, []).append(
                (1 if "abstract" in dm.group(1) or dm.group(2) == "interface" else 0, module,
                 pm.group(1) if pm else "", text.count("\n"), supers(dm.group(4)), dm.group(2)))

memo = {}


def reaches(name, root, seen=()):
    if name == root:
        return True
    key = (name, root)
    if key in memo:
        return memo[key]
    if name in seen:
        return False
    r = any(reaches(s, root, seen + (name,)) for t in types.get(name, ()) for s in t[4])
    memo[key] = r
    return r


print("root\tclass\tabstract\tmodule\tpackage\tlines\tsupers")
for root in ROOTS:
    for name in sorted(types):
        if name == root or not reaches(name, root):
            continue
        for t in types[name]:
            print("\t".join([root, name, str(t[0]), t[1], t[2], str(t[3]), ",".join(t[4])]))
