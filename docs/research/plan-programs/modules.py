#!/usr/bin/env python3
"""Every Ghidra module: size by language and source set, declared dependencies.

Usage: modules.py <ghidra root>  > modules.tsv

A module is a directory that holds a Module.manifest (Ghidra's own
definition). For each one the script counts lines (physical lines,
comments and blanks included) of Java per source set, of C/C++, Python,
SLEIGH and other notable kinds, counts files, and reads the module's
build.gradle for `project(':X')` dependencies (api, implementation,
testImplementation, and so on) and Module.manifest for MODULE DEPENDENCY
lines.

Output: one tab-separated row per module, sorted by path.
"""
import os
import re
import sys

ROOT = sys.argv[1]
JAVA_SETS = ["main", "test", "test.slow", "test.processors", "screen", "integrationTest"]
KINDS = {
    ".java": "java", ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "c", ".hh": "cpp",
    ".hpp": "cpp", ".y": "cpp", ".l": "cpp", ".py": "python", ".slaspec": "sleigh",
    ".sinc": "sleigh", ".g": "antlr", ".g4": "antlr", ".jj": "javacc",
}
DEP = re.compile(r"^\s*(\w+)\s*\(?\s*project\(\s*(?:path:\s*)?['\"]:([\w.-]+)['\"]")
MAN = re.compile(r"^MODULE DEPENDENCY:\s*(\S+)")


def count_lines(path):
    try:
        with open(path, "rb") as f:
            return f.read().count(b"\n")
    except OSError:
        return 0


def measure(mod):
    lines = {}
    files = {}
    for dirpath, dirnames, filenames in os.walk(mod):
        dirnames[:] = [d for d in dirnames if d not in ("build", ".git", "node_modules")]
        rel = os.path.relpath(dirpath, mod)
        parts = rel.split(os.sep)
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            kind = KINDS.get(ext)
            if kind is None:
                continue
            key = kind
            if kind == "java":
                # src/<set>/java/... ; scripts and other places are "other"
                sset = "other"
                if len(parts) >= 3 and parts[0] == "src" and parts[2] == "java":
                    sset = parts[1]
                elif parts[0] in ("ghidra_scripts", "developer_scripts"):
                    sset = "scripts"
                key = "java:" + sset
            n = count_lines(os.path.join(dirpath, fn))
            lines[key] = lines.get(key, 0) + n
            files[key] = files.get(key, 0) + 1
    return lines, files


def deps(mod):
    out = {}
    g = os.path.join(mod, "build.gradle")
    if os.path.exists(g):
        with open(g, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = DEP.match(line)
                if m:
                    conf, name = m.group(1), m.group(2)
                    kind = "test" if "test" in conf.lower() else "main"
                    out.setdefault(kind, set()).add(name)
    man = set()
    mf = os.path.join(mod, "Module.manifest")
    with open(mf, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MAN.match(line)
            if m:
                man.add(m.group(1))
    return out, man


mods = []
for top in ("Ghidra", "GPL"):
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
        dirnames[:] = sorted(d for d in dirnames if d not in ("build", ".git"))
        if "Module.manifest" in filenames:
            mods.append(dirpath)
            dirnames[:] = []

cols = ["java:main", "java:test", "java:test.slow", "java:test.processors", "java:screen",
        "java:scripts", "java:other", "cpp", "c", "python", "sleigh", "antlr", "javacc"]
print("\t".join(["module", "files_java_main", "files_java_tests"] + cols +
                ["deps_main", "deps_test", "manifest_deps"]))
for mod in sorted(mods):
    lines, files = measure(mod)
    d, man = deps(mod)
    tests = sum(files.get(k, 0) for k in ("java:test", "java:test.slow", "java:test.processors"))
    row = [os.path.relpath(mod, ROOT), str(files.get("java:main", 0)), str(tests)]
    row += [str(lines.get(c, 0)) for c in cols]
    row += [",".join(sorted(d.get("main", ()))), ",".join(sorted(d.get("test", ()))),
            ",".join(sorted(man))]
    print("\t".join(row))
