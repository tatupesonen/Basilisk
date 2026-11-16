#!/usr/bin/env python3
"""Import dependencies between groups of Java packages, from Ghidra's source.

Usage: pkgdeps.py <ghidra root> <groups file> <out prefix>

Reads every `src/main/java` tree under Ghidra/ (tests are not read). Each
file belongs to a *group*: the groups file gives rules, one per line,

    <group name> <module path or *> <package prefix>

and the longest matching package prefix among the rules for the file's
module (or `*`) wins; a file no rule matches belongs to the group named
after its module (`Features/Base` -> `Base:other`).

Imports are resolved to classes, not packages, because Ghidra splits
packages over modules (`ghidra.util` has files in Generic, Utility,
SoftwareModeling and Base). An explicit import (static ones included) is
resolved by stripping trailing name components until a top-level class
of the tree is found. A wildcard import `a.b.*` is resolved by looking
for each top-level class name of package `a.b` as a word in the file's
text. JDK and third-party imports are ignored.

Not seen: a use of a class of the same package that lives in another
module (no import is needed for it), and fully qualified names written
in code. Both are rare in Ghidra's source; the edge counts are a floor.

Writes:
  <out>-groups.tsv   group, files, lines
  <out>-edges.tsv    from, to, files (files of `from` importing `to`), imports
  <out>-scc.txt      strongly connected components of the group graph with
                     more than one member (each is a dependency cycle), and
                     a topological order of the condensation (leaves first)
"""
import os
import re
import sys

ROOT, GROUPS, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
IMPORT = re.compile(r"^import\s+(static\s+)?([\w.]+?)(\.\*)?;", re.M)
WORD = re.compile(r"[A-Za-z_]\w*")
PKG = re.compile(r"^package\s+([\w.]+);", re.M)

rules = []
with open(GROUPS) as f:
    for line in f:
        line = line.split("#")[0].strip()
        if line:
            g, mod, pref = line.split()
            rules.append((g, mod, pref))


def group_of(module, pkg):
    best, blen = None, -1
    for g, mod, pref in rules:
        if mod != "*" and mod != module:
            continue
        if pkg == pref or pkg.startswith(pref + "."):
            score = len(pref) * 2 + (1 if mod != "*" else 0)
            if score > blen:
                best, blen = g, score
    return best or module.split("/")[-1] + ":other"


files = []  # (group, lines, imports, words)
classes = {}  # (pkg, class) -> group
pkg_classes = {}  # pkg -> {class: group}
for dirpath, dirnames, fnames in os.walk(os.path.join(ROOT, "Ghidra")):
    dirnames[:] = [d for d in dirnames if d != "build"]
    rel = os.path.relpath(dirpath, ROOT).replace(os.sep, "/")
    m = re.match(r"^Ghidra/(.*?)/src/main/java(?:/|$)", rel + "/")
    if not m:
        continue
    module = m.group(1)
    for fn in fnames:
        if not fn.endswith(".java"):
            continue
        with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
            text = f.read()
        pm = PKG.search(text)
        pkg = pm.group(1) if pm else ""
        g = group_of(module, pkg)
        imports = IMPORT.findall(text)
        words = set(WORD.findall(text)) if any(w for _s, _n, w in imports) else set()
        files.append((g, text.count("\n"), imports, words))
        classes[(pkg, fn[:-5])] = g
        pkg_classes.setdefault(pkg, {})[fn[:-5]] = g


def resolve(name, wildcard, words):
    """Groups an import refers to."""
    if wildcard:
        if name in pkg_classes:  # a package
            return {g for c, g in pkg_classes[name].items() if c in words}
        # `import static a.b.C.*` or `import a.b.C.*` (nested types)
    parts = name.split(".")
    while len(parts) > 1:
        key = (".".join(parts[:-1]), parts[-1])
        if key in classes:
            return {classes[key]}
        parts.pop()
    return set()


sizes, edges = {}, {}
for g, lines, imports, words in files:
    s = sizes.setdefault(g, [0, 0])
    s[0] += 1
    s[1] += lines
    seen = set()
    for _static, name, wildcard in imports:
        for to in resolve(name, wildcard, words):
            if to == g:
                continue
            e = edges.setdefault((g, to), [0, 0])
            e[1] += 1
            if to not in seen:
                seen.add(to)
                e[0] += 1

with open(OUT + "-groups.tsv", "w") as f:
    f.write("group\tfiles\tlines\n")
    for g in sorted(sizes):
        f.write(f"{g}\t{sizes[g][0]}\t{sizes[g][1]}\n")
with open(OUT + "-edges.tsv", "w") as f:
    f.write("from\tto\tfiles\timports\n")
    for (a, b) in sorted(edges):
        f.write(f"{a}\t{b}\t{edges[(a, b)][0]}\t{edges[(a, b)][1]}\n")

# Tarjan's algorithm, iterative
adj = {g: set() for g in sizes}
for (a, b) in edges:
    adj[a].add(b)
index, low, on, stack, comps, counter = {}, {}, set(), [], [], [0]
for root in sorted(adj):
    if root in index:
        continue
    work = [(root, iter(sorted(adj[root])))]
    index[root] = low[root] = counter[0]
    counter[0] += 1
    stack.append(root)
    on.add(root)
    while work:
        v, it = work[-1]
        advanced = False
        for w in it:
            if w not in index:
                index[w] = low[w] = counter[0]
                counter[0] += 1
                stack.append(w)
                on.add(w)
                work.append((w, iter(sorted(adj[w]))))
                advanced = True
                break
            if w in on:
                low[v] = min(low[v], index[w])
        if advanced:
            continue
        work.pop()
        if work:
            low[work[-1][0]] = min(low[work[-1][0]], low[v])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            comps.append(sorted(comp))
with open(OUT + "-scc.txt", "w") as f:
    f.write("# Cycles (strongly connected components with more than one group)\n")
    for c in comps:
        if len(c) > 1:
            lines = sum(sizes[g][1] for g in c)
            f.write(f"cycle of {len(c)} groups, {lines} lines: {', '.join(c)}\n")
    f.write("\n# Condensation in dependency order (a component depends only on earlier ones)\n")
    for c in comps:  # Tarjan emits components in reverse topological order: leaves first
        lines = sum(sizes[g][1] for g in c)
        f.write(f"{lines:8d}  {' + '.join(c)}\n")
