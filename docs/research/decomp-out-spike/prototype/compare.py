#!/usr/bin/env python3
"""Throw-away prototype, part 3: tree -> Emit calls, compared with the log.

    compare.py LOGDIR [LOGDIR...] [--summary FILE] [--failures FILE]

For every `<name>.tree` in the directories: build each function's tree from
the `.tree` file alone (tree.py), print it (printer.py), and compare the
resulting call sequence with the function's calls in `<name>.emit`, after
renumbering the begin/open ids of both by order of first appearance. Prints
per-variant counts; the failures file lists every function that does not
match, with the first differing call and the cause.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

import tree as T
import printer as Pr

ID_RESULT = {"beginDocument", "beginFunction", "beginBlock", "beginReturnType", "beginVarDecl",
             "beginStatement", "beginFuncProto", "openParen", "openGroup", "startIndent",
             "startComment", "openBraceIndent"}
ID_ARG1 = {"endDocument", "endFunction", "endBlock", "endReturnType", "endVarDecl", "endStatement",
           "endFuncProto", "closeGroup", "stopIndent", "stopComment"}
ID_ARG2 = {"closeParen", "closeBraceIndent"}


def canon(lines):
    """Rename ids by order of first appearance."""
    m = {}

    def cid(x):
        if x not in m:
            m[x] = f"#{len(m)}"
        return m[x]

    out = []
    for line in lines:
        f = line.split("\t")
        name = f[0]
        if name in ID_RESULT and len(f) >= 3 and f[-2] == "=":
            f[-1] = cid(f[-1])
        if name in ID_ARG1 and len(f) > 1:
            f[1] = cid(f[1])
        if name in ID_ARG2 and len(f) > 2:
            f[2] = cid(f[2])
        out.append("\t".join(f))
    return out


def read_emit(path):
    res, cur = {}, None
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("F\t"):
                cur = int(line.split("\t")[1])
                res[cur] = []
            elif line.startswith("/F\t"):
                cur = None
            elif cur is not None:
                res[cur].append(line)
    return res


def run_file(tree_path, stats, failures, coverage):
    emit = read_emit(tree_path.with_suffix(".emit"))
    for fn in T.read_functions(tree_path):
        stats["functions"] += 1
        expected = canon(emit.get(fn.num, []))
        stats["emit_calls"] += len(expected)
        try:
            T.build(fn)
            for k, v in fn.pushes.items():
                stats["push_" + k] += v
            pr = Pr.Printer(fn.options)
            pr.node(fn.root)
            got = canon(pr.out.lines)
            for k, v in pr.counts.items():
                coverage["node:" + k] += v
            if pr.mod_mismatches:
                stats["functions_mods_differ"] += 1
                for kind, logged, ours in pr.mod_mismatches[:3]:
                    failures.append(f"{tree_path.name}\t{fn.num}\t{fn.name}\tmods\t{kind} logged {logged:#x} recomputed {ours:#x}")
            collect_coverage(fn.root, coverage)
            for m in fn.vnmods:
                for bit in range(16):
                    if m & (1 << bit):
                        coverage[f"mod-at-pushVn:{1 << bit:#x}"] += 1
            for line in expected:
                coverage["emit:" + line.split("\t")[0]] += 1
        except (T.TreeError, Pr.Mismatch, IndexError, ValueError, KeyError) as e:
            stats["functions_error"] += 1
            failures.append(f"{tree_path.name}\t{fn.num}\t{fn.name}\terror\t{type(e).__name__}: {e}")
            continue
        n = 0
        while n < len(got) and n < len(expected) and got[n] == expected[n]:
            n += 1
        if n == len(got) == len(expected):
            stats["functions_match"] += 1
            stats["emit_calls_match"] += n
        else:
            stats["emit_calls_match"] += n
            ctx_e = expected[n] if n < len(expected) else "<end>"
            ctx_g = got[n] if n < len(got) else "<end>"
            failures.append(f"{tree_path.name}\t{fn.num}\t{fn.name}\tdiff at call {n}\tlog: {ctx_e}\tprinted: {ctx_g}")


def collect_coverage(node, cov):
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, T.Struct):
            if n.kind.startswith("block") or n.kind == "forLoop":
                kind = n.facts[0].split(":")[0]
                cov[f"block:{n.kind}:{kind}"] += 1
                if n.kind == "blockIf":
                    cov[f"if:{n.facts[3]}"] += 1
            for bit in range(16):
                if n.mods & (1 << bit):
                    cov[f"mod-at-entry:{1 << bit:#x}"] += 1
            stack.extend(n.kids)
        elif isinstance(n, T.OpNode):
            cov[f"token:{n.tok}"] += 1
            stack.extend(n.kids)
        else:
            cov[f"atom:{n.tag}"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--summary")
    ap.add_argument("--failures")
    ap.add_argument("--coverage")
    args = ap.parse_args()
    rc = 0
    lines = []
    allfail = []
    cov_all = Counter()
    for d in args.dirs:
        stats, failures, cov = Counter(), [], Counter()
        for p in sorted(Path(d).glob("*.tree")):
            run_file(p, stats, failures, cov)
        cov_all.update(cov)
        name = Path(d).name
        lines.append(f"{name}\tfunctions\t{stats['functions']}\tmatch\t{stats['functions_match']}\t"
                     f"errors\t{stats['functions_error']}\temit_calls\t{stats['emit_calls']}\t"
                     f"emit_calls_match\t{stats['emit_calls_match']}\tpush_op\t{stats['push_op']}\t"
                     f"push_atom\t{stats['push_atom']}\tpush_vn\t{stats['push_vn']}\t"
                     f"structural\t{stats['push_struct']}\tstate\t{stats['push_state']}\t"
                     f"mods_differ\t{stats['functions_mods_differ']}")
        allfail.extend(f"{name}\t{x}" for x in failures)
        if stats["functions_match"] != stats["functions"]:
            rc = 1
    text = "\n".join(lines) + "\n"
    print(text, end="")
    if args.summary:
        Path(args.summary).write_text(text)
    if args.failures:
        Path(args.failures).write_text("\n".join(allfail) + ("\n" if allfail else ""))
    else:
        for x in allfail[:40]:
            print(x)
    if args.coverage:
        Path(args.coverage).write_text("".join(f"{k}\t{v}\n" for k, v in sorted(cov_all.items())))
    return rc


if __name__ == "__main__":
    sys.exit(main())
