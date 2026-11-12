#!/usr/bin/env python3
"""Cheap text proxies over the decompiler output in `out/`.

    tools/metrics.py            one line per output file, then totals

These are the "cheap first" readability counters proposed in
`../decompiler-quality.md` (section 5). They need no ground truth and no
parser, and each one can be gamed (see the document), so they are trend
indicators for a fixed corpus, not a score.
"""

import pathlib
import re
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "out"

TYPE = r"(?:u?int[1248]|xunknown[1248]|float(?:4|8|10)|bool|char|code|void|size_t|ssize_t|\w+)"
COUNTERS = {
    # name: regex counted over the function bodies
    "goto": r"\bgoto\b",
    "cast": r"\((?:%s)(?: ?\*+)?\)(?=[\w(*&-])" % TYPE,
    "artefact": r"\b(?:CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d|SCARRY\d|SBORROW\d)\(|\._\d+_\d+_",
    "do_while": r"\}\s*while\s*\(",
    "for": r"\bfor\s*\(",
    "while": r"(?<!\} )\bwhile\s*\(",
    "switch": r"\bswitch\s*\(",
    "warning": r"WARNING",
    "rawaddr": r"\b0x[0-9a-f]{6,}\b(?!U?\s*[<>|&^])",
    "autoname": r"\b(?:[a-z]{1,3}Var\d+|param_\d+|[a-z]{1,3}Stack_[0-9a-f]+|local_[0-9a-f]+|in_\w+|unaff_\w+|extraout_\w+)\b",
}
FUNC = re.compile(r"^(?P<ret>[\w ]+?[ *]+)(?:__\w+ )?(?P<name>\w+)\((?P<params>[^)]*)\)\s*$", re.M)


def bodies(text):
    """(return type, name, body) for every function printed in a transcript."""
    found = []
    for match in FUNC.finditer(text):
        start = text.find("{", match.end())
        end = text.find("\n}", start)
        if start < 0 or end < 0:
            continue
        found.append((match.group("ret").strip(), match.group("name"), text[start : end + 2]))
    return found


def main():
    names = list(COUNTERS) + ["decls", "lines", "void"]
    total = dict.fromkeys(names, 0)
    funcs = 0
    print("%-36s %5s " % ("output", "funcs") + " ".join("%8s" % n for n in names))
    for path in sorted(OUT.glob("*.c")):
        row = dict.fromkeys(names, 0)
        found = bodies(path.read_text())
        for ret, _name, body in found:
            for name, pattern in COUNTERS.items():
                row[name] += len(re.findall(pattern, body))
            head = body.split("\n  \n")[0] if "\n  \n" in body else ""
            row["decls"] += len(re.findall(r"^  \w[\w ]*[ *]\w+(?: ?\[\d+\])?;$", head, re.M))
            row["lines"] += body.count("\n") + 1
            row["void"] += ret == "void"
        funcs += len(found)
        for name in names:
            total[name] += row[name]
        print("%-36s %5d " % (path.stem, len(found)) + " ".join("%8d" % row[n] for n in names))
    print("%-36s %5d " % ("TOTAL", funcs) + " ".join("%8d" % total[n] for n in names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
