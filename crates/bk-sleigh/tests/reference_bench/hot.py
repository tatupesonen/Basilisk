#!/usr/bin/env python3
"""Instruction-level profile of one symbol from a `perf record` file, for
hosts where `perf annotate` cannot read Rust's debug information.

    hot.py PERF_DATA BINARY SYMBOL [MIN_PERCENT]

Counts the samples per offset in SYMBOL (`perf script -F sym,symoff`),
disassembles SYMBOL with `llvm-objdump` (with source lines, `-l`), and
prints each instruction holding at least MIN_PERCENT (default 0.5) of the
symbol's samples, with the source line before it. Development tooling only.
"""

import collections
import re
import shutil
import subprocess
import sys


def main():
    data, binary, symbol = sys.argv[1:4]
    minimum = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
    script = subprocess.run(
        ["perf", "script", "-i", data, "-F", "sym,symoff"],
        capture_output=True, text=True, check=True).stdout
    counts = collections.Counter()
    for line in script.splitlines():
        line = line.strip()
        if line.startswith(symbol + "+0x"):
            counts[int(line[len(symbol) + 1:], 16)] += 1
    total = sum(counts.values())
    if not total:
        print("no samples in", symbol)
        return
    objdump = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-19") or "objdump"
    dump = subprocess.run(
        [objdump, "-d", "-l", "--no-show-raw-insn", "--disassemble-symbols=" + symbol, binary],
        capture_output=True, text=True, check=True).stdout
    start = None
    source = ""
    print("%s: %d samples" % (symbol, total))
    for line in dump.splitlines():
        m = re.match(r"^([0-9a-f]+) <", line)
        if m:
            start = int(m.group(1), 16)
            continue
        if line.startswith("; "):
            source = line[2:]
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s*(.*)$", line)
        if not m or start is None:
            continue
        offset = int(m.group(1), 16) - start
        share = 100.0 * counts.get(offset, 0) / total
        if share >= minimum:
            print("%6.2f%%  +0x%-5x %-50s %s" % (share, offset, m.group(2)[:50], source[-70:]))


if __name__ == "__main__":
    main()
