#!/usr/bin/env python3
"""Run the oracle corpus through the reference console and the instrumented one.

    run_corpus.py --instr DIR/bin/decomp_instr --out OUT [--jobs N] [--only NAME]

Needs BASILISK_GHIDRA_DIR (the data tests) and BASILISK_REFERENCE_DIR
(bin/decomp and the compiled languages). The corpus is the one bk-oracle
captures (crates/bk-testkit/src/oracle/capture/scripts.rs): the 93 data tests,
run as `load test file <name>.xml` plus the test's commands up to `quit`, and
the research fragments of docs/research/decompiler-quality/frag, run as they
are (two that fail in plain `decomp` are skipped there too).

Variants of every script (each run by both consoles):
  orig    the script as it is
  xml     every `print C` followed by `print C xml`
  flat    every `print C` followed by `print C flat`         (coverage only)
  java    every `print C` followed by `print language java`  (coverage only)

The instrumented console runs `orig` twice (with and without BK_PRINTLOG) and
the others with BK_PRINTLOG. Its standard output and exit status must equal
the reference console's, byte for byte. Logs go to OUT/logs/<variant>/<corpus>.<name>.*;
OUT/identity.txt has one line per run and a summary.
"""
import argparse
import concurrent.futures as cf
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SKIP_RESEARCH = {"a07_switch.a64-gcc-O2", "a07_switch.x64-gcc-O2"}
VARIANTS = ["orig", "xml", "flat", "java"]
EXTRA = {"xml": "print C xml", "flat": "print C flat", "java": "print language java"}


def until_quit(cmds):
    out = []
    for c in cmds:
        c = c.strip()
        if c.split()[:1] == ["quit"]:
            break
        if c:
            out.append(c)
    return out


def data_tests(ghidra):
    d = Path(ghidra) / "Ghidra/Features/Decompiler/src/decompile/datatests"
    res = []
    for p in sorted(d.glob("*.xml"), key=lambda p: p.name.encode()):
        root = ET.parse(p).getroot()
        script = root.find("script")
        cmds = []
        for com in script:
            text = "".join(com.itertext()).replace("\r", "").replace("\n", " ")
            cmds.append(text)
        res.append(("datatests", p.stem, d, f"load test file {p.name}", until_quit(cmds)))
    return res


def research():
    d = ROOT / "docs/research/decompiler-quality"
    res = []
    for p in sorted((d / "frag").glob("*.script"), key=lambda p: p.name.encode()):
        if p.stem in SKIP_RESEARCH:
            continue
        lines = p.read_text().splitlines()
        res.append(("research", p.stem, d, lines[0], until_quit(lines[1:])))
    return res


def variant(load, cmds, v):
    lines = [load]
    for c in cmds:
        lines.append(c)
        if v != "orig" and c.strip() == "print C":
            lines.append(EXTRA[v])
    return lines


def run(console, script, cwd, ref, log):
    env = dict(os.environ, LC_ALL="C", SLEIGHHOME=ref)
    env.pop("BK_PRINTLOG", None)
    if log:
        env["BK_PRINTLOG"] = log
    try:
        p = subprocess.run([console, "-i", script], cwd=cwd, input=b"\n", capture_output=True,
                           env=env, timeout=600)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return "timeout", b""


def job(item, args, ref):
    corpus, name, cwd, load, cmds = item
    rows = []
    for v in VARIANTS:
        sdir = Path(args.out) / "scripts" / v
        sdir.mkdir(parents=True, exist_ok=True)
        script = sdir / f"{corpus}.{name}.script"
        script.write_text("\n".join(variant(load, cmds, v)) + "\n")
        ldir = Path(args.out) / "logs" / v
        ldir.mkdir(parents=True, exist_ok=True)
        log = str(ldir / f"{corpus}.{name}")
        rc0, out0 = run(str(Path(ref) / "bin/decomp"), str(script), cwd, ref, None)
        rc1, out1 = run(args.instr, str(script), cwd, ref, log)
        (ldir / f"{corpus}.{name}.out").write_bytes(out1)
        rows.append((v, "log", corpus, name, rc0, rc1, out0 == out1 and rc0 == rc1, len(out0)))
        if v == "orig":
            rc2, out2 = run(args.instr, str(script), cwd, ref, None)
            rows.append((v, "nolog", corpus, name, rc0, rc2, out0 == out2 and rc0 == rc2, len(out0)))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instr", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--only")
    args = ap.parse_args()
    ghidra = os.environ["BASILISK_GHIDRA_DIR"]
    ref = os.environ["BASILISK_REFERENCE_DIR"]
    items = data_tests(ghidra) + research()
    if args.only:
        items = [i for i in items if i[1] == args.only]
    rows = []
    with cf.ThreadPoolExecutor(args.jobs) as ex:
        for r in ex.map(lambda i: job(i, args, ref), items):
            rows.extend(r)
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3]))
    bad = [r for r in rows if not r[6]]
    with open(Path(args.out) / "identity.txt", "w") as f:
        f.write("variant\tlogging\tcorpus\tscript\tref exit\tinstr exit\tidentical\tbytes\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
        for v in VARIANTS:
            for lg in ("log", "nolog"):
                sel = [r for r in rows if r[0] == v and r[1] == lg]
                if sel:
                    f.write(f"# {v} {lg}: {len(sel)} runs, {sum(1 for r in sel if r[6])} identical, "
                            f"{sum(r[7] for r in sel)} bytes\n")
    print(f"scripts {len(items)}, runs {len(rows)}, not identical {len(bad)}")
    for r in bad:
        print("DIFF", *r)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
