#!/usr/bin/env python3
"""Regenerates licd.bkdemo, the demo program shown by the basilisk interface.

Compiles licd.c for x86-64 macOS with clang, disassembles its code sections
with Ghidra's own decoder (the reference `pcodedump` tool, so mnemonics and
operands are spelled exactly as Ghidra spells them), and takes the mapping
from decompiled-C lines to instructions from the program's DWARF line table.

Needs macOS with the Xcode command-line tools (clang, dsymutil, dwarfdump,
otool, nm) and the reference tools built under ../reference (see
docs/features/reference-tools.md). Usage, from this directory:

    python3 generate.py [path/to/reference]

The output format is described at the top of the generated file.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "licd.c")
OUT = os.path.join(HERE, "licd.bkdemo")
LANG = "x86:LE:64:default"

# Types of the global variables (the generator does not read DWARF types).
GLOBAL_TYPES = {
    "g_config": "config_t",
    "crc_table": "uint[256]",
    "crc_table_ready": "int",
    "g_log_level": "int",
    "g_running": "int",
    "g_last_contact": "long",
    "g_rc4": "rc4_state_t",
    "s_banner_enc": "byte[24]",
    "s_activate_enc": "byte[16]",
    "s_heartbeat_enc": "byte[16]",
    "b64_alphabet": "char[65]",
    "level_names": "char *[4]",
}

# Comments a user might have added, so the listing shows each kind.
EOL_COMMENTS = {
    ("validate_key", 0): "key must be XXXX-XXXX-XXXX-XXXX-CCCC",
    ("crc32", 3): "reflected CRC-32 (0xedb88320)",
    ("rc4_init", 0): "KSA",
    ("check_debugger", 2): "parent is launchd?",
}
PLATE_COMMENTS = {
    "main": "Entry point. Reads /etc/licd.conf, checks the licence key,\nactivates against the server and then sends heartbeats.",
    "validate_key": "Licence key check: 24 characters in groups of five\nseparated by '-', the last group the CRC-32 of the first 19.",
    "rc4_init": "RC4 key schedule over the licence key.",
}
PRE_COMMENTS = {
    ("activate", 6): "build and send the ACTIVATE request",
}


def run(*args, stdin=None):
    return subprocess.run(args, check=True, capture_output=True, text=stdin is None or isinstance(stdin, str), input=stdin).stdout


def sections(binary):
    out = run("otool", "-l", binary)
    secs = []
    cur = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("sectname", "segname", "addr", "size", "offset"):
            cur[parts[0]] = parts[1]
            if parts[0] == "offset" and "sectname" in cur:
                secs.append((cur["segname"], cur["sectname"], int(cur["addr"], 16), int(cur["size"], 16), int(cur["offset"])))
                cur = {}
    return secs


def symbols(binary):
    syms = {}
    for line in run("nm", "-n", binary).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TtDdSs" and parts[2].startswith("_") and not parts[2].startswith("__"):
            syms[int(parts[0], 16)] = (parts[1], parts[2][1:])
    return syms


def indirect(binary):
    table = {}
    section = None
    for line in run("otool", "-Iv", binary).splitlines():
        m = re.match(r"Indirect symbols for \((\S+),(\S+)\)", line)
        if m:
            section = m.group(2)
            continue
        parts = line.split()
        if len(parts) == 3 and parts[0].startswith("0x"):
            name = parts[2].lstrip("_") if parts[2].startswith("_") else parts[2]
            table[int(parts[0], 16)] = (section, name)
    return table


def line_table(dsym):
    rows = []
    for line in run("dwarfdump", "--debug-line", dsym).splitlines():
        m = re.match(r"0x([0-9a-f]{16})\s+(\d+)\s+\d+\s+(\d+)", line)
        if m and m.group(3) == "1":
            rows.append((int(m.group(1), 16), int(m.group(2))))
    return rows


def disassemble(reference, data, base):
    out = run(os.path.join(reference, "bin", "pcodedump"), reference, LANG, hex(base), "--hex", data.hex())
    insns = []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0] == "I":
            ops = parts[6] if len(parts) > 6 else ""
            insns.append((int(parts[1], 16), parts[4], parts[5], ops))
    return insns


def functions_in_source():
    """Each function's (name, first line, last line) in licd.c, 1-based."""
    lines = open(SRC).read().split("\n")
    funcs = []
    i = 0
    while i < len(lines):
        m = re.match(r"^[A-Za-z_][\w \*]*?\b(\w+)\(.*\)\s*$", lines[i])
        if m and i + 1 < len(lines) and lines[i + 1] == "{":
            j = i + 1
            while lines[j] != "}":
                j += 1
            funcs.append((m.group(1), i + 1, j + 1))
            i = j
        i += 1
    return funcs, lines


def esc(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def main():
    reference = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "../../../../../reference")
    reference = os.path.abspath(reference)
    tmp = tempfile.mkdtemp(prefix="bk-ui-demo-")
    obj = os.path.join(tmp, "licd.o")
    binary = os.path.join(tmp, "licd")
    flags = ["-target", "x86_64-apple-macos12", "-O1", "-g", "-fno-inline", "-fno-stack-protector", "-fno-omit-frame-pointer", "-w"]
    run("clang", *flags, "-c", "-o", obj, SRC)
    run("clang", "-target", "x86_64-apple-macos12", "-o", binary, obj)
    run("dsymutil", binary)
    raw = open(binary, "rb").read()
    secs = sections(binary)
    syms = symbols(binary)
    ind = indirect(binary)
    lines = line_table(binary + ".dSYM")
    src_funcs, src_lines = functions_in_source()

    out = []
    out.append("# basilisk demo program, generated by generate.py from licd.c; do not edit.")
    out.append("# Records are tab-separated; text fields escape \\t, \\n and \\\\.")
    out.append("# PROGRAM name language format image-base")
    out.append("# SECTION segment section start size flags")
    out.append("# FUNC start end name   (end exclusive)")
    out.append("# IMPORT stub-address name pointer-address")
    out.append("# DATA address size name type bytes-hex")
    out.append("# STRING address text")
    out.append("# INSN address bytes-hex mnemonic operands source-line")
    out.append("# SRC function line-number text   (decompiled C, one record per line)")
    out.append("# EOL|PRE address text; PLATE function-start text")
    out.append("PROGRAM\tlicd\t%s\tMach-O x86-64\t0x100000000" % LANG)
    flags_of = {"__text": "r-x", "__stubs": "r-x", "__stub_helper": "r-x", "__const": "r--", "__cstring": "r--",
                "__unwind_info": "r--", "__got": "rw-", "__la_symbol_ptr": "rw-", "__data": "rw-", "__common": "rw-"}
    for seg, sect, addr, size, off in secs:
        out.append("SECTION\t%s\t%s\t%#x\t%#x\t%s" % (seg, sect, addr, size, flags_of.get(sect, "r--")))

    text = next(s for s in secs if s[1] == "__text")
    text_end = text[2] + text[3]
    func_addrs = sorted(a for a, (k, _) in syms.items() if k in "Tt" and text[2] <= a < text_end)
    func_name = {a: syms[a][1] for a in func_addrs}
    for i, a in enumerate(func_addrs):
        end = func_addrs[i + 1] if i + 1 < len(func_addrs) else text_end
        out.append("FUNC\t%#x\t%#x\t%s" % (a, end, func_name[a]))

    la = {name: a for a, (sec, name) in ind.items() if sec == "__la_symbol_ptr"}
    for a, (sec, name) in sorted(ind.items()):
        if sec == "__stubs":
            out.append("IMPORT\t%#x\t%s\t%#x" % (a, name, la.get(name, 0)))
    for a, (sec, name) in sorted(ind.items()):
        if sec == "__got":
            out.append("DATA\t%#x\t8\tPTR_%s\tpointer\t%s" % (a, name, raw[a - 0x100000000: a - 0x100000000 + 8].hex()))

    # Globals in __data, __common and __const.
    data_secs = [s for s in secs if s[1] in ("__data", "__common", "__const")]
    for seg, sect, addr, size, off in data_secs:
        here = sorted(a for a in syms if addr <= a < addr + size)
        for i, a in enumerate(here):
            name = syms[a][1]
            end = here[i + 1] if i + 1 < len(here) else addr + size
            typ = GLOBAL_TYPES.get(name, "undefined")
            if sect == "__common":
                sz = {"g_config": 0x10c, "crc_table": 1024, "crc_table_ready": 4, "g_last_contact": 8, "g_rc4": 258}.get(name, end - a)
                b = "00" * min(sz, 16)
            else:
                sz = min(end - a, {"int": 4, "long": 8}.get(typ, end - a))
                b = raw[off + (a - addr): off + (a - addr) + sz].hex()
            out.append("DATA\t%#x\t%d\t%s\t%s\t%s" % (a, sz, name, typ, b))

    cstr = next(s for s in secs if s[1] == "__cstring")
    blob = raw[cstr[4]: cstr[4] + cstr[3]]
    pos = 0
    while pos < len(blob):
        end = blob.index(b"\0", pos)
        out.append("STRING\t%#x\t%s" % (cstr[2] + pos, esc(blob[pos:end].decode())))
        pos = end + 1

    def line_of(addr):
        best = 0
        for a, l in lines:
            if a <= addr:
                best = l
            else:
                break
        return best

    lines.sort()
    for seg, sect, addr, size, off in secs:
        if sect not in ("__text", "__stubs"):
            continue
        for a, b, mnem, ops in disassemble(reference, raw[off: off + size], addr):
            out.append("INSN\t%#x\t%s\t%s\t%s\t%d" % (a, b, mnem, ops, line_of(a) if sect == "__text" else 0))

    by_name = {n: (s, e) for n, s, e in src_funcs}
    for a in func_addrs:
        name = func_name[a]
        if name not in by_name:
            continue
        s, e = by_name[name]
        for n in range(s, e + 1):
            out.append("SRC\t%s\t%d\t%s" % (name, n, esc(src_lines[n - 1])))

    insn_addrs = {}
    for rec in out:
        if rec.startswith("INSN\t"):
            insn_addrs.setdefault("all", []).append(int(rec.split("\t")[1], 16))
    all_insns = sorted(insn_addrs["all"])
    by_addr = {n: a for a, n in func_name.items()}
    for (fn, k), text_ in EOL_COMMENTS.items():
        start = by_addr[fn]
        here = [x for x in all_insns if x >= start]
        out.append("EOL\t%#x\t%s" % (here[k], esc(text_)))
    for (fn, k), text_ in PRE_COMMENTS.items():
        start = by_addr[fn]
        here = [x for x in all_insns if x >= start]
        out.append("PRE\t%#x\t%s" % (here[k], esc(text_)))
    for fn, text_ in PLATE_COMMENTS.items():
        out.append("PLATE\t%#x\t%s" % (by_addr[fn], esc(text_)))

    with open(OUT, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote %s (%d records)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
