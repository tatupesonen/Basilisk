#!/usr/bin/env python3
"""Build the cases in `src/` and run each through Ghidra's reference `decomp`.

    tools/run.py [case ...]        (default: every src/*.c with a `//! funcs:` line)

For every case and target this compiles `src/<case>.c` with `src/stubs.c` into
a small static ELF, converts it with `elf2frag.py` into `frag/<case>.<target>.xml`
(the fragment fed to `decomp`), writes the console script beside it as
`frag/<case>.<target>.script`, and stores what the console printed in
`out/<case>.<target>.c`.

Directives in a case file (lines starting with `//!`):

    //! targets: x64-clang-O2 a64-gcc-O2     arch-compiler-optlevel, see TARGETS
    //! funcs: f g                           functions to decompile
    //! cflags: -fstack-protector-all        extra compiler flags
    //! pre: parse line struct foo {...};    console command before `load function`
    //! post: map addr s0x.. int4 x          console command after `load function`
    //! libc: no                             do not give the console libc prototypes
    //! globals: no                          do not map data symbols by name
    //! tailcalls: no                        do not mark jumps to function entries as calls
    //! vectorize: yes                       leave the compiler's auto-vectoriser on

Environment: `BK_REFERENCE` (default: `reference/` beside the basilisk
checkout, where `scripts/build-reference.sh` puts the tools), `BK_CLANG`, `BK_LLD`, `BK_GCC_IMAGE`.
"""

import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
SRC, FRAG, OUT, BUILD = HERE / "src", HERE / "frag", HERE / "out", HERE / "build"
REFERENCE = pathlib.Path(os.environ.get("BK_REFERENCE", HERE.parents[3] / "reference"))
if not (REFERENCE / "bin" / "decomp").exists():
    # A worktree under basilisk-wt/ sits one level deeper than the main checkout.
    REFERENCE = HERE.parents[4] / "reference"
CLANG = os.environ.get("BK_CLANG", "/opt/homebrew/opt/llvm@20/bin/clang")
LLD = os.environ.get("BK_LLD", "/opt/homebrew/opt/lld@20/bin/ld.lld")
GCC_IMAGE = os.environ.get("BK_GCC_IMAGE", "gcc:14")
OBJDUMP = os.environ.get("BK_OBJDUMP", "/opt/homebrew/opt/llvm@20/bin/llvm-objdump")

# arch -> (clang triple, Ghidra language id, pointer size in bytes)
ARCHES = {
    "x64": ("x86_64-unknown-linux-gnu", "x86:LE:64:default:gcc", 8),
    "x86": ("i686-unknown-linux-gnu", "x86:LE:32:default:gcc", 4),
    "a64": ("aarch64-unknown-linux-gnu", "AARCH64:LE:64:v8A:default", 8),
    "arm": ("armv7a-unknown-linux-gnueabi", "ARM:LE:32:v7:default", 4),
}
COMMON = ["-fno-pic", "-fno-pie", "-fno-asynchronous-unwind-tables", "-fno-stack-protector", "-w"]
# Auto-vectorisation is switched off unless a case asks for it (`//! vectorize: yes`),
# so that each case shows one weakness and not SIMD noise on top of it.
NOVEC = ["-fno-tree-vectorize", "-fno-tree-slp-vectorize"]


def directives(path):
    found = {}
    for line in path.read_text().splitlines():
        match = re.match(r"//!\s*(\w+):\s*(.*)", line)
        if match:
            found.setdefault(match.group(1), []).append(match.group(2).strip())
    return found


def run(cmd, **kwargs):
    done = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if done.returncode != 0:
        raise SystemExit("command failed: %s\n%s%s" % (" ".join(map(str, cmd)), done.stdout, done.stderr))
    return done.stdout


def build(case, target, cflags, entry):
    arch, compiler, opt = target.split("-")
    triple, _lang, _ptr = ARCHES[arch]
    BUILD.mkdir(exist_ok=True)
    elf = BUILD / ("%s.%s.elf" % (case, target))
    flags = COMMON + ["-" + opt] + cflags
    if compiler == "clang":
        objs = []
        for name, extra in ((case, []), ("stubs", ["-fno-builtin", "-O1"])):
            obj = BUILD / ("%s.%s.o" % (name, target))
            run([CLANG, "--target=" + triple, "-c", *flags, *extra, "-I", SRC, SRC / (name + ".c"), "-o", obj])
            objs.append(obj)
        run([LLD, "-static", "-e", entry, "--no-rosegment", "-o", elf, *objs])
    elif compiler == "gcc":
        # GCC from a container; its native target must be the case's arch.
        inner = (
            "gcc -c {f} -I/w/src /w/src/{c}.c -o /w/build/{c}.{t}.o && "
            "gcc -c {f} -fno-builtin -O1 -I/w/src /w/src/stubs.c -o /w/build/stubs.{t}.o && "
            "ld -static -e {e} -o /w/build/{c}.{t}.elf /w/build/{c}.{t}.o /w/build/stubs.{t}.o"
        ).format(f=" ".join(flags), c=case, t=target, e=entry)
        run(["docker", "run", "--rm", "-v", "%s:/w" % HERE, GCC_IMAGE, "sh", "-c", inner])
    else:
        raise SystemExit("unknown compiler in target " + target)
    return elf


def tail_calls(elf):
    """Addresses of unconditional jumps to the entry of another function.

    Full Ghidra marks these as call-then-return before the decompiler runs
    (`SharedReturnAnalyzer`, a flow override); the bare console would follow
    the jump and print the callee's body as part of the caller.
    """
    found = []
    for line in run([OBJDUMP, "-d", "--no-show-raw-insn", elf]).splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+(?:jmp|b)\s+0x[0-9a-f]+ <([\w.]+)>\s*$", line)
        if match:
            found.append(match.group(1))
    return found


def undefined_type(size):
    return {1: "xunknown1", 2: "xunknown2", 4: "xunknown4", 8: "xunknown8"}.get(size)


def one(case, target, info):
    arch = target.split("-")[0]
    _triple, lang, ptr = ARCHES[arch]
    funcs = " ".join(info["funcs"]).split()
    cflags = " ".join(info.get("cflags", [])).split()
    if info.get("vectorize", ["no"])[0] != "yes":
        cflags = NOVEC + cflags
    elf = build(case, target, cflags, funcs[0])
    frag = FRAG / ("%s.%s.xml" % (case, target))
    syms = BUILD / ("%s.%s.syms" % (case, target))
    run([sys.executable, HERE / "tools" / "elf2frag.py", elf, lang, frag, syms])

    script = ["load file " + str(frag), "option readonly on"]
    if info.get("libc", ["yes"])[0] != "no":
        script.append("parse line typedef uint%d size_t;" % ptr)
        script.append("parse line typedef int%d ssize_t;" % ptr)
        script.extend(line for line in (SRC / "libc.proto").read_text().splitlines() if line.strip())
    script.extend(info.get("pre", []))
    explicit = " ".join(info.get("pre", []))
    if info.get("globals", ["yes"])[0] != "no":
        for line in syms.read_text().splitlines():
            addr, size, name = line.split()
            if name in explicit or name.startswith("__") or int(size) == 0:
                continue
            kind = undefined_type(int(size))
            if kind:
                script.append("map addr r%s %s %s" % (addr, kind, name))
            else:
                # A symbol with a size but no type: an array of unknown bytes.
                script.append("map addr r%s xunknown1 %s[%s]" % (addr, name, size))
    overrides = []
    if info.get("tailcalls", ["yes"])[0] != "no":
        overrides = ["override flow r0x%s callreturn" % addr for addr in tail_calls(elf)]
    for func in funcs:
        script.append("load function " + func)
        # Flow overrides belong to the loaded function; one for an address
        # outside it has no effect.
        script.extend(overrides)
        script.extend(info.get("post", []))
        if overrides:
            # `load function` has already followed flow, and an override is
            # only consulted while flow is followed. The first `decompile`
            # uses the stale flow; the second clears the analysis (overrides
            # are kept) and follows flow again with the overrides in force.
            script.append("decompile")
        script.extend(["decompile", "print C"])
    script.append("quit")
    script_path = FRAG / ("%s.%s.script" % (case, target))
    shown = [line.replace(str(HERE) + "/", "") for line in script]
    script_path.write_text("\n".join(shown) + "\n")

    real = BUILD / "run.script"
    real.write_text("\n".join(script) + "\n")
    env = dict(os.environ, SLEIGHHOME=str(REFERENCE))
    with open(real) as stdin:
        done = subprocess.run(
            [REFERENCE / "bin" / "decomp"], stdin=stdin, capture_output=True, text=True, env=env, timeout=120
        )
    text = done.stdout.replace(str(HERE) + "/", "")
    # Keep the transcript from the first function load on; the prototype
    # preamble is in the .script file.
    marker = text.find("[decomp]> load function")
    kept = text[marker:] if marker >= 0 else text
    kept = "\n".join(l for l in kept.splitlines() if not l.startswith("[decomp]> quit"))
    header = "// %s, %s (%s)\n// Ghidra reference decomp output; inputs: frag/%s\n\n" % (
        case,
        target,
        lang,
        frag.name,
    )
    (OUT / ("%s.%s.c" % (case, target))).write_text(header + kept.strip() + "\n" + done.stderr)
    return kept


def main(argv):
    FRAG.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)
    wanted = argv[1:]
    for path in sorted(SRC.glob("*.c")):
        info = directives(path)
        if "funcs" not in info or (wanted and path.stem not in wanted):
            continue
        for target in " ".join(info.get("targets", ["x64-clang-O2"])).split():
            text = one(path.stem, target, info)
            print("== %s %s: %d lines" % (path.stem, target, len(text.splitlines())))
            if wanted:
                print(text)


if __name__ == "__main__":
    main(sys.argv)
