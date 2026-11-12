#!/usr/bin/env python3
"""Turn a small statically linked ELF executable into the `<binaryimage>` XML
that Ghidra's `decomp` console loads (`load file <xml>`), the same form
Ghidra's decompiler data tests use.

    elf2frag.py <elf> <language-id> <out.xml> [<out.symbols>]

Every allocated PROGBITS section becomes a `<bytechunk>` (read-only unless the
section is writable); every FUNC symbol becomes a `<symbol>`. OBJECT symbols
are written to the optional symbols file as `address size name` lines, so the
runner can turn them into `map address` commands: the console makes a function
of every `<symbol>`, so data symbols cannot go in the image.

No dependencies beyond the Python standard library.
"""

import struct
import sys

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHF_WRITE = 1
SHF_ALLOC = 2
STT_OBJECT = 1
STT_FUNC = 2


def parse(data):
    if data[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        (shoff,) = struct.unpack_from(end + "Q", data, 0x28)
        shentsize, shnum, _shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
    else:
        (shoff,) = struct.unpack_from(end + "I", data, 0x20)
        shentsize, shnum, _shstrndx = struct.unpack_from(end + "HHH", data, 0x2E)
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if is64:
            _name, typ, flags, addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                end + "IIQQQQIIQQ", data, off
            )
        else:
            _name, typ, flags, addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                end + "IIIIIIIIII", data, off
            )
        sections.append((typ, flags, addr, offset, size, link, entsize))
    chunks = []
    for typ, flags, addr, offset, size, _link, _entsize in sections:
        if typ == SHT_PROGBITS and flags & SHF_ALLOC and size:
            chunks.append((addr, data[offset : offset + size], not flags & SHF_WRITE))
    funcs, objects = {}, []
    for typ, _flags, _addr, offset, size, link, entsize in sections:
        if typ != SHT_SYMTAB:
            continue
        strtab = sections[link]
        for i in range(size // entsize):
            off = offset + i * entsize
            if is64:
                name, info, _other, _shndx, value, symsize = struct.unpack_from(end + "IBBHQQ", data, off)
            else:
                name, value, symsize, info, _other, _shndx = struct.unpack_from(end + "IIIBBH", data, off)
            start = strtab[3] + name
            text = data[start : data.index(b"\0", start)].decode()
            kind = info & 0xF
            if not text or text.startswith("$"):
                continue
            if kind == STT_FUNC:
                funcs.setdefault(value & ~1 if not is64 else value, text)
            elif kind == STT_OBJECT:
                objects.append((value, symsize, text))
    return chunks, funcs, objects


def main(argv):
    if len(argv) not in (4, 5):
        raise SystemExit(__doc__)
    with open(argv[1], "rb") as handle:
        chunks, funcs, objects = parse(handle.read())
    lines = ['<binaryimage arch="%s">' % argv[2]]
    for addr, blob, readonly in sorted(chunks):
        attr = ' readonly="true"' if readonly else ""
        lines.append('<bytechunk space="ram" offset="0x%x"%s>' % (addr, attr))
        text = blob.hex()
        lines.extend(text[i : i + 64] for i in range(0, len(text), 64))
        lines.append("</bytechunk>")
    for addr, name in sorted(funcs.items()):
        lines.append('<symbol space="ram" offset="0x%x" name="%s"/>' % (addr, name))
    lines.append("</binaryimage>")
    with open(argv[3], "w") as handle:
        handle.write("\n".join(lines) + "\n")
    if len(argv) == 5:
        with open(argv[4], "w") as handle:
            for addr, size, name in sorted(objects):
                handle.write("0x%x %d %s\n" % (addr, size, name))


if __name__ == "__main__":
    main(sys.argv)
