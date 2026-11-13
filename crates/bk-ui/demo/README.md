# Demo program

`licd.bkdemo` is the program the interface shows until the real program
model lands. It is generated, not hand-written:

- `licd.c` — a small licence daemon (config parsing, CRC-32, RC4, base64,
  sockets, a command loop), written in the style of Ghidra's decompiler
  output (Ghidra's type names, `param_1`, `local_28`, `iVar1`), so its text
  can stand in for decompiled C.
- `generate.py` — compiles it with Apple clang for `x86_64-apple-macos12`
  (`-O1 -g -fno-inline -fno-stack-protector -fno-omit-frame-pointer`),
  disassembles `__text` and `__stubs` with Ghidra's own decoder (the
  reference `pcodedump`, language `x86:LE:64:default`, so mnemonics and
  operands are spelled exactly as Ghidra's listing spells them), reads
  symbols, imports and sections with `nm`/`otool`, and takes each
  instruction's source line from the DWARF line table (`dsymutil`,
  `dwarfdump --debug-line`). That line table is what links decompiler lines
  to listing rows.

Regenerate (macOS with the Xcode command-line tools and `../reference`
built):

    python3 crates/bk-ui/demo/generate.py /path/to/reference

Provenance: all code in `licd.c` was written for basilisk (GPL-3.0-or-later);
the generated file contains only its compiled form. A few comments are
added by the generator so each comment kind appears in the listing.
