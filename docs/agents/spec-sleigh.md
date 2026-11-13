# Track `spec-sleigh` — status (research; documents only)

Branch `spec-sleigh`, worktree `/Users/tatu/slop/basilisk-wt/spec-sleigh`.
Product: `docs/inventory/01-sleigh.md` and the SLEIGH feature specs. No
code. This file is kept current so another agent can continue from the
files alone.

## Done
- `docs/inventory/01-sleigh.md` sections 0–8a: model, `.sla` format,
  loading, context, decoding, disassembly text, p-code generation,
  undefined behaviour in the C++ runtime, measured baselines.

## In progress / next (in this order)
1. `docs/features/sla.md` — crate `bk-sla` (model, reader, writer).
2. `docs/features/sleigh-decode.md` — crate `bk-sleigh`, part 1.
3. `docs/features/sleigh-pcode.md` — crate `bk-sleigh`, part 2.
4. `docs/features/sleigh-language.md` — Java-side language services.
5. Inventory sections 9–12 (compiler front half — still to be read in
   `CPP/slgh_compile.cc` 1930–4091, `pcodecompile.cc`, `slghparse.y`;
   compiler back half — notes exist, see below; Java differences; census).
6. `docs/features/sleigh-compiler-front.md`, `sleigh-compiler-back.md`,
   `sleigh-snippet.md`.
7. Final report (end of this file).

## Material outside the repository (session scratchpad; may vanish)
- Notes on the compiler back half (patterns, operand offsets, decision
  trees, consistency checker), with `file:line` citations: to be folded
  into inventory section 10.

## Measurements and how they were made
- **Element census of all 150 reference `.sla`**: a Python script inflates
  each file (`zlib.decompress(data[4:])`) and walks the packed stream
  (header byte: `0x40` element start, `0x80` end, `0xc0` attribute; 5 id
  bits, extension byte when `0x20`; attribute type byte: high nibble type,
  low nibble length; type 7 = string with a length integer), counting
  elements, attributes with their types, parent/child pairs and maxima.
  Results are in inventory sections 1 and 12.
- **Reference speed per phase**: a C++ program linked against
  `../reference/src/cpp/libsla.a` and `../reference/src/zlib/libz.a`
  (`g++ -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -I../reference/src/cpp`),
  loading `x86-64.sla`, setting `longMode=1 bit64=1 addrsize=2 opsize=1`
  over the code space, and sweeping 539 kB of x86-64 code (text sections of
  `ruleaction.cc`, `coreaction.cc`, `fspec.cc`, `type.cc` compiled
  `-O2 -arch x86_64`) calling `instructionLength`, `printAssembly`,
  `oneInstruction` in four combinations; best of 5. Results: inventory
  section 8a. Taken at load average > 40; re-measure on an idle machine.
- `REF/bin/sleigh -y in.slaspec out` writes XML to `out.sla` (the tool
  appends `.sla`); a plain compile of `toy_be.slaspec` is byte-identical to
  the reference directory's `toy_be.sla`.
- `REF/bin/pcodedump REF <lang> 0x1000 --hex …` on x86-64, ARM and PowerPC
  samples (inventory sections 6–8).
