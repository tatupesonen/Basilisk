// a07_switch, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a07_switch.x64-clang-O2.xml

[decomp]> load function dense
Function dense: 0x00200180
[decomp]> override flow r0x20018e callreturn
Successfully added flow override
[decomp]> override flow r0x2001bf callreturn
Successfully added flow override
[decomp]> override flow r0x2001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e2 callreturn
Successfully added flow override
[decomp]> override flow r0x2001ee callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dense
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dense
Decompilation complete
[decomp]> print C

xunknown8 dense(uint4 param_1)

{
  xunknown8 xVar1;
  
  if (param_1 < 6) {
    xVar1 = ext_i(*(xunknown4 *)((uint8)param_1 * 4 + 0x200140));
    return xVar1;
  }
  return 0xffffffff;
}
[decomp]> load function sparse
Function sparse: 0x002001a0
[decomp]> override flow r0x20018e callreturn
Successfully added flow override
[decomp]> override flow r0x2001bf callreturn
Successfully added flow override
[decomp]> override flow r0x2001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e2 callreturn
Successfully added flow override
[decomp]> override flow r0x2001ee callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sparse
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sparse
Decompilation complete
[decomp]> print C

xunknown8 sparse(int4 param_1)

{
  xunknown4 xVar1;
  xunknown8 xVar2;
  
  if (param_1 < 100) {
    xVar1 = 10;
    if (param_1 == 1) goto code_r0x002001ec;
    if (param_1 == 10) {
      xVar2 = ext_i(0x16);
      return xVar2;
    }
  }
  else {
    if (param_1 == 100) {
      xVar2 = ext_i(0x23);
      return xVar2;
    }
    if (param_1 == 1000) {
      xVar1 = 0x29;
code_r0x002001ec:
      xVar2 = ext_i(xVar1);
      return xVar2;
    }
    if (param_1 == 10000) {
      xVar2 = ext_i(0x39);
      return xVar2;
    }
  }
  return 0xffffffff;
}
[decomp]> load function bittest
Function bittest: 0x00200200
[decomp]> override flow r0x20018e callreturn
Successfully added flow override
[decomp]> override flow r0x2001bf callreturn
Successfully added flow override
[decomp]> override flow r0x2001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e2 callreturn
Successfully added flow override
[decomp]> override flow r0x2001ee callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bittest
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bittest
Decompilation complete
[decomp]> print C

xunknown8 bittest(uint4 param_1)

{
  if ((param_1 < 0x3c) && ((0x800100100002600U >> ((uint8)param_1 & 0x3f) & 1) != 0)) {
    return 1;
  }
  return 0;
}
[decomp]> load function lookup
Function lookup: 0x00200220
[decomp]> override flow r0x20018e callreturn
Successfully added flow override
[decomp]> override flow r0x2001bf callreturn
Successfully added flow override
[decomp]> override flow r0x2001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e2 callreturn
Successfully added flow override
[decomp]> override flow r0x2001ee callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lookup
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lookup
Decompilation complete
[decomp]> print C

xunknown8 lookup(uint4 param_1)

{
  xunknown8 xVar1;
  
  xVar1 = 0x200120;
  if (param_1 < 5) {
    xVar1 = *(xunknown8 *)((uint8)param_1 * 8 + 0x200158);
  }
  return xVar1;
}
