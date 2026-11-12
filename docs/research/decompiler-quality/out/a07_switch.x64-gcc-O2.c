// a07_switch, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a07_switch.x64-gcc-O2.xml

[decomp]> load function dense
Function dense: 0x00401000
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dense
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dense
Decompilation complete
[decomp]> print C

xunknown8 dense(xunknown4 param_1)

{
  xunknown8 xVar1;
  
  switch(param_1) {
  case 0:
    xVar1 = ext_i(10);
    return xVar1;
  case 1:
    xVar1 = ext_i(0x16);
    return xVar1;
  case 2:
    xVar1 = ext_i(0x23);
    return xVar1;
  case 3:
    xVar1 = ext_i(0x29);
    return xVar1;
  case 4:
    xVar1 = ext_i(0x39);
    return xVar1;
  case 5:
    xVar1 = ext_i(0x3f);
    return xVar1;
  default:
    return 0xffffffff;
  }
}
[decomp]> load function sparse
Function sparse: 0x00401070
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
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
  xunknown8 xVar1;
  
  if (param_1 == 100) {
    xVar1 = ext_i(0x23);
    return xVar1;
  }
  if (param_1 < 0x65) {
    if (param_1 == 1) {
      xVar1 = ext_i(10);
      return xVar1;
    }
    if (param_1 == 10) {
      xVar1 = ext_i(0x16);
      return xVar1;
    }
  }
  else {
    if (param_1 == 1000) {
      xVar1 = ext_i(0x29);
      return xVar1;
    }
    if (param_1 == 10000) {
      xVar1 = ext_i(0x39);
      return xVar1;
    }
  }
  return 0xffffffff;
}
[decomp]> load function bittest
Function bittest: 0x004010f0
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bittest
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bittest
Decompilation complete
[decomp]> print C

bool bittest(uint4 param_1)

{
  bool bVar1;
  
  bVar1 = false;
  if (param_1 < 0x3c) {
    bVar1 = (0x800100100002600U >> ((uint8)param_1 & 0x3f) & 1) != 0;
  }
  return bVar1;
}
[decomp]> load function lookup
Function lookup: 0x00401110
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
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
  
  xVar1 = 0x402068;
  if (param_1 < 5) {
    xVar1 = *(xunknown8 *)((uint8)param_1 * 8 + 0x402040);
  }
  return xVar1;
}
