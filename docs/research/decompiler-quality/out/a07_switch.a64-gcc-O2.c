// a07_switch, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a07_switch.a64-gcc-O2.xml

[decomp]> load function dense
Function dense: 0x00400120
[decomp]> override flow r0x400144 callreturn
Successfully added flow override
[decomp]> override flow r0x40015c callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400174 callreturn
Successfully added flow override
[decomp]> override flow r0x40017c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> override flow r0x400268 callreturn
Successfully added flow override
[decomp]> override flow r0x40028c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dense
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dense
Decompilation complete
[decomp]> print C

xunknown8 dense(int4 param_1)

{
  xunknown8 xVar1;
  
  if (param_1 == 3) {
    xVar1 = ext_i(0x29);
    return xVar1;
  }
  if (param_1 < 4) {
    if (param_1 == 1) {
      xVar1 = ext_i(0x16);
      return xVar1;
    }
    if (param_1 == 2) {
      xVar1 = ext_i(0x23);
      return xVar1;
    }
    if (param_1 == 0) {
      xVar1 = ext_i(10);
      return xVar1;
    }
  }
  else {
    if (param_1 == 4) {
      xVar1 = ext_i(0x39);
      return xVar1;
    }
    if (param_1 == 5) {
      xVar1 = ext_i(0x3f);
      return xVar1;
    }
  }
  return 0xffffffff;
}
[decomp]> load function sparse
Function sparse: 0x00400188
[decomp]> override flow r0x400144 callreturn
Successfully added flow override
[decomp]> override flow r0x40015c callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400174 callreturn
Successfully added flow override
[decomp]> override flow r0x40017c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> override flow r0x400268 callreturn
Successfully added flow override
[decomp]> override flow r0x40028c callreturn
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
Function bittest: 0x004001e8
[decomp]> override flow r0x400144 callreturn
Successfully added flow override
[decomp]> override flow r0x40015c callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400174 callreturn
Successfully added flow override
[decomp]> override flow r0x40017c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> override flow r0x400268 callreturn
Successfully added flow override
[decomp]> override flow r0x40028c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bittest
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bittest
Decompilation complete
[decomp]> print C

uint4 bittest(uint8 param_1)

{
  uint4 uVar1;
  
  uVar1 = (uint4)(0x800100100002600 >> (param_1 & 0x3f)) & 1;
  if (0x3b < (uint4)param_1) {
    uVar1 = 0;
  }
  return uVar1;
}
[decomp]> load function lookup
Function lookup: 0x00400208
[decomp]> override flow r0x400144 callreturn
Successfully added flow override
[decomp]> override flow r0x40015c callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400174 callreturn
Successfully added flow override
[decomp]> override flow r0x40017c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> override flow r0x400268 callreturn
Successfully added flow override
[decomp]> override flow r0x40028c callreturn
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
  if (param_1 < 5) {
    return *(xunknown8 *)((uint8)param_1 * 8 + 0x4002e0);
  }
  return 0x4002a8;
}
