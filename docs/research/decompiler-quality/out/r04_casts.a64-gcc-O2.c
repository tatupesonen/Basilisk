// r04_casts, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r04_casts.a64-gcc-O2.xml

[decomp]> load function widen
Function widen: 0x00400120
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling widen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling widen
Decompilation complete
[decomp]> print C

int8 widen(int4 param_1,int2 param_2,char param_3,uint1 param_4)

{
  return ((int8)param_3 + (int8)param_1 * (int8)(int4)param_2) - (uint8)param_4;
}
[decomp]> load function index8
Function index8: 0x00400140
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling index8
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling index8
Decompilation complete
[decomp]> print C

int4 index8(int8 param_1,uint8 param_2,uint8 param_3)

{
  return *(int4 *)(param_1 + (param_2 & 0xff) * 4) +
         *(int4 *)(param_1 + (-(param_3 >> 7 & 1) & 0xfffffffffffffc00 | (param_3 & 0xff) << 2));
}
[decomp]> load function mulhi
Function mulhi: 0x00400160
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mulhi
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mulhi
Decompilation complete
[decomp]> print C

xunknown8 mulhi(uint8 param_1,uint8 param_2)

{
  xunknown1 axVar1 [16];
  xunknown1 axVar2 [16];
  
  axVar1._8_8_ = 0;
  axVar1._0_8_ = param_1;
  axVar2._8_8_ = 0;
  axVar2._0_8_ = param_2;
  return SUB168(axVar1 * axVar2,8);
}
[decomp]> load function pack
Function pack: 0x00400168
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling pack
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling pack
Decompilation complete
[decomp]> print C

uint4 pack(int4 param_1,uint4 param_2,uint4 param_3)

{
  return (param_2 & 0xff) << 0x10 | param_3 & 0xffff | param_1 << 0x18;
}
