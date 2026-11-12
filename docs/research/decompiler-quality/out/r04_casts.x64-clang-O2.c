// r04_casts, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r04_casts.x64-clang-O2.xml

[decomp]> load function widen
Function widen: 0x00200120
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling widen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling widen
Decompilation complete
[decomp]> print C

int8 widen(int4 param_1,int4 param_2,int4 param_3,uint4 param_4)

{
  return ((int8)param_3 + (int8)param_2 * (int8)param_1) - (uint8)param_4;
}
[decomp]> load function index8
Function index8: 0x00200140
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling index8
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling index8
Decompilation complete
[decomp]> print C

int4 index8(int8 param_1,uint4 param_2,int4 param_3)

{
  return *(int4 *)(param_1 + (int8)param_3 * 4) + *(int4 *)(param_1 + (uint8)param_2 * 4);
}
[decomp]> load function mulhi
Function mulhi: 0x00200150
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
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
  axVar1._0_8_ = param_2;
  axVar2._8_8_ = 0;
  axVar2._0_8_ = param_1;
  return SUB168(axVar1 * axVar2,8);
}
[decomp]> load function pack
Function pack: 0x00200160
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling pack
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling pack
Decompilation complete
[decomp]> print C

uint4 pack(int4 param_1,int4 param_2,uint4 param_3)

{
  return param_2 * 0x10000 + param_1 * 0x1000000 | param_3;
}
