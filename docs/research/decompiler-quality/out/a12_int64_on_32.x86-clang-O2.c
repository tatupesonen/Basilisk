// a12_int64_on_32, x86-clang-O2 (x86:LE:32:default:gcc)
// Ghidra reference decomp output; inputs: frag/a12_int64_on_32.x86-clang-O2.xml

[decomp]> load function add64
Function add64: 0x004000c0
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling add64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling add64
Decompilation complete
[decomp]> print C

xunknown8 add64(uint4 param_1,int4 param_2,uint4 param_3,int4 param_4)

{
  return CONCAT44(param_4 + param_2 + (uint4)CARRY4(param_3,param_1),param_3 + param_1);
}
[decomp]> load function mul64
Function mul64: 0x004000e0
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mul64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mul64
Decompilation complete
[decomp]> print C

xunknown8 mul64(uint4 param_1,int4 param_2,uint4 param_3,int4 param_4)

{
  return CONCAT44((int4)((uint8)param_3 * (uint8)param_1 >> 0x20) + param_3 * param_2 +
                  param_1 * param_4,(int4)((uint8)param_3 * (uint8)param_1));
}
[decomp]> load function shl64
Function shl64: 0x00400100
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling shl64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling shl64
Decompilation complete
[decomp]> print C

xunknown8 shl64(uint4 param_1,int4 param_2,uint1 param_3)

{
  uint4 uVar1;
  uint4 uVar2;
  uint4 uVar3;
  
  uVar3 = param_1 << (param_3 & 0x1f);
  uVar2 = param_2 << (param_3 & 0x1f) | param_1 >> 0x20 - (param_3 & 0x1f);
  if ((param_3 & 0x20) == 0) {
    uVar1 = uVar3;
  }
  else {
    uVar1 = 0;
    uVar2 = uVar3;
  }
  return CONCAT44(uVar2,uVar1);
}
[decomp]> load function cmp64
Function cmp64: 0x00400130
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling cmp64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling cmp64
Decompilation complete
[decomp]> print C

bool cmp64(uint4 param_1,int4 param_2,uint4 param_3,int4 param_4)

{
  return (SBORROW4(param_2,param_4) != SBORROW4(param_2 - param_4,(uint4)(param_1 < param_3))) !=
         (int4)((param_2 - param_4) - (uint4)(param_1 < param_3)) < 0;
}
