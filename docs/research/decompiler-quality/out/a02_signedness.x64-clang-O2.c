// a02_signedness, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a02_signedness.x64-clang-O2.xml

[decomp]> load function half
Function half: 0x00200120
[decomp]> override flow r0x200270 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling half
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling half
Decompilation complete
[decomp]> print C

int4 half(int4 param_1)

{
  return param_1 / 2;
}
[decomp]> load function avg
Function avg: 0x00200130
[decomp]> override flow r0x200270 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling avg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling avg
Decompilation complete
[decomp]> print C

int4 avg(int4 param_1,int4 param_2)

{
  return (param_1 + param_2) / 2;
}
[decomp]> load function is_upper
Function is_upper: 0x00200140
[decomp]> override flow r0x200270 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_upper
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_upper
Decompilation complete
[decomp]> print C

bool is_upper(char param_1)

{
  return (uint1)(param_1 + 0xbfU) < 0x1a;
}
[decomp]> load function count_neg
Function count_neg: 0x00200150
[decomp]> override flow r0x200270 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_neg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_neg
Decompilation complete
[decomp]> print C

int4 count_neg(int8 param_1,uint4 param_2)

{
  int4 iVar1;
  uint8 uVar2;
  uint8 uVar3;
  
  if (param_2 == 0) {
    return 0;
  }
  if (param_2 < 4) {
    uVar2 = 0;
    iVar1 = 0;
  }
  else {
    uVar2 = 0;
    iVar1 = 0;
    do {
      iVar1 = (uint4)(*(uint1 *)(param_1 + 3 + uVar2) >> 7) +
              (uint4)(*(uint1 *)(param_1 + 2 + uVar2) >> 7) +
              (uint4)(*(uint1 *)(param_1 + 1 + uVar2) >> 7) +
              (uint4)(*(uint1 *)(param_1 + uVar2) >> 7) + iVar1;
      uVar2 = uVar2 + 4;
    } while ((param_2 & 0xfffffffc) != uVar2);
  }
  if ((uint8)(param_2 & 3) != 0) {
    uVar3 = 0;
    do {
      iVar1 = iVar1 + (uint4)(*(uint1 *)(param_1 + uVar2 + uVar3) >> 7);
      uVar3 = uVar3 + 1;
    } while ((param_2 & 3) != uVar3);
  }
  return iVar1;
}
