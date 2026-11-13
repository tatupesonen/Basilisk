// r08_cmov, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r08_cmov.x64-clang-O2.xml

[decomp]> load function max3
Function max3: 0x00200120
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling max3
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling max3
Decompilation complete
[decomp]> print C

int4 max3(int4 param_1,int4 param_2,int4 param_3)

{
  if (param_2 < param_1) {
    param_2 = param_1;
  }
  if (param_2 <= param_3) {
    param_2 = param_3;
  }
  return param_2;
}
[decomp]> load function iabs
Function iabs: 0x00200130
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling iabs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling iabs
Decompilation complete
[decomp]> print C

int4 iabs(int4 param_1)

{
  int4 iVar1;
  
  iVar1 = -param_1;
  if (-param_1 < 0) {
    iVar1 = param_1;
  }
  return iVar1;
}
[decomp]> load function clamp
Function clamp: 0x00200140
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clamp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clamp
Decompilation complete
[decomp]> print C

int4 clamp(int4 param_1,int4 param_2,int4 param_3)

{
  if (param_1 < param_3) {
    param_3 = param_1;
  }
  if (param_1 < param_2) {
    param_3 = param_2;
  }
  return param_3;
}
[decomp]> load function sign
Function sign: 0x00200150
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sign
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sign
Decompilation complete
[decomp]> print C

uint4 sign(int4 param_1)

{
  return (uint4)(param_1 != 0) | param_1 >> 0x1f;
}
[decomp]> load function count_if
Function count_if: 0x00200160
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_if
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_if
Decompilation complete
[decomp]> print C

int4 count_if(int8 param_1,uint4 param_2,int4 param_3)

{
  int4 iVar1;
  uint8 uVar2;
  uint8 uVar3;
  
  if ((int4)param_2 < 1) {
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
      iVar1 = (uint4)(param_3 <= *(int4 *)(param_1 + 0xc + uVar2 * 4)) +
              (uint4)(param_3 <= *(int4 *)(param_1 + 8 + uVar2 * 4)) +
              (uint4)(param_3 <= *(int4 *)(param_1 + 4 + uVar2 * 4)) +
              (uint4)(param_3 <= *(int4 *)(param_1 + uVar2 * 4)) + iVar1;
      uVar2 = uVar2 + 4;
    } while ((param_2 & 0x7ffffffc) != uVar2);
  }
  if ((uint8)(param_2 & 3) != 0) {
    uVar3 = 0;
    do {
      iVar1 = iVar1 + (uint4)(param_3 <= *(int4 *)(param_1 + uVar2 * 4 + uVar3 * 4));
      uVar3 = uVar3 + 1;
    } while ((param_2 & 3) != uVar3);
  }
  return iVar1;
}
