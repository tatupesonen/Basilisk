// t_smoke, a64-clang-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/t_smoke.a64-clang-O2.xml

[decomp]> load function sum
Function sum: 0x00200128
[decomp]> override flow r0x2001f4 callreturn
Successfully added flow override
[decomp]> override flow r0x2001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum
Decompilation complete
[decomp]> print C

uint4 sum(int8 param_1,uint4 param_2)

{
  int8 iVar1;
  uint8 uVar2;
  uint8 uVar3;
  uint4 uVar4;
  
  if ((int4)param_2 < 1) {
    uVar4 = 0;
  }
  else {
    uVar2 = 0;
    uVar4 = 0;
    do {
      uVar3 = uVar2 & 0xf;
      iVar1 = uVar2 * 4;
      uVar2 = uVar2 + 1;
      uVar4 = uVar4 + *(int4 *)(table + uVar3 * 4) * *(int4 *)(param_1 + iVar1);
    } while (param_2 != uVar2);
  }
  printf("sum=%d\n",(uint8)uVar4);
  return uVar4;
}
