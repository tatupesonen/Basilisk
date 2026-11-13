// t_smoke, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/t_smoke.a64-gcc-O2.xml

[decomp]> load function sum
Function sum: 0x00400120
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x400208 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum
Decompilation complete
[decomp]> print C

uint4 sum(int8 param_1,int4 param_2)

{
  int8 iVar1;
  uint4 uVar2;
  int8 iVar3;
  uint4 uVar4;
  
  if (param_2 < 1) {
    printf("sum=%d\n",0);
    return 0;
  }
  iVar3 = 0;
  uVar4 = 0;
  do {
    uVar2 = (uint4)iVar3;
    iVar1 = iVar3 * 4;
    iVar3 = iVar3 + 1;
    uVar4 = uVar4 + *(int4 *)(table + (int8)(int4)(uVar2 & 0xf) * 4) * *(int4 *)(param_1 + iVar1);
  } while (param_2 != iVar3);
  printf("sum=%d\n",(uint8)uVar4);
  return uVar4;
}
