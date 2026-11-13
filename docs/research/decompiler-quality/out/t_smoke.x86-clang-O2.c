// t_smoke, x86-clang-O2 (x86:LE:32:default:gcc)
// Ghidra reference decomp output; inputs: frag/t_smoke.x86-clang-O2.xml

[decomp]> load function sum
Function sum: 0x004000c0
[decomp]> override flow r0x400230 callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> override flow r0x400290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum
Decompilation complete
[decomp]> print C

int4 sum(int4 param_1,uint4 param_2)

{
  uint4 uVar1;
  uint4 uVar2;
  int4 iVar3;
  
  if ((int4)param_2 < 1) {
    iVar3 = 0;
  }
  else {
    uVar1 = param_2 & 3;
    if (param_2 < 4) {
      uVar2 = 0;
      iVar3 = 0;
    }
    else {
      uVar2 = 0;
      iVar3 = 0;
      do {
        iVar3 = *(int4 *)(table + (uVar2 + 3 & 0xf) * 4) * *(int4 *)(param_1 + 0xc + uVar2 * 4) +
                *(int4 *)(table + (uVar2 + 2 & 0xe) * 4) * *(int4 *)(param_1 + 8 + uVar2 * 4) +
                *(int4 *)(table + (uVar2 + 1 & 0xd) * 4) * *(int4 *)(param_1 + 4 + uVar2 * 4) +
                *(int4 *)(table + (uVar2 & 0xc) * 4) * *(int4 *)(param_1 + uVar2 * 4) + iVar3;
        uVar2 = uVar2 + 4;
      } while ((param_2 & 0x7ffffffc) != uVar2);
    }
    for (; uVar1 != 0; uVar1 = uVar1 - 1) {
      iVar3 = iVar3 + *(int4 *)(table + (uVar2 & 0xf) * 4) * *(int4 *)(param_1 + uVar2 * 4);
      uVar2 = uVar2 + 1;
    }
  }
  printf("sum=%d\n",iVar3);
  return iVar3;
}
