// t_smoke, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/t_smoke.x64-clang-O2.xml

[decomp]> load function sum
Function sum: 0x00200130
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
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
  uint8 uVar1;
  uint4 uVar2;
  uint8 uVar3;
  uint4 uVar4;
  
  if ((int4)param_2 < 1) {
    uVar4 = 0;
  }
  else {
    uVar1 = (uint8)(param_2 & 3);
    if (param_2 < 4) {
      uVar3 = 0;
      uVar4 = 0;
    }
    else {
      uVar3 = 0;
      uVar4 = 0;
      do {
        uVar2 = (uint4)uVar3;
        uVar4 = *(int4 *)(table + (uint8)(uVar2 + 3 & 0xf) * 4) *
                *(int4 *)(param_1 + 0xc + uVar3 * 4) +
                *(int4 *)(table + (uint8)(uVar2 + 2 & 0xe) * 4) * *(int4 *)(param_1 + 8 + uVar3 * 4)
                + *(int4 *)(table + (uint8)(uVar2 + 1 & 0xd) * 4) *
                  *(int4 *)(param_1 + 4 + uVar3 * 4) +
                  *(int4 *)(table + (uint8)(uVar2 & 0xc) * 4) * *(int4 *)(param_1 + uVar3 * 4) +
                  uVar4;
        uVar3 = uVar3 + 4;
      } while ((param_2 & 0x7ffffffc) != uVar3);
    }
    for (; uVar1 != 0; uVar1 = uVar1 - 1) {
      uVar4 = uVar4 + *(int4 *)(table + (uint8)((uint4)uVar3 & 0xf) * 4) *
                      *(int4 *)(param_1 + uVar3 * 4);
      uVar3 = uVar3 + 1;
    }
  }
  printf("sum=%d\n",(uint8)uVar4);
  return uVar4;
}
