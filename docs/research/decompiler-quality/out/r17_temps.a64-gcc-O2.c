// r17_temps, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r17_temps.a64-gcc-O2.xml

[decomp]> load function checksum
Function checksum: 0x00400120
[decomp]> override flow r0x400208 callreturn
Successfully added flow override
[decomp]> override flow r0x40020c callreturn
Successfully added flow override
[decomp]> override flow r0x400230 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling checksum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling checksum
Decompilation complete
[decomp]> print C

uint4 checksum(uint1 *param_1,uint4 param_2)

{
  uint1 *puVar2;
  uint1 *puVar1;
  uint4 uVar3;
  uint4 uVar4;
  
  if (param_2 == 0) {
    return 1;
  }
  uVar4 = 0;
  uVar3 = 1;
  puVar2 = param_1;
  do {
    puVar1 = puVar2 + 1;
    uVar3 = (*puVar2 + uVar3) % 0xfff1;
    uVar4 = (uVar3 + uVar4) % 0xfff1;
    puVar2 = puVar1;
  } while (param_1 + param_2 != puVar1);
  return uVar3 | uVar4 << 0x10;
}
[decomp]> load function update
Function update: 0x00400180
[decomp]> override flow r0x400208 callreturn
Successfully added flow override
[decomp]> override flow r0x40020c callreturn
Successfully added flow override
[decomp]> override flow r0x400230 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling update
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling update
Decompilation complete
[decomp]> print C

int4 update(int8 *param_1,int8 param_2)

{
  uint4 uVar1;
  int4 iVar2;
  uint4 uVar3;
  
  param_2 = param_2 + *param_1;
  uVar1 = *(uint4 *)((int8)param_1 + 0x14);
  if (-param_2 == param_1[1] || -param_1[1] < param_2) {
    uVar3 = uVar1 & 0xfffffffe;
    if (param_2 < 0) {
      uVar3 = uVar1 | 1;
    }
    iVar2 = (int4)param_1[2] + 1;
    *param_1 = param_2;
    *(int4 *)(param_1 + 2) = iVar2;
  }
  else {
    uVar3 = uVar1 | 4;
    iVar2 = -1;
  }
  *(uint4 *)((int8)param_1 + 0x14) = uVar3;
  return iVar2;
}
