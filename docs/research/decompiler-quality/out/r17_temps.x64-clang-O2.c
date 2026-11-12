// r17_temps, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r17_temps.x64-clang-O2.xml

[decomp]> load function checksum
Function checksum: 0x00200120
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> override flow r0x200340 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling checksum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling checksum
Decompilation complete
[decomp]> print C

uint4 checksum(int8 param_1,uint4 param_2)

{
  uint4 uVar1;
  uint4 uVar2;
  uint8 uVar3;
  uint4 uVar4;
  
  if (param_2 == 0) {
    return 1;
  }
  if (param_2 == 1) {
    uVar2 = 1;
    uVar3 = 0;
    uVar1 = 0;
  }
  else {
    uVar2 = 1;
    uVar3 = 0;
    uVar1 = 0;
    do {
      uVar4 = (*(uint1 *)(param_1 + uVar3) + uVar2) % 0xfff1;
      uVar2 = (*(uint1 *)(param_1 + 1 + uVar3) + uVar4) % 0xfff1;
      uVar1 = ((uVar1 + uVar4) % 0xfff1 + uVar2) % 0xfff1;
      uVar3 = uVar3 + 2;
    } while ((param_2 & 0xfffffffe) != uVar3);
  }
  if ((param_2 & 1) != 0) {
    uVar2 = (uVar2 + *(uint1 *)(param_1 + uVar3)) % 0xfff1;
    uVar1 = (uVar1 + uVar2) % 0xfff1;
  }
  return uVar1 << 0x10 | uVar2;
}
[decomp]> load function update
Function update: 0x00200210
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> override flow r0x200340 callreturn
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
  int4 iVar1;
  
  param_2 = param_2 + *param_1;
  if (param_2 < -param_1[1]) {
    *(uint1 *)((int8)param_1 + 0x14) = *(uint1 *)((int8)param_1 + 0x14) | 4;
    return -1;
  }
  *param_1 = param_2;
  iVar1 = (int4)param_1[2] + 1;
  *(int4 *)(param_1 + 2) = iVar1;
  if (param_2 < 0) {
    *(uint4 *)((int8)param_1 + 0x14) = *(uint4 *)((int8)param_1 + 0x14) | 1;
    return iVar1;
  }
  *(uint4 *)((int8)param_1 + 0x14) = *(uint4 *)((int8)param_1 + 0x14) & 0xfffffffe;
  return iVar1;
}
