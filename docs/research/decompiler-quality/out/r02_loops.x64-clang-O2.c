// r02_loops, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r02_loops.x64-clang-O2.xml

[decomp]> load function fill
Function fill: 0x00200120
[decomp]> override flow r0x2003b0 callreturn
Successfully added flow override
[decomp]> override flow r0x2003c0 callreturn
Successfully added flow override
[decomp]> override flow r0x200410 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fill
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fill
Decompilation complete
[decomp]> print C

void fill(int8 param_1,uint4 param_2,int4 param_3)

{
  int4 iVar1;
  uint8 uVar2;
  uint8 uVar3;
  
  if (0 < (int4)param_2) {
    if (param_2 < 4) {
      uVar2 = 0;
    }
    else {
      uVar2 = 0;
      do {
        iVar1 = (int4)uVar2;
        *(int4 *)(param_1 + uVar2 * 4) = param_3 + iVar1;
        *(int4 *)(param_1 + 4 + uVar2 * 4) = param_3 + iVar1 + 1;
        *(int4 *)(param_1 + 8 + uVar2 * 4) = param_3 + 2 + iVar1;
        *(int4 *)(param_1 + 0xc + uVar2 * 4) = param_3 + iVar1 + 3;
        uVar2 = uVar2 + 4;
      } while ((param_2 & 0x7ffffffc) != uVar2);
    }
    if ((uint8)(param_2 & 3) != 0) {
      uVar3 = 0;
      do {
        *(int4 *)(param_1 + uVar2 * 4 + uVar3 * 4) = param_3 + (int4)uVar2 + (int4)uVar3;
        uVar3 = uVar3 + 1;
      } while ((param_2 & 3) != uVar3);
    }
  }
  return;
}
[decomp]> load function find_first
Function find_first: 0x002001a0
[decomp]> override flow r0x2003b0 callreturn
Successfully added flow override
[decomp]> override flow r0x2003c0 callreturn
Successfully added flow override
[decomp]> override flow r0x200410 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_first
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_first
Decompilation complete
[decomp]> print C

void find_first(int8 param_1,int4 param_2,int4 param_3)

{
  int4 iVar1;
  uint4 uVar2;
  int4 iVar3;
  
  uVar2 = 0;
  if (0 < param_2) {
    do {
      iVar1 = *(int4 *)(param_1 + (uint8)uVar2 * 4);
      if (iVar1 < 0) {
        iVar3 = 2;
      }
      else {
        iVar3 = 1;
        if (iVar1 == param_3) {
          return;
        }
      }
      uVar2 = uVar2 + iVar3;
    } while ((int4)uVar2 < param_2);
  }
  return;
}
[decomp]> load function count_pairs
Function count_pairs: 0x002001e0
[decomp]> override flow r0x2003b0 callreturn
Successfully added flow override
[decomp]> override flow r0x2003c0 callreturn
Successfully added flow override
[decomp]> override flow r0x200410 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_pairs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_pairs
Decompilation complete
[decomp]> print C

int4 count_pairs(int8 param_1,uint4 param_2,int4 param_3)

{
  int4 iVar1;
  int4 iVar2;
  uint8 uVar3;
  uint8 uVar4;
  uint8 uVar5;
  char cVar6;
  uint4 uVar7;
  int8 iVar8;
  uint8 uVar9;
  int8 iVar10;
  uint8 uVar11;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  uVar3 = (uint8)param_2;
  cVar6 = (char)param_2;
  uVar9 = 1;
  iVar10 = -1;
  iVar2 = 0;
  uVar4 = 0;
  iVar8 = param_1;
  do {
    iVar8 = iVar8 + 4;
    uVar7 = (uint1)(cVar6 + 3) & 3;
    uVar5 = uVar4 + 1;
    if (uVar5 < uVar3) {
      iVar1 = *(int4 *)(param_1 + uVar4 * 4);
      if ((~(uint4)uVar4 + param_2 & 3) == 0) {
        uVar11 = uVar9;
      }
      else {
        uVar11 = 0;
        do {
          iVar2 = iVar2 + (uint4)(*(int4 *)(iVar8 + uVar11 * 4) + iVar1 == param_3);
          uVar11 = uVar11 + 1;
        } while (uVar7 != uVar11);
        uVar11 = uVar11 - iVar10;
      }
      if (2 < (uVar3 - 2) - uVar4) {
        do {
          iVar2 = (uint4)(*(int4 *)(param_1 + 0xc + uVar11 * 4) + iVar1 == param_3) +
                  (uint4)(*(int4 *)(param_1 + 8 + uVar11 * 4) + iVar1 == param_3) +
                  (uint4)(*(int4 *)(param_1 + 4 + uVar11 * 4) + iVar1 == param_3) +
                  (uint4)(*(int4 *)(param_1 + uVar11 * 4) + iVar1 == param_3) + iVar2;
          uVar11 = uVar11 + 4;
        } while (uVar3 != uVar11);
      }
    }
    uVar9 = uVar9 + 1;
    iVar10 = iVar10 + -1;
    cVar6 = (char)uVar7;
    uVar4 = uVar5;
  } while (uVar5 != uVar3);
  return iVar2;
}
[decomp]> load function my_strlen
Function my_strlen: 0x00200300
[decomp]> override flow r0x2003b0 callreturn
Successfully added flow override
[decomp]> override flow r0x2003c0 callreturn
Successfully added flow override
[decomp]> override flow r0x200410 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling my_strlen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling my_strlen
Decompilation complete
[decomp]> print C

void my_strlen(int8 param_1)

{
  char *pcVar1;
  int8 iVar2;
  
  iVar2 = -1;
  do {
    pcVar1 = (char *)(param_1 + 1 + iVar2);
    iVar2 = iVar2 + 1;
  } while (*pcVar1 != '\0');
  return;
}
