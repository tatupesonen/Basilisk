// r02_loops, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r02_loops.x64-gcc-O2.xml

[decomp]> load function fill
Function fill: 0x00401000
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fill
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fill
Decompilation complete
[decomp]> print C

void fill(int4 *param_1,int4 param_2,int4 param_3)

{
  if (0 < param_2) {
    param_2 = param_2 + param_3;
    do {
      *param_1 = param_3;
      param_3 = param_3 + 1;
      param_1 = param_1 + 1;
    } while (param_3 != param_2);
  }
  return;
}
[decomp]> load function find_first
Function find_first: 0x00401020
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
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
  int4 iVar2;
  
  iVar2 = 0;
  if (param_2 < 1) {
    return;
  }
  while( true ) {
    while (iVar1 = *(int4 *)(param_1 + (int8)iVar2 * 4), iVar1 < 0) {
      iVar2 = iVar2 + 2;
      if (param_2 <= iVar2) {
        return;
      }
    }
    if (iVar1 == param_3) break;
    iVar2 = iVar2 + 1;
    if (param_2 <= iVar2) {
      return;
    }
  }
  return;
}
[decomp]> load function count_pairs
Function count_pairs: 0x00401060
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
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
  int8 iVar1;
  uint8 uVar2;
  int4 iVar3;
  uint8 uVar4;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  uVar4 = 1;
  iVar3 = 0;
  if ((uint8)param_2 != 1) {
    do {
      uVar2 = uVar4;
      do {
        iVar1 = uVar2 * 4;
        uVar2 = uVar2 + 1;
        iVar3 = iVar3 + (uint4)(*(int4 *)(param_1 + iVar1) + *(int4 *)(param_1 + -4 + uVar4 * 4) ==
                               param_3);
      } while ((int4)uVar2 < (int4)param_2);
      uVar4 = uVar4 + 1;
    } while (uVar4 != param_2);
  }
  return iVar3;
}
[decomp]> load function my_strlen
Function my_strlen: 0x004010d0
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling my_strlen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling my_strlen
Decompilation complete
[decomp]> print C

int8 my_strlen(char *param_1)

{
  char *pcVar1;
  
  if (*param_1 == '\0') {
    return 0;
  }
  pcVar1 = param_1;
  do {
    pcVar1 = pcVar1 + 1;
  } while (*pcVar1 != '\0');
  return (int8)pcVar1 - (int8)param_1;
}
