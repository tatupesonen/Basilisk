// r02_loops, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r02_loops.a64-gcc-O2.xml

[decomp]> load function fill
Function fill: 0x00400120
[decomp]> override flow r0x40023c callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fill
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fill
Decompilation complete
[decomp]> print C

void fill(int8 param_1,int4 param_2,int4 param_3)

{
  int8 iVar1;
  
  if (0 < param_2) {
    iVar1 = 0;
    do {
      *(int4 *)(param_1 + iVar1 * 4) = param_3 + (int4)iVar1;
      iVar1 = iVar1 + 1;
    } while (iVar1 != param_2);
  }
  return;
}
[decomp]> load function find_first
Function find_first: 0x00400148
[decomp]> override flow r0x40023c callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
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
  if (0 < param_2) {
    do {
      while (iVar1 = *(int4 *)(param_1 + (int8)iVar2 * 4), -1 < iVar1) {
        if (iVar1 == param_3) {
          return;
        }
        iVar2 = iVar2 + 1;
        if (param_2 <= iVar2) {
          return;
        }
      }
      iVar2 = iVar2 + 2;
    } while (iVar2 < param_2);
  }
  return;
}
[decomp]> load function count_pairs
Function count_pairs: 0x00400188
[decomp]> override flow r0x40023c callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_pairs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_pairs
Decompilation complete
[decomp]> print C

int4 count_pairs(int8 param_1,int4 param_2,int4 param_3)

{
  int8 iVar1;
  int4 iVar2;
  int8 iVar3;
  int8 iVar4;
  
  iVar2 = 0;
  if (0 < param_2) {
    iVar4 = 1;
    if (1 < param_2) {
      do {
        iVar3 = iVar4;
        do {
          iVar1 = iVar3 * 4;
          iVar3 = iVar3 + 1;
          if (*(int4 *)(param_1 + -4 + iVar4 * 4) + *(int4 *)(param_1 + iVar1) == param_3) {
            iVar2 = iVar2 + 1;
          }
        } while ((int4)iVar3 < param_2);
        iVar4 = iVar4 + 1;
      } while ((int4)iVar4 < param_2);
    }
  }
  return iVar2;
}
[decomp]> load function my_strlen
Function my_strlen: 0x004001e0
[decomp]> override flow r0x40023c callreturn
Successfully added flow override
[decomp]> override flow r0x400240 callreturn
Successfully added flow override
[decomp]> override flow r0x400264 callreturn
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
