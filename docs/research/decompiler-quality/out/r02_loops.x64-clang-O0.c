// r02_loops, x64-clang-O0 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r02_loops.x64-clang-O0.xml

[decomp]> load function fill
Function fill: 0x00200120
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
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
  int4 iStack_1c;
  
  for (iStack_1c = 0; iStack_1c < param_2; iStack_1c = iStack_1c + 1) {
    *(int4 *)(param_1 + (int8)iStack_1c * 4) = param_3 + iStack_1c;
  }
  return;
}
[decomp]> load function find_first
Function find_first: 0x00200160
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_first
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_first
Decompilation complete
[decomp]> print C

int4 find_first(int8 param_1,int4 param_2,int4 param_3)

{
  int4 iStack_1c;
  
  iStack_1c = 0;
  while( true ) {
    while( true ) {
      if (param_2 <= iStack_1c) {
        return iStack_1c;
      }
      if (-1 < *(int4 *)(param_1 + (int8)iStack_1c * 4)) break;
      iStack_1c = iStack_1c + 2;
    }
    if (*(int4 *)(param_1 + (int8)iStack_1c * 4) == param_3) break;
    iStack_1c = iStack_1c + 1;
  }
  return iStack_1c;
}
[decomp]> load function count_pairs
Function count_pairs: 0x002001c0
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
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
  int4 iStack_24;
  int4 iStack_20;
  int4 iStack_1c;
  
  iStack_1c = 0;
  for (iStack_20 = 0; iStack_24 = iStack_20, iStack_20 < param_2; iStack_20 = iStack_20 + 1) {
    while (iStack_24 = iStack_24 + 1, iStack_24 < param_2) {
      if (*(int4 *)(param_1 + (int8)iStack_20 * 4) + *(int4 *)(param_1 + (int8)iStack_24 * 4) ==
          param_3) {
        iStack_1c = iStack_1c + 1;
      }
    }
  }
  return iStack_1c;
}
[decomp]> load function my_strlen
Function my_strlen: 0x00200240
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
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
  char *pcStack_18;
  
  for (pcStack_18 = param_1; *pcStack_18 != '\0'; pcStack_18 = pcStack_18 + 1) {
  }
  return (int8)pcStack_18 - (int8)param_1;
}
