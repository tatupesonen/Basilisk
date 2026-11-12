// a16_retval, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a16_retval.x64-clang-O2.xml

[decomp]> load function inc
Function inc: 0x00200120
[decomp]> override flow r0x200220 callreturn
Successfully added flow override
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling inc
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling inc
Decompilation complete
[decomp]> print C

void inc(int4 *param_1)

{
  *param_1 = *param_1 + 1;
  return;
}
[decomp]> load function find_idx
Function find_idx: 0x00200130
[decomp]> override flow r0x200220 callreturn
Successfully added flow override
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_idx
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_idx
Decompilation complete
[decomp]> print C

uint8 find_idx(int8 param_1,uint4 param_2,int4 param_3)

{
  uint8 uVar1;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  uVar1 = 0;
  do {
    if (*(int4 *)(param_1 + uVar1 * 4) == param_3) {
      return uVar1;
    }
    uVar1 = uVar1 + 1;
  } while (param_2 != uVar1);
  return (uint8)param_2;
}
[decomp]> load function after_call
Function after_call: 0x00200160
[decomp]> override flow r0x200220 callreturn
Successfully added flow override
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling after_call
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling after_call
Decompilation complete
[decomp]> print C

void after_call(char *param_1)

{
  char acStack_28 [32];
  
  strcpy(acStack_28,param_1);
  puts(acStack_28);
  return;
}
