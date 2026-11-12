// a16_retval, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a16_retval.a64-gcc-O2.xml

[decomp]> load function inc
Function inc: 0x00400120
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001e8 callreturn
Successfully added flow override
[decomp]> override flow r0x40020c callreturn
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
Function find_idx: 0x00400140
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001e8 callreturn
Successfully added flow override
[decomp]> override flow r0x40020c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_idx
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_idx
Decompilation complete
[decomp]> print C

uint8 find_idx(int8 param_1,int4 param_2,int4 param_3)

{
  int4 iVar1;
  uint8 uVar2;
  
  if (param_2 < 1) {
    return 0;
  }
  uVar2 = 0;
  do {
    iVar1 = (int4)uVar2;
    if (*(int4 *)(param_1 + uVar2 * 4) == param_3) {
      return uVar2 & 0xffffffff;
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 != (int8)param_2);
  return (uint8)(iVar1 + 1);
}
[decomp]> load function after_call
Function after_call: 0x00400188
[decomp]> override flow r0x4001e4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001e8 callreturn
Successfully added flow override
[decomp]> override flow r0x40020c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling after_call
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling after_call
Decompilation complete
[decomp]> print C

int4 after_call(char *param_1)

{
  int4 iVar1;
  char acStack_20 [32];
  
  strcpy(acStack_20,param_1);
  iVar1 = puts(acStack_20);
  return iVar1;
}
