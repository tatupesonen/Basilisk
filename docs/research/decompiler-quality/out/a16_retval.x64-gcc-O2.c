// a16_retval, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a16_retval.x64-gcc-O2.xml

[decomp]> load function inc
Function inc: 0x00401000
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
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
Function find_idx: 0x00401010
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_idx
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_idx
Decompilation complete
[decomp]> print C

void find_idx(int4 *param_1,int4 param_2,int4 param_3)

{
  int4 iVar1;
  
  iVar1 = 0;
  if (param_2 < 1) {
    return;
  }
  do {
    if (*param_1 == param_3) {
      return;
    }
    iVar1 = iVar1 + 1;
    param_1 = param_1 + 1;
  } while (param_2 != iVar1);
  return;
}
[decomp]> load function after_call
Function after_call: 0x00401040
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
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
  char acStack_28 [40];
  
  strcpy(acStack_28,param_1);
  puts(acStack_28);
  return;
}
