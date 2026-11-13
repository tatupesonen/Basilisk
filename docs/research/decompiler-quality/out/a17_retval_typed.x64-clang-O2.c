// a17_retval_typed, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a17_retval_typed.x64-clang-O2.xml

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

int4 inc(int4 *p)

{
  int4 iVar1;
  
  iVar1 = *p;
  *p = iVar1 + 1;
  return iVar1 + 1;
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

int4 find_idx(int4 *a,int4 n,int4 key)

{
  uint8 uVar1;
  
  if (n < 1) {
    return 0;
  }
  uVar1 = 0;
  do {
    if (a[uVar1] == key) goto code_r0x0020014f;
    uVar1 = uVar1 + 1;
  } while ((uint4)n != uVar1);
  uVar1 = (uint8)(uint4)n;
code_r0x0020014f:
  return (int4)uVar1;
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

int4 after_call(char *s)

{
  int4 iVar1;
  char acStack_28 [32];
  
  strcpy(acStack_28,s);
  iVar1 = puts(acStack_28);
  return iVar1;
}
