// a17_retval_typed, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a17_retval_typed.a64-gcc-O2.xml

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

int4 inc(int4 *p)

{
  int4 iVar1;
  
  iVar1 = *p;
  *p = iVar1 + 1;
  return iVar1 + 1;
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

int4 find_idx(int4 *a,int4 n,int4 key)

{
  int4 iVar1;
  int8 iVar2;
  
  if (n < 1) {
    return 0;
  }
  iVar2 = 0;
  do {
    iVar1 = (int4)iVar2;
    if (a[iVar2] == key) {
      return iVar1;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 != n);
  return iVar1 + 1;
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

int4 after_call(char *s)

{
  int4 iVar1;
  char acStack_20 [32];
  
  strcpy(acStack_20,s);
  iVar1 = puts(acStack_20);
  return iVar1;
}
