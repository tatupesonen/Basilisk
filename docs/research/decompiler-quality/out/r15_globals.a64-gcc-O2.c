// r15_globals, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r15_globals.a64-gcc-O2.xml

[decomp]> load function bump
Function bump: 0x00400120
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001cc callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bump
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bump
Decompilation complete
[decomp]> print C

void bump(int4 param_1)

{
  counter = param_1 + counter;
  *(int4 *)(history + (int8)(int4)(counter & 0x1f) * 4) = param_1;
  return;
}
[decomp]> load function lookup_name
Function lookup_name: 0x00400148
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001cc callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lookup_name
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lookup_name
Decompilation complete
[decomp]> print C

xunknown8 lookup_name(int4 param_1)

{
  int4 iVar1;
  int4 iVar2;
  xunknown1 *pxVar3;
  
  pxVar3 = table;
  iVar2 = 0;
  do {
    iVar1 = *(int4 *)pxVar3;
    pxVar3 = (xunknown1 *)((int8)pxVar3 + 0x10);
    if (iVar1 == param_1) {
      return *(xunknown8 *)(table + (int8)iVar2 * 0x10 + 8);
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 != 8);
  return 0;
}
