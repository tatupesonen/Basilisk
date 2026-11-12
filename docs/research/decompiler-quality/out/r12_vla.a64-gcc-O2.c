// r12_vla, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r12_vla.a64-gcc-O2.xml

[decomp]> load function reverse_print
Function reverse_print: 0x00400120
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001e8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling reverse_print
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling reverse_print
Decompilation complete
[decomp]> print C

int4 reverse_print(xunknown1 *param_1,int4 param_2)

{
  int8 iVar1;
  bool bVar2;
  int4 iVar3;
  xunknown1 *pxVar4;
  char *pcVar5;
  char acStack_90 [128];
  
  iVar1 = -((int8)(param_2 + 1) + 0xfU & 0xfffffffffffffff0);
  if (0 < param_2) {
    pxVar4 = param_1 + (param_2 + -1);
    pcVar5 = acStack_90 + iVar1 + 0x80;
    do {
      bVar2 = pxVar4 != param_1;
      *pcVar5 = *pxVar4;
      pxVar4 = pxVar4 + -1;
      pcVar5 = pcVar5 + 1;
    } while (bVar2);
  }
  acStack_90[param_2 + iVar1 + 0x80] = '\0';
  iVar3 = puts(acStack_90 + iVar1 + 0x80);
  return iVar3;
}
