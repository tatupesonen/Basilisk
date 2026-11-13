// r11_varargs, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r11_varargs.a64-gcc-O2.xml

[decomp]> load function sum_ints
Function sum_ints: 0x00400120
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> override flow r0x400224 callreturn
Successfully added flow override
[decomp]> override flow r0x400248 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_ints
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_ints
Decompilation complete
[decomp]> print C

int4 sum_ints(int4 param_1)

{
  bool bVar1;
  int4 iVar2;
  int4 iVar3;
  int4 iVar4;
  int4 iVar5;
  int4 in_stack_00000000;
  int4 iStack0000000000000008;
  int4 aiStack_38 [14];
  
  if (param_1 < 1) {
    return 0;
  }
  iVar3 = 0;
  iVar2 = 0;
  iVar4 = -0x38;
  iVar5 = -0x30;
  do {
    if (0 < iVar5) {
      iVar3 = iVar3 + 1;
      iVar2 = iVar2 + in_stack_00000000;
      register_sp = (BADSPACEBASE *)&iStack0000000000000008;
      if (param_1 == iVar3) {
        return iVar2;
      }
      break;
    }
    iVar3 = iVar3 + 1;
    iVar2 = iVar2 + *(int4 *)((int8)aiStack_38 + (int8)iVar4 + 0x38);
    if (param_1 == iVar3) {
      return iVar2;
    }
    bVar1 = iVar5 < 0;
    iVar4 = iVar5;
    iVar5 = iVar5 + 8;
  } while (bVar1);
  do {
    iVar3 = iVar3 + 1;
    iVar2 = iVar2 + *(int4 *)register_sp;
    register_sp = (BADSPACEBASE *)((int8)register_sp + 8);
  } while (param_1 != iVar3);
  return iVar2;
}
