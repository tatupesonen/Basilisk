// r11_varargs, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r11_varargs.x64-clang-O2.xml

[decomp]> load function sum_ints
Function sum_ints: 0x00200120
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_ints
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_ints
Decompilation complete
[decomp]> print C

int4 sum_ints(uint4 param_1)

{
  int4 iVar1;
  int4 *piVar2;
  uint8 uVar3;
  int4 *piVar4;
  uint4 uVar5;
  int4 *piVar6;
  int4 *piVar7;
  int4 iStack0000000000000008;
  uint4 uStack_d8;
  int4 aiStack_b8 [46];
  
  piVar2 = &iStack0000000000000008;
  if ((int4)param_1 < 1) {
    return 0;
  }
  uStack_d8 = 8;
  if (param_1 == 1) {
    iVar1 = 0;
  }
  else {
    uVar5 = param_1 & 0x7ffffffe;
    iVar1 = 0;
    do {
      if (uStack_d8 < 0x29) {
        uVar3 = (uint8)uStack_d8;
        uStack_d8 = uStack_d8 + 8;
        piVar4 = (int4 *)((int8)aiStack_b8 + uVar3);
        piVar7 = piVar2;
      }
      else {
        piVar7 = piVar2 + 2;
        piVar4 = piVar2;
      }
      if (uStack_d8 < 0x29) {
        piVar6 = (int4 *)((int8)aiStack_b8 + (uint8)uStack_d8);
        uStack_d8 = uStack_d8 + 8;
        piVar2 = piVar7;
      }
      else {
        piVar2 = piVar7 + 2;
        piVar6 = piVar7;
      }
      iVar1 = iVar1 + *piVar4 + *piVar6;
      uVar5 = uVar5 - 2;
    } while (uVar5 != 0);
  }
  if ((param_1 & 1) != 0) {
    if (uStack_d8 < 0x29) {
      piVar2 = (int4 *)((int8)aiStack_b8 + (uint8)uStack_d8);
    }
    iVar1 = iVar1 + *piVar2;
  }
  return iVar1;
}
