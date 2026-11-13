// a01_ptr_param, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a01_ptr_param.x64-clang-O2.xml

[decomp]> load function get
Function get: 0x00200120
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling get
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling get
Decompilation complete
[decomp]> print C

xunknown4 get(int8 param_1,int8 param_2)

{
  return *(xunknown4 *)(param_1 + param_2 * 4);
}
[decomp]> load function sum_array
Function sum_array: 0x00200130
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_array
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_array
Decompilation complete
[decomp]> print C

int8 sum_array(int8 param_1,uint4 param_2)

{
  int8 iVar1;
  uint8 uVar2;
  uint8 uVar3;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  if (param_2 < 8) {
    uVar2 = 0;
    iVar1 = 0;
  }
  else {
    uVar2 = 0;
    iVar1 = 0;
    do {
      iVar1 = (int8)*(int4 *)(param_1 + 0x1c + uVar2 * 4) +
              (int8)*(int4 *)(param_1 + 0x18 + uVar2 * 4) +
              (int8)*(int4 *)(param_1 + 0x14 + uVar2 * 4) +
              (int8)*(int4 *)(param_1 + 0x10 + uVar2 * 4) +
              (int8)*(int4 *)(param_1 + 0xc + uVar2 * 4) +
              (int8)*(int4 *)(param_1 + 8 + uVar2 * 4) + (int8)*(int4 *)(param_1 + 4 + uVar2 * 4) +
              *(int4 *)(param_1 + uVar2 * 4) + iVar1;
      uVar2 = uVar2 + 8;
    } while ((param_2 & 0x7ffffff8) != uVar2);
  }
  if ((uint8)(param_2 & 7) != 0) {
    uVar3 = 0;
    do {
      iVar1 = iVar1 + *(int4 *)(param_1 + uVar2 * 4 + uVar3 * 4);
      uVar3 = uVar3 + 1;
    } while ((param_2 & 7) != uVar3);
  }
  return iVar1;
}
[decomp]> load function list_sum
Function list_sum: 0x002001d0
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling list_sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling list_sum
Decompilation complete
[decomp]> print C

int4 list_sum(int4 *param_1)

{
  int4 iVar1;
  
  iVar1 = 0;
  for (; param_1 != (int4 *)0x0; param_1 = *(int4 **)(param_1 + 2)) {
    iVar1 = iVar1 + *param_1;
  }
  return iVar1;
}
