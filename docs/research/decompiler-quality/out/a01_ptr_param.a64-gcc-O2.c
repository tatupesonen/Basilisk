// a01_ptr_param, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a01_ptr_param.a64-gcc-O2.xml

[decomp]> load function get
Function get: 0x00400120
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001bc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
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
Function sum_array: 0x00400128
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001bc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_array
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_array
Decompilation complete
[decomp]> print C

int8 sum_array(int4 *param_1,uint4 param_2)

{
  int8 iVar1;
  int4 *piVar3;
  int4 *piVar2;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  iVar1 = 0;
  piVar2 = param_1;
  do {
    piVar3 = piVar2 + 1;
    iVar1 = iVar1 + *piVar2;
    piVar2 = piVar3;
  } while (piVar3 != param_1 + param_2);
  return iVar1;
}
[decomp]> load function list_sum
Function list_sum: 0x00400160
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001bc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
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
