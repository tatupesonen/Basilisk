// a09_overflow, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a09_overflow.x64-clang-O2.xml

[decomp]> load function add_overflows
Function add_overflows: 0x00200120
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling add_overflows
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling add_overflows
Decompilation complete
[decomp]> print C

bool add_overflows(int4 param_1)

{
  return 0x7fffff9b < param_1;
}
[decomp]> load function uadd_overflows
Function uadd_overflows: 0x00200130
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling uadd_overflows
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling uadd_overflows
Decompilation complete
[decomp]> print C

bool uadd_overflows(uint4 param_1,uint4 param_2)

{
  return CARRY4(param_1,param_2);
}
[decomp]> load function mul_checked
Function mul_checked: 0x00200140
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mul_checked
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mul_checked
Decompilation complete
[decomp]> print C

bool mul_checked(int4 param_1,int4 param_2,int4 *param_3)

{
  int4 iVar1;
  
  iVar1 = (int4)((int8)param_1 * (int8)param_2);
  *param_3 = iVar1;
  return (int8)iVar1 != (int8)param_1 * (int8)param_2;
}
[decomp]> load function next_id
Function next_id: 0x00200150
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling next_id
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling next_id
Decompilation complete
[decomp]> print C

int4 next_id(uint4 param_1)

{
  int4 iVar1;
  
  iVar1 = 1;
  if (param_1 < 0x7fffffff) {
    iVar1 = param_1 + 1;
  }
  return iVar1;
}
