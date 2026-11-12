// r13_bool, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r13_bool.x64-clang-O2.xml

[decomp]> load function in_range
Function in_range: 0x00200120
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling in_range
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling in_range
Decompilation complete
[decomp]> print C

bool in_range(int4 param_1,int4 param_2,int4 param_3)

{
  return param_1 <= param_3 && param_2 <= param_1;
}
[decomp]> load function valid
Function valid: 0x00200130
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling valid
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling valid
Decompilation complete
[decomp]> print C

bool valid(int4 *param_1,int4 param_2)

{
  bool bVar1;
  
  bVar1 = false;
  if (0 < param_2 && param_1 != (int4 *)0x0) {
    bVar1 = *param_1 == param_2;
  }
  return bVar1;
}
[decomp]> load function either
Function either: 0x00200150
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling either
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling either
Decompilation complete
[decomp]> print C

bool either(int4 param_1,int4 param_2,int4 param_3)

{
  return param_3 != 0 || param_2 != 0 && param_1 != 0;
}
