// r13_bool, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r13_bool.a64-gcc-O2.xml

[decomp]> load function in_range
Function in_range: 0x00400120
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
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
  return param_2 <= param_1 && param_1 <= param_3;
}
[decomp]> load function valid
Function valid: 0x00400130
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
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
  if (param_1 == (int4 *)0x0 || param_2 < 1) {
    return false;
  }
  return *param_1 == param_2;
}
[decomp]> load function either
Function either: 0x00400160
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d4 callreturn
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
  return param_1 != 0 && param_2 != 0 || param_3 != 0;
}
