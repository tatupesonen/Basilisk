// a13_float, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a13_float.x64-clang-O2.xml

[decomp]> load function fmin2
Function fmin2: 0x00200140
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fmin2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fmin2
Decompilation complete
[decomp]> print C

float8 fmin2(float8 param_1,float8 param_2)

{
  if (param_2 <= param_1) {
    param_1 = param_2;
  }
  return param_1;
}
[decomp]> load function fabs2
Function fabs2: 0x00200150
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fabs2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fabs2
Decompilation complete
[decomp]> print C

float8 fabs2(float8 param_1)

{
  float8 fVar1;
  
  fVar1 = -param_1;
  if (-param_1 <= param_1) {
    fVar1 = param_1;
  }
  return fVar1;
}
[decomp]> load function to_int
Function to_int: 0x00200170
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling to_int
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling to_int
Decompilation complete
[decomp]> print C

int4 to_int(float4 param_1)

{
  return (int4)(param_1 * 100.0 + 0.5);
}
[decomp]> load function lerp
Function lerp: 0x00200190
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lerp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lerp
Decompilation complete
[decomp]> print C

float4 lerp(float4 param_1,float4 param_2,float4 param_3)

{
  return param_1 + (param_2 - param_1) * param_3;
}
[decomp]> load function below
Function below: 0x002001a0
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling below
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling below
Decompilation complete
[decomp]> print C

bool below(float8 param_1,float8 param_2)

{
  return param_1 < param_2;
}
