// a13_float, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a13_float.a64-gcc-O2.xml

[decomp]> load function fmin2
Function fmin2: 0x00400120
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fmin2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fmin2
Decompilation complete
[decomp]> print C

xunknown1  [16] fmin2(float8 param_1,float8 param_2)

{
  xunknown1 axVar1 [16];
  
  if (param_2 <= param_1) {
    param_1 = param_2;
  }
  axVar1._8_8_ = 0;
  axVar1._0_8_ = param_1;
  return axVar1;
}
[decomp]> load function fabs2
Function fabs2: 0x0040012c
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fabs2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fabs2
Decompilation complete
[decomp]> print C

xunknown1  [16] fabs2(xunknown1 param_1 [16])

{
  xunknown1 axVar1 [16];
  
  if (0.0 <= param_1._0_8_) {
    return param_1;
  }
  axVar1._0_8_ = -param_1._0_8_;
  axVar1._8_8_ = 0;
  return axVar1;
}
[decomp]> load function to_int
Function to_int: 0x00400140
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
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
Function lerp: 0x00400160
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
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
  return param_1 + param_3 * (param_2 - param_1);
}
[decomp]> load function below
Function below: 0x0040016c
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
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
