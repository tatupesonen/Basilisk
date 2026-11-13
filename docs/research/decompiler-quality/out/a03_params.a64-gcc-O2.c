// a03_params, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a03_params.a64-gcc-O2.xml

[decomp]> load function third
Function third: 0x00400120
[decomp]> override flow r0x400198 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling third
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling third
Decompilation complete
[decomp]> print C

int4 third(xunknown8 param_1,xunknown8 param_2,int4 param_3)

{
  return param_3 * 3;
}
[decomp]> load function mixed
Function mixed: 0x00400128
[decomp]> override flow r0x400198 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mixed
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mixed
Decompilation complete
[decomp]> print C

xunknown1  [16] mixed(float8 param_1,float8 param_2,int4 param_3,int4 param_4)

{
  xunknown1 axVar1 [16];
  
  axVar1._0_8_ = (float8)param_4 * param_2 + param_1 * (float8)param_3;
  axVar1._8_8_ = 0;
  return axVar1;
}
[decomp]> load function area
Function area: 0x00400140
[decomp]> override flow r0x400198 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling area
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling area
Decompilation complete
[decomp]> print C

xunknown1  [16] area(float8 param_1,float8 param_2,float8 param_3,float8 param_4)

{
  xunknown1 axVar1 [16];
  
  axVar1._0_8_ = (param_3 - param_1) * (param_4 - param_2);
  axVar1._8_8_ = 0;
  return axVar1;
}
[decomp]> load function mkpair
Function mkpair: 0x00400150
[decomp]> override flow r0x400198 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mkpair
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mkpair
Decompilation complete
[decomp]> print C

xunknown1  [16] mkpair(int8 param_1,int8 param_2)

{
  xunknown1 axVar1 [16];
  
  axVar1._8_8_ = param_1 - param_2;
  axVar1._0_8_ = param_1 + param_2;
  return axVar1;
}
