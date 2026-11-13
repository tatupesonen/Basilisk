// r08_cmov, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r08_cmov.a64-gcc-O2.xml

[decomp]> load function max3
Function max3: 0x00400120
[decomp]> override flow r0x4001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling max3
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling max3
Decompilation complete
[decomp]> print C

int4 max3(int4 param_1,int4 param_2,int4 param_3)

{
  if (param_1 < param_3) {
    param_1 = param_3;
  }
  if (param_1 < param_2) {
    param_1 = param_2;
  }
  return param_1;
}
[decomp]> load function iabs
Function iabs: 0x00400140
[decomp]> override flow r0x4001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling iabs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling iabs
Decompilation complete
[decomp]> print C

int4 iabs(int4 param_1)

{
  int4 iVar1;
  
  iVar1 = -param_1;
  if (-1 < param_1) {
    iVar1 = param_1;
  }
  return iVar1;
}
[decomp]> load function clamp
Function clamp: 0x0040014c
[decomp]> override flow r0x4001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clamp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clamp
Decompilation complete
[decomp]> print C

int4 clamp(int4 param_1,int4 param_2,int4 param_3)

{
  if (param_1 < param_2) {
    return param_2;
  }
  if (param_3 < param_1) {
    param_1 = param_3;
  }
  return param_1;
}
[decomp]> load function sign
Function sign: 0x00400168
[decomp]> override flow r0x4001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sign
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sign
Decompilation complete
[decomp]> print C

int4 sign(int4 param_1)

{
  return (uint4)(0 < param_1) + (param_1 >> 0x1f);
}
[decomp]> load function count_if
Function count_if: 0x00400180
[decomp]> override flow r0x4001f8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> override flow r0x400220 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_if
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_if
Decompilation complete
[decomp]> print C

int4 count_if(int4 *param_1,uint4 param_2,int4 param_3)

{
  int4 iVar1;
  int4 *piVar3;
  int4 *piVar2;
  
  if ((int4)param_2 < 1) {
    return 0;
  }
  iVar1 = 0;
  piVar2 = param_1;
  do {
    piVar3 = piVar2 + 1;
    if (param_3 <= *piVar2) {
      iVar1 = iVar1 + 1;
    }
    piVar2 = piVar3;
  } while (piVar3 != param_1 + param_2);
  return iVar1;
}
