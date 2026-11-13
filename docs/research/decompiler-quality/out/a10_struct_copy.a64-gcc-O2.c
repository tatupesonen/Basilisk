// a10_struct_copy, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a10_struct_copy.a64-gcc-O2.xml

[decomp]> load function copy_struct
Function copy_struct: 0x00400120
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling copy_struct
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling copy_struct
Decompilation complete
[decomp]> print C

void copy_struct(xunknown8 *param_1,xunknown8 *param_2)

{
  xunknown8 xVar1;
  xunknown8 xVar2;
  xunknown8 xVar3;
  xunknown8 xVar4;
  xunknown8 xVar5;
  
  xVar5 = param_2[5];
  xVar4 = param_2[1];
  xVar3 = *param_2;
  xVar2 = param_2[3];
  xVar1 = param_2[2];
  param_1[4] = param_2[4];
  param_1[5] = xVar5;
  param_1[1] = xVar4;
  *param_1 = xVar3;
  param_1[3] = xVar2;
  param_1[2] = xVar1;
  return;
}
[decomp]> load function zero_init
Function zero_init: 0x00400140
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling zero_init
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling zero_init
Decompilation complete
[decomp]> print C

void zero_init(void)

{
  xunknown8 xStack_30;
  xunknown8 xStack_28;
  xunknown8 xStack_20;
  xunknown8 xStack_18;
  xunknown8 xStack_10;
  xunknown8 xStack_8;
  
  xStack_18 = 0;
  xStack_30 = 0;
  xStack_28 = 0;
  xStack_20 = 7;
  xStack_10 = 0;
  xStack_8 = 0;
  ext_p(&xStack_30);
  return;
}
[decomp]> load function copy16
Function copy16: 0x0040016c
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001b4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling copy16
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling copy16
Decompilation complete
[decomp]> print C

void copy16(xunknown8 *param_1,xunknown8 *param_2)

{
  xunknown8 xVar1;
  
  xVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = xVar1;
  return;
}
