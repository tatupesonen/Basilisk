// a08_stack_array, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a08_stack_array.a64-gcc-O2.xml

[decomp]> load function local_array
Function local_array: 0x00400120
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling local_array
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling local_array
Decompilation complete
[decomp]> print C

int4 local_array(void)

{
  xunknown1 axStack_10 [4];
  int4 iStack_c;
  int4 iStack_4;
  
  ext_p(axStack_10);
  return iStack_c + iStack_4;
}
[decomp]> load function local_struct
Function local_struct: 0x00400144
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling local_struct
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling local_struct
Decompilation complete
[decomp]> print C

int8 local_struct(xunknown4 param_1)

{
  xunknown4 xStack_18;
  int4 iStack_14;
  int8 iStack_10;
  xunknown8 xStack_8;
  
  iStack_14 = 3;
  iStack_10 = 0x1000;
  xStack_8 = 0x6b73696c69736162;
  xStack_18 = param_1;
  ext_p(&xStack_18);
  return iStack_14 + iStack_10;
}
