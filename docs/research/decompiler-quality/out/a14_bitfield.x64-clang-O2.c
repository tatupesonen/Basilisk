// a14_bitfield, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a14_bitfield.x64-clang-O2.xml

[decomp]> load function get_kind
Function get_kind: 0x00200120
[decomp]> override flow r0x2001d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling get_kind
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling get_kind
Decompilation complete
[decomp]> print C

int4 get_kind(uint4 *param_1)

{
  return (*param_1 >> 8) + (*param_1 & 7);
}
[decomp]> load function set_kind
Function set_kind: 0x00200130
[decomp]> override flow r0x2001d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling set_kind
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling set_kind
Decompilation complete
[decomp]> print C

void set_kind(uint4 *param_1,uint4 param_2)

{
  *param_1 = (*param_1 & 0xfffffff0) + (param_2 & 7) + 8;
  return;
}
