// a15_struct_known, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a15_struct_known.a64-gcc-O2.xml

[decomp]> load function total
Low-level ERROR: Bytes at 0x004feed0 are not mapped
Unable to proceed with function: total
[decomp]> override flow r0x4010c2 callreturn
Execution error: No function selected
[decomp]> override flow r0x4010dc callreturn
Execution error: No function selected
[decomp]> decompile
Execution error: No function selected
[decomp]> decompile
Execution error: No function selected
[decomp]> print C
Execution error: No function selected
[decomp]> load function find
Function find: 0x00401060
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> override flow r0x4010dc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

item * find(item *v,int4 n,int4 id)

{
  xunknown8 in_x10;
  xunknown1 in_z8 [32];
  xunknown4 in_p2;
  
  SVE_ld1rsb(in_z8,in_p2,in_x10,0x38);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
