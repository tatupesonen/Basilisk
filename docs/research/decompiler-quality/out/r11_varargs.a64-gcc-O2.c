// r11_varargs, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r11_varargs.a64-gcc-O2.xml

[decomp]> load function sum_ints
Function sum_ints: 0x00401000
[decomp]> override flow r0x4010cc callreturn
Successfully added flow override
[decomp]> override flow r0x4010e6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_ints
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_ints
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sum_ints(void)

{
  xunknown1 in_z4 [32];
  xunknown1 in_z10 [32];
  xunknown4 in_p3;
  xunknown4 in_p8;
  
  SVE_cmpge(in_p8,in_p3,in_z10,in_z4);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
