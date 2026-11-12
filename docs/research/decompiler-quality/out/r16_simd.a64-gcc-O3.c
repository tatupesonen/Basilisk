// r16_simd, a64-gcc-O3 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r16_simd.a64-gcc-O3.xml

[decomp]> load function add_arrays
Function add_arrays: 0x00401000
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling add_arrays
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling add_arrays
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void add_arrays(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
