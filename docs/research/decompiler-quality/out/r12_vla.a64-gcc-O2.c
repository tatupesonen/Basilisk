// r12_vla, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r12_vla.a64-gcc-O2.xml

[decomp]> load function reverse_print
Function reverse_print: 0x00401000
[decomp]> override flow r0x401096 callreturn
Successfully added flow override
[decomp]> override flow r0x4010b0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling reverse_print
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling reverse_print
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void reverse_print(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
