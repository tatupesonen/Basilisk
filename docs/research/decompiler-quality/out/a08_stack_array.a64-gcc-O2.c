// a08_stack_array, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a08_stack_array.a64-gcc-O2.xml

[decomp]> load function local_array
Function local_array: 0x00401000
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling local_array
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling local_array
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void local_array(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function local_struct
Function local_struct: 0x00401020
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling local_struct
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling local_struct
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void local_struct(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
