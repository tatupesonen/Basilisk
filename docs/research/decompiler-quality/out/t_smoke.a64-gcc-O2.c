// t_smoke, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/t_smoke.a64-gcc-O2.xml

[decomp]> load function sum
Function sum: 0x00401000
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sum(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
