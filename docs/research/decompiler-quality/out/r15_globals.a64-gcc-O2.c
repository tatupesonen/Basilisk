// r15_globals, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r15_globals.a64-gcc-O2.xml

[decomp]> load function bump
Function bump: 0x00401000
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bump
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bump
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void bump(int8 param_1)

{
  *(int8 *)(param_1 + 0x10) = param_1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function lookup_name
Function lookup_name: 0x00401020
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lookup_name
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lookup_name
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void lookup_name(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
