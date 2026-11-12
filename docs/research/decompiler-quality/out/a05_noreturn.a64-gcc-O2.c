// a05_noreturn, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a05_noreturn.a64-gcc-O2.xml

[decomp]> load function checked_get
Function checked_get: 0x00401020
[decomp]> override flow r0x40107c callreturn
Successfully added flow override
[decomp]> override flow r0x401096 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling checked_get
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling checked_get
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void checked_get(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function die
Function die: 0x00401000
[decomp]> override flow r0x40107c callreturn
Successfully added flow override
[decomp]> override flow r0x401096 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling die
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling die
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void die(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function after
Function after: 0x00401040
[decomp]> override flow r0x40107c callreturn
Successfully added flow override
[decomp]> override flow r0x401096 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling after
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling after
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void after(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
