// a06_tailcall, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a06_tailcall.a64-gcc-O2.xml

[decomp]> load function direct_tail
Function direct_tail: 0x00401000
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling direct_tail
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling direct_tail
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void direct_tail(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function indirect_tail
Function indirect_tail: 0x00401010
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling indirect_tail
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling indirect_tail
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void indirect_tail(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function dispatch
Function dispatch: 0x00401020
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dispatch
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dispatch
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void dispatch(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
