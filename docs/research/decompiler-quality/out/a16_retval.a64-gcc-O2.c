// a16_retval, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a16_retval.a64-gcc-O2.xml

[decomp]> load function inc
Function inc: 0x00401000
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling inc
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling inc
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void inc(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function find_idx
Function find_idx: 0x00401010
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_idx
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_idx
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void find_idx(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function after_call
Function after_call: 0x00401040
[decomp]> override flow r0x40108a callreturn
Successfully added flow override
[decomp]> override flow r0x4010a4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling after_call
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling after_call
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void after_call(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
