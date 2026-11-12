// a07_switch, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a07_switch.a64-gcc-O2.xml

[decomp]> load function dense
Function dense: 0x00401000
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dense
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dense
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void dense(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function sparse
Function sparse: 0x00401070
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sparse
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sparse
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sparse(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function bittest
Function bittest: 0x004010f0
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bittest
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bittest
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void bittest(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function lookup
Function lookup: 0x00401110
[decomp]> override flow r0x401015 callreturn
Successfully added flow override
[decomp]> override flow r0x401025 callreturn
Successfully added flow override
[decomp]> override flow r0x401035 callreturn
Successfully added flow override
[decomp]> override flow r0x401045 callreturn
Successfully added flow override
[decomp]> override flow r0x401055 callreturn
Successfully added flow override
[decomp]> override flow r0x401065 callreturn
Successfully added flow override
[decomp]> override flow r0x40108c callreturn
Successfully added flow override
[decomp]> override flow r0x4010a7 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010d5 callreturn
Successfully added flow override
[decomp]> override flow r0x4010e5 callreturn
Successfully added flow override
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lookup
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lookup
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void lookup(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
