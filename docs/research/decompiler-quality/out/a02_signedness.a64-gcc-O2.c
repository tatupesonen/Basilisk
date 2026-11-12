// a02_signedness, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a02_signedness.a64-gcc-O2.xml

[decomp]> load function half
Function half: 0x00401000
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling half
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling half
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void half(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function avg
Function avg: 0x00401010
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling avg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling avg
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void avg(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function is_upper
Function is_upper: 0x00401020
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_upper
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_upper
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void is_upper(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function count_neg
Function count_neg: 0x00401030
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_neg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_neg
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void count_neg(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
