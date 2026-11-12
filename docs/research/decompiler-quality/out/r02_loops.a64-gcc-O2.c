// r02_loops, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r02_loops.a64-gcc-O2.xml

[decomp]> load function fill
Function fill: 0x00401000
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fill
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fill
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void fill(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function find_first
Function find_first: 0x00401020
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find_first
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find_first
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void find_first(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function count_pairs
Function count_pairs: 0x00401060
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_pairs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_pairs
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void count_pairs(void)

{
  xunknown1 in_z5 [32];
  xunknown1 in_z20 [32];
  xunknown1 in_z30 [32];
  xunknown4 in_p5;
  
  SVE_fnmsb(in_z5,in_p5,in_z20,in_z30);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function my_strlen
Function my_strlen: 0x004010d0
[decomp]> override flow r0x401122 callreturn
Successfully added flow override
[decomp]> override flow r0x40113c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling my_strlen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling my_strlen
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void my_strlen(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
