// a03_params, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a03_params.a64-gcc-O2.xml

[decomp]> load function third
Function third: 0x00401000
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling third
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling third
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void third(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function mixed
Function mixed: 0x00401010
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mixed
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mixed
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void mixed(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function area
Function area: 0x00401040
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling area
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling area
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void area(void)

{
  xunknown8 unaff_x28;
  
  MemoryCopyForward(0xb85ff000,unaff_x28,0,3,1);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function mkpair
Function mkpair: 0x00401060
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> override flow r0x4010b6 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mkpair
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mkpair
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void mkpair(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
