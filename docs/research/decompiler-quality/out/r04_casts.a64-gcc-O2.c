// r04_casts, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r04_casts.a64-gcc-O2.xml

[decomp]> load function widen
Function widen: 0x00401000
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling widen
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling widen
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void widen(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function index8
Function index8: 0x00401020
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling index8
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling index8
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void index8(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function mulhi
Function mulhi: 0x00401030
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling mulhi
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling mulhi
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void mulhi(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function pack
Function pack: 0x00401040
[decomp]> override flow r0x401082 callreturn
Successfully added flow override
[decomp]> override flow r0x40109c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling pack
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling pack
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void pack(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
