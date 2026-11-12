// r05_divmod, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r05_divmod.a64-gcc-O2.xml

[decomp]> load function udiv7
Function udiv7: 0x00401000
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling udiv7
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling udiv7
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void udiv7(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function sdiv7
Function sdiv7: 0x00401020
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sdiv7
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sdiv7
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sdiv7(void)

{
  xunknown1 in_z3 [32];
  xunknown1 in_z19 [32];
  xunknown4 in_p0;
  xunknown4 in_p9;
  
  LOAcquire();
  SVE_cmphs(in_p9,in_p0,in_z3,in_z19);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function umod10
Function umod10: 0x00401040
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling umod10
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling umod10
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void umod10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function sdiv64
Function sdiv64: 0x00401060
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sdiv64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sdiv64
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sdiv64(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function divisible3
Function divisible3: 0x00401080
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling divisible3
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling divisible3
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void divisible3(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function digits
Function digits: 0x004010a0
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling digits
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling digits
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void digits(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function to_hms
Function to_hms: 0x004010e0
[decomp]> override flow r0x401154 callreturn
Successfully added flow override
[decomp]> override flow r0x40116e callreturn
Successfully added flow override
[decomp]> decompile
Decompiling to_hms
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling to_hms
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void to_hms(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
