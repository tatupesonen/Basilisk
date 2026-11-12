// r06_canary, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r06_canary.a64-gcc-O2.xml

[decomp]> load function greet
Function greet: 0x00401000
[decomp]> override flow r0x401080 callreturn
Successfully added flow override
[decomp]> override flow r0x40109a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling greet
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling greet
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void greet(void)

{
  xunknown1 in_z2 [32];
  xunknown1 in_z8 [32];
  xunknown4 in_p6;
  
  SVE_fmsb(in_z8,in_p6,in_z2,in_z8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
