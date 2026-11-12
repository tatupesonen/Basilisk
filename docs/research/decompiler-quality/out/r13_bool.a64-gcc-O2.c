// r13_bool, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r13_bool.a64-gcc-O2.xml

[decomp]> load function in_range
Function in_range: 0x00401000
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling in_range
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling in_range
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void in_range(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function valid
Function valid: 0x00401020
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling valid
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling valid
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void valid(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function either
Function either: 0x00401040
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling either
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling either
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void either(void)

{
  func_0x04800e54();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
