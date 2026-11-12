// r08_cmov, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r08_cmov.a64-gcc-O2.xml

[decomp]> load function max3
Function max3: 0x00401000
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling max3
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling max3
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void max3(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function iabs
Function iabs: 0x00401010
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling iabs
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling iabs
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void iabs(void)

{
  Hint_Prefetch(0x3f0f20,1,0,1);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function clamp
Function clamp: 0x00401020
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clamp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clamp
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void clamp(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function sign
Function sign: 0x00401030
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sign
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sign
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sign(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function count_if
Low-level ERROR: Bytes at 0x004fef10 are not mapped
Unable to proceed with function: count_if
[decomp]> override flow r0x4010aa callreturn
Execution error: No function selected
[decomp]> override flow r0x4010c4 callreturn
Execution error: No function selected
[decomp]> decompile
Execution error: No function selected
[decomp]> decompile
Execution error: No function selected
[decomp]> print C
Execution error: No function selected
