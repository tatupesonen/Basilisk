// r07_strings, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r07_strings.a64-gcc-O2.xml

[decomp]> load function log_it
Function log_it: 0x00401000
[decomp]> override flow r0x401020 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling log_it
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling log_it
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void log_it(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function stack_string
Function stack_string: 0x00401030
[decomp]> override flow r0x401020 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling stack_string
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling stack_string
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void stack_string(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function is_yes
Function is_yes: 0x00401060
[decomp]> override flow r0x401020 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> override flow r0x4010c4 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_yes
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_yes
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void is_yes(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
