// r01_goto, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r01_goto.a64-gcc-O2.xml

[decomp]> load function classify
Function classify: 0x00401000
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling classify
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling classify
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void classify(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function parse_kv
Function parse_kv: 0x00401060
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling parse_kv
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling parse_kv
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void parse_kv(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function cleanup
Function cleanup: 0x00401110
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling cleanup
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling cleanup
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void cleanup(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
