// r17_temps, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r17_temps.a64-gcc-O2.xml

[decomp]> load function checksum
Function checksum: 0x00401000
[decomp]> override flow r0x401110 callreturn
Successfully added flow override
[decomp]> override flow r0x40112a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling checksum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling checksum
Decompilation complete
[decomp]> print C

void checksum(void)

{
  code *pcVar1;
  xunknown1 in_z20 [32];
  xunknown4 in_p5;
  
  SVE_prfb(5,in_p5,in_z20,0xf);
                    /* WARNING: Does not return */
  pcVar1 = (code *)UndefinedInstructionException(0x88,0x401004);
  (*pcVar1)();
}
[decomp]> load function update
Function update: 0x004010a0
[decomp]> override flow r0x401110 callreturn
Successfully added flow override
[decomp]> override flow r0x40112a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling update
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling update
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void update(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
