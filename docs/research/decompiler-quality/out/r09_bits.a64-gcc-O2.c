// r09_bits, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r09_bits.a64-gcc-O2.xml

[decomp]> load function bswap
Function bswap: 0x00401000
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bswap
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bswap
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void bswap(void)

{
  bool bVar1;
  xunknown8 *in_x4;
  xunknown8 in_x9;
  xunknown8 in_d6;
  xunknown8 in_d22;
  
  bVar1 = (bool)ExclusiveMonitorPass(in_x4,0x10);
  if (bVar1) {
    *in_x4 = in_x9;
    ExclusiveMonitorsStatus();
  }
  NEON_umax(in_d22,in_d6,2);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function rotl
Function rotl: 0x00401010
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling rotl
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling rotl
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void rotl(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function popcnt
Function popcnt: 0x00401020
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling popcnt
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling popcnt
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void popcnt(void)

{
  xunknown8 in_x17;
  xunknown1 in_z17 [32];
  xunknown4 in_p4;
  
  SVE_ld1rw(in_z17,in_p4,in_x17,0x20);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function clz
Function clz: 0x00401040
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clz
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clz
Decompilation complete
[decomp]> print C

void clz(void)

{
  code *pcVar1;
  
                    /* WARNING: Does not return */
  pcVar1 = (code *)UndefinedInstructionException(0x20b8,0x401040);
  (*pcVar1)();
}
[decomp]> load function align_up
Function align_up: 0x00401050
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling align_up
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling align_up
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void align_up(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function is_pow2
Function is_pow2: 0x00401060
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4010ba callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_pow2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_pow2
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void is_pow2(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
