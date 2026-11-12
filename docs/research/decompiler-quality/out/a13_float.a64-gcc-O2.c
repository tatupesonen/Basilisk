// a13_float, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a13_float.a64-gcc-O2.xml

[decomp]> load function fmin2
Function fmin2: 0x00401000
[decomp]> override flow r0x4010a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fmin2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fmin2
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void fmin2(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function fabs2
Function fabs2: 0x00401010
[decomp]> override flow r0x4010a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling fabs2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling fabs2
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void fabs2(void)

{
  bool bVar1;
  xunknown8 in_x3;
  xunknown8 *unaff_x27;
  
  Hint_Prefetch(0x451200,0,3,0);
  bVar1 = (bool)ExclusiveMonitorPass(unaff_x27,0x10);
  if (bVar1) {
    *unaff_x27 = 0x787b000000000000;
    unaff_x27[1] = in_x3;
    ExclusiveMonitorsStatus();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function to_int
Function to_int: 0x00401040
[decomp]> override flow r0x4010a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling to_int
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling to_int
Decompilation complete
[decomp]> print C

void to_int(void)

{
  code *pcVar1;
  xunknown1 in_z19 [32];
  xunknown4 in_p9;
  
  SVE_cpy(in_z19,in_p9,0x7f,0);
                    /* WARNING: Does not return */
  pcVar1 = (code *)UndefinedInstructionException(0xfc8,0x401044);
  (*pcVar1)();
}
[decomp]> load function lerp
Function lerp: 0x00401060
[decomp]> override flow r0x4010a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lerp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lerp
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void lerp(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function below
Function below: 0x00401070
[decomp]> override flow r0x4010a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4010c2 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling below
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling below
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void below(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
