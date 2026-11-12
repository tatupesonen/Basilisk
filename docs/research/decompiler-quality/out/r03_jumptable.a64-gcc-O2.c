// r03_jumptable, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r03_jumptable.a64-gcc-O2.xml

[decomp]> load function interp
Function interp: 0x00401010
[decomp]> override flow r0x4010e8 callreturn
Successfully added flow override
[decomp]> override flow r0x401102 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling interp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling interp
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void interp(xunknown2 param_1)

{
  bool bVar1;
  xunknown2 *unaff_x28;
  
  bVar1 = (bool)ExclusiveMonitorPass(unaff_x28,0x10);
  if (bVar1) {
    *unaff_x28 = param_1;
    ExclusiveMonitorsStatus();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
