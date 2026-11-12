// r06_canary, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r06_canary.a64-gcc-O2.xml

[decomp]> load function greet
Function greet: 0x00400120
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001cc callreturn
Successfully added flow override
[decomp]> override flow r0x4001f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling greet
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling greet
Decompilation complete
[decomp]> print C

int4 greet(char *param_1)

{
  int4 iVar1;
  char acStack_58 [64];
  int8 iStack_18;
  
  iStack_18 = iRam000000000041ffe8;
  builtin_strncpy(acStack_58,"hello, ",8);
  strcpy(acStack_58 + 7,param_1);
  iVar1 = puts(acStack_58);
  if (iStack_18 != iRam000000000041ffe8) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
