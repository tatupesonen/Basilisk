// a05_noreturn, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a05_noreturn.a64-gcc-O2.xml

[decomp]> load function checked_get
Function checked_get: 0x00400140
[decomp]> override flow r0x4001a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling checked_get
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling checked_get
Decompilation complete
[decomp]> print C

int4 checked_get(int4 *param_1)

{
  int4 iVar1;
  
  if (param_1 == (int4 *)0x0) {
    iVar1 = die(0x4001e8);
    return iVar1 * 7 + 1;
  }
  return *param_1;
}
[decomp]> load function die
Function die: 0x00400120
[decomp]> override flow r0x4001a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling die
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling die
Decompilation complete
[decomp]> print C

void die(char *param_1)

{
  puts(param_1);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
[decomp]> load function after
Function after: 0x00400160
[decomp]> override flow r0x4001a8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ac callreturn
Successfully added flow override
[decomp]> override flow r0x4001d0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling after
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling after
Decompilation complete
[decomp]> print C

int4 after(int4 param_1)

{
  return param_1 * 7 + 1;
}
