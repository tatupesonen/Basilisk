// a05_noreturn, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a05_noreturn.x64-clang-O2.xml

[decomp]> load function checked_get
Function checked_get: 0x00200130
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
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
    iVar1 = 0x200120;
    die(0x200120);
    return iVar1 * 7 + 1;
  }
  return *param_1;
}
[decomp]> load function die
Function die: 0x00200160
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
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
Function after: 0x00200150
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
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
