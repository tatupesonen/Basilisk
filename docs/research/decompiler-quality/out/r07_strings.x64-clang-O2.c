// r07_strings, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r07_strings.x64-clang-O2.xml

[decomp]> load function log_it
Function log_it: 0x00200180
[decomp]> override flow r0x20019a callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling log_it
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling log_it
Decompilation complete
[decomp]> print C

void log_it(uint8 param_1)

{
  printf("error %d: %s\n",param_1 & 0xffffffff,0x200120);
  ext_p(0x20012e);
  return;
}
[decomp]> load function stack_string
Function stack_string: 0x002001a0
[decomp]> override flow r0x20019a callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling stack_string
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling stack_string
Decompilation complete
[decomp]> print C

void stack_string(void)

{
  xunknown4 xStack_18;
  xunknown4 xStack_14;
  xunknown4 xStack_10;
  xunknown4 xStack_c;
  xunknown4 xStack_8;
  
  xStack_18 = 0x69736162;
  xStack_14 = 0x6b73696c;
  xStack_10 = 0x63656420;
  xStack_c = 0x69706d6f;
  xStack_8 = 0x72656c;
  ext_p(&xStack_18);
  return;
}
[decomp]> load function is_yes
Function is_yes: 0x002001d0
[decomp]> override flow r0x20019a callreturn
Successfully added flow override
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_yes
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_yes
Decompilation complete
[decomp]> print C

bool is_yes(char *param_1)

{
  int4 iVar1;
  
  iVar1 = strcmp(param_1,"yes");
  return iVar1 == 0;
}
