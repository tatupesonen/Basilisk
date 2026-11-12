// r07_strings, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r07_strings.a64-gcc-O2.xml

[decomp]> load function log_it
Function log_it: 0x00400120
[decomp]> override flow r0x40014c callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x400204 callreturn
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
  printf("error %d: %s\n",param_1 & 0xffffffff,0x400220);
  ext_p(0x400240);
  return;
}
[decomp]> load function stack_string
Function stack_string: 0x00400150
[decomp]> override flow r0x40014c callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x400204 callreturn
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
  xunknown8 xStack_18;
  xunknown8 xStack_10;
  xunknown4 xStack_8;
  
  xStack_18 = 0x6b73696c69736162;
  xStack_10 = 0x69706d6f63656420;
  xStack_8 = 0x72656c;
  ext_p(&xStack_18);
  return;
}
[decomp]> load function is_yes
Function is_yes: 0x00400180
[decomp]> override flow r0x40014c callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x4001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x400204 callreturn
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
