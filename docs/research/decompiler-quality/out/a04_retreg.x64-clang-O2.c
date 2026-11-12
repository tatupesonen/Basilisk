// a04_retreg, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a04_retreg.x64-clang-O2.xml

[decomp]> load function use_pair
Function use_pair: 0x00200140
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling use_pair
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling use_pair
Decompilation complete
[decomp]> print C

int8 use_pair(void)

{
  xunknown1 axVar1 [16];
  
  axVar1 = ext_pair();
  return axVar1._0_8_ * axVar1._8_8_;
}
[decomp]> load function is_ready
Function is_ready: 0x00200150
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_ready
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_ready
Decompilation complete
[decomp]> print C

xunknown8 is_ready(void)

{
  char cVar1;
  xunknown8 xVar2;
  
  cVar1 = ext_flag();
  xVar2 = 0x14;
  if (cVar1 != '\0') {
    xVar2 = 10;
  }
  return xVar2;
}
