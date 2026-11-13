// r15_globals, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r15_globals.x64-clang-O2.xml

[decomp]> load function bump
Function bump: 0x00200120
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bump
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bump
Decompilation complete
[decomp]> print C

void bump(int4 param_1)

{
  counter = counter + param_1;
  *(int4 *)(history + (uint8)(counter & 0x1f) * 4) = param_1;
  return;
}
[decomp]> load function lookup_name
Function lookup_name: 0x00200140
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling lookup_name
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling lookup_name
Decompilation complete
[decomp]> print C

xunknown8 lookup_name(int4 param_1)

{
  xunknown1 *pxVar1;
  
  pxVar1 = table;
  if (((((table._0_4_ == param_1) || (pxVar1 = table + 0x10, table._16_4_ == param_1)) ||
       (pxVar1 = table + 0x20, table._32_4_ == param_1)) ||
      ((pxVar1 = table + 0x30, table._48_4_ == param_1 ||
       (pxVar1 = table + 0x40, table._64_4_ == param_1)))) ||
     ((pxVar1 = table + 0x50, table._80_4_ == param_1 ||
      ((pxVar1 = table + 0x60, table._96_4_ == param_1 ||
       (pxVar1 = table + 0x70, table._112_4_ == param_1)))))) {
    return *(xunknown8 *)(pxVar1 + 8);
  }
  return 0;
}
