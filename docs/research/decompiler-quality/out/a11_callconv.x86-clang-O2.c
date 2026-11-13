// a11_callconv, x86-clang-O2 (x86:LE:32:default:gcc)
// Ghidra reference decomp output; inputs: frag/a11_callconv.x86-clang-O2.xml

[decomp]> load function helper
Function helper: 0x00400100
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> override flow r0x400210 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling helper
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling helper
Decompilation complete
[decomp]> print C

int4 __regparm3 helper(xunknown4 param_1,int4 param_2,int4 param_3,int4 param_4)

{
  int4 iVar1;
  
  iVar1 = ext_i(param_3 * param_2);
  return iVar1 + param_4;
}
[decomp]> load function caller
Function caller: 0x004000c0
[decomp]> override flow r0x4001b0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c0 callreturn
Successfully added flow override
[decomp]> override flow r0x400210 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling caller
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling caller
Decompilation complete
[decomp]> print C

int4 caller(xunknown4 param_1)

{
  int4 iVar1;
  int4 iVar2;
  
  iVar1 = helper(5);
  iVar2 = helper(param_1);
  return iVar2 + iVar1;
}
