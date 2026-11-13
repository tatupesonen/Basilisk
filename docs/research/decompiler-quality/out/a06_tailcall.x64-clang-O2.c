// a06_tailcall, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a06_tailcall.x64-clang-O2.xml

[decomp]> load function direct_tail
Function direct_tail: 0x00200120
[decomp]> override flow r0x200122 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x2001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling direct_tail
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling direct_tail
Decompilation complete
[decomp]> print C

void direct_tail(int4 param_1)

{
  ext_i(param_1 + 1);
  return;
}
[decomp]> load function indirect_tail
Function indirect_tail: 0x00200130
[decomp]> override flow r0x200122 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x2001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling indirect_tail
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling indirect_tail
Decompilation complete
[decomp]> print C

void indirect_tail(code *UNRECOVERED_JUMPTABLE,int4 param_2)

{
                    /* WARNING: Could not recover jumptable at 0x00200136. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_2 + 1);
  return;
}
[decomp]> load function dispatch
Function dispatch: 0x00200140
[decomp]> override flow r0x200122 callreturn
Successfully added flow override
[decomp]> override flow r0x2001e0 callreturn
Successfully added flow override
[decomp]> override flow r0x2001f0 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dispatch
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dispatch
Decompilation complete
[decomp]> print C

void dispatch(int8 param_1,int4 param_2,xunknown4 param_3)

{
                    /* WARNING: Could not recover jumptable at 0x0020014c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(param_1 + (uint8)(param_2 != 0) * 8))(param_3);
  return;
}
