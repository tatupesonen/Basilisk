// a06_tailcall, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a06_tailcall.x64-gcc-O2.xml

[decomp]> load function direct_tail
Function direct_tail: 0x00401000
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
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
Function indirect_tail: 0x00401010
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
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
                    /* WARNING: Could not recover jumptable at 0x00401016. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_2 + 1);
  return;
}
[decomp]> load function dispatch
Function dispatch: 0x00401020
[decomp]> override flow r0x401003 callreturn
Successfully added flow override
[decomp]> override flow r0x401060 callreturn
Successfully added flow override
[decomp]> override flow r0x40107a callreturn
Successfully added flow override
[decomp]> decompile
Decompiling dispatch
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling dispatch
Decompilation complete
[decomp]> print C

void dispatch(xunknown8 *param_1,int4 param_2,xunknown4 param_3)

{
  if (param_2 == 0) {
                    /* WARNING: Could not recover jumptable at 0x00401030. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)*param_1)(param_3);
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00401029. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)param_1[1])();
  return;
}
