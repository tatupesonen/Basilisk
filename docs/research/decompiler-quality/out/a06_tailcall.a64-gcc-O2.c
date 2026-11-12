// a06_tailcall, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a06_tailcall.a64-gcc-O2.xml

[decomp]> load function direct_tail
Function direct_tail: 0x00400120
[decomp]> override flow r0x400124 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
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
Function indirect_tail: 0x00400128
[decomp]> override flow r0x400124 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
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
                    /* WARNING: Could not recover jumptable at 0x00400134. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_2 + 1);
  return;
}
[decomp]> load function dispatch
Function dispatch: 0x00400140
[decomp]> override flow r0x400124 callreturn
Successfully added flow override
[decomp]> override flow r0x40019c callreturn
Successfully added flow override
[decomp]> override flow r0x4001a0 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c4 callreturn
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
                    /* WARNING: Could not recover jumptable at 0x00400160. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)*param_1)(param_3);
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00400154. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)param_1[1])();
  return;
}
