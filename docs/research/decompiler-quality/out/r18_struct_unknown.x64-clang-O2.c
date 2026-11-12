// r18_struct_unknown, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r18_struct_unknown.x64-clang-O2.xml

[decomp]> load function init_acct
Function init_acct: 0x00200120
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling init_acct
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling init_acct
Decompilation complete
[decomp]> print C

void init_acct(xunknown8 *param_1,xunknown8 param_2)

{
  *param_1 = 0;
  param_1[1] = param_2;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  return;
}
[decomp]> load function total
Function total: 0x00200140
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling total
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling total
Decompilation complete
[decomp]> print C

int8 total(int8 *param_1)

{
  int8 iVar1;
  
  iVar1 = 0;
  for (; param_1 != (int8 *)0x0; param_1 = (int8 *)param_1[5]) {
    if ((*(uint1 *)((int8)param_1 + 0x14) & 2) == 0) {
      iVar1 = iVar1 + *param_1;
    }
  }
  return iVar1;
}
