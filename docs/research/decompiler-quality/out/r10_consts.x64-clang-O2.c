// r10_consts, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r10_consts.x64-clang-O2.xml

[decomp]> load function create
Function create: 0x00200120
[decomp]> override flow r0x20012c callreturn
Successfully added flow override
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling create
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling create
Decompilation complete
[decomp]> print C

void create(char *param_1)

{
  open(param_1,0x241,0x1a4);
  return;
}
[decomp]> load function is_space
Function is_space: 0x00200140
[decomp]> override flow r0x20012c callreturn
Successfully added flow override
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_space
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_space
Decompilation complete
[decomp]> print C

bool is_space(int4 param_1)

{
  bool bVar1;
  
  bVar1 = true;
  if ((param_1 != 9) && (param_1 != 0x20)) {
    bVar1 = param_1 == 10;
  }
  return bVar1;
}
[decomp]> load function neg
Function neg: 0x00200160
[decomp]> override flow r0x20012c callreturn
Successfully added flow override
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling neg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling neg
Decompilation complete
[decomp]> print C

int4 neg(int4 param_1)

{
  int4 iVar1;
  
  iVar1 = -2;
  if (param_1 != -1) {
    iVar1 = param_1 + -100;
  }
  return iVar1;
}
