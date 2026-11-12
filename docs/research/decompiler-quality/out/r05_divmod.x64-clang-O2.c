// r05_divmod, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r05_divmod.x64-clang-O2.xml

[decomp]> load function udiv7
Function udiv7: 0x00200120
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling udiv7
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling udiv7
Decompilation complete
[decomp]> print C

uint4 udiv7(uint4 param_1)

{
  return param_1 / 7;
}
[decomp]> load function sdiv7
Function sdiv7: 0x00200140
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sdiv7
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sdiv7
Decompilation complete
[decomp]> print C

int4 sdiv7(int4 param_1)

{
  return param_1 / 7;
}
[decomp]> load function umod10
Function umod10: 0x00200160
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling umod10
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling umod10
Decompilation complete
[decomp]> print C

uint4 umod10(uint4 param_1)

{
  return param_1 % 10;
}
[decomp]> load function sdiv64
Function sdiv64: 0x00200180
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sdiv64
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sdiv64
Decompilation complete
[decomp]> print C

int8 sdiv64(int8 param_1)

{
  return param_1 / 1000;
}
[decomp]> load function divisible3
Function divisible3: 0x002001a0
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling divisible3
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling divisible3
Decompilation complete
[decomp]> print C

bool divisible3(int4 param_1)

{
  return (uint4)(param_1 * -0x55555555) < 0x55555556;
}
[decomp]> load function digits
Function digits: 0x002001c0
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling digits
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling digits
Decompilation complete
[decomp]> print C

int4 digits(uint4 param_1)

{
  bool bVar1;
  int4 iVar2;
  
  iVar2 = 0;
  do {
    iVar2 = iVar2 + 1;
    bVar1 = 9 < param_1;
    param_1 = param_1 / 10;
  } while (bVar1);
  return iVar2;
}
[decomp]> load function to_hms
Function to_hms: 0x002001f0
[decomp]> override flow r0x2002d0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
Successfully added flow override
[decomp]> override flow r0x200330 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling to_hms
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling to_hms
Decompilation complete
[decomp]> print C

void to_hms(uint4 param_1,uint4 *param_2,uint4 *param_3,uint4 *param_4)

{
  *param_2 = param_1 / 0xe10;
  *param_3 = (param_1 % 0xe10) / 0x3c;
  *param_4 = param_1 % 0x3c;
  return;
}
