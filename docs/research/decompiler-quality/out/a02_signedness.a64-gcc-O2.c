// a02_signedness, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a02_signedness.a64-gcc-O2.xml

[decomp]> load function half
Function half: 0x00400120
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling half
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling half
Decompilation complete
[decomp]> print C

int4 half(int4 param_1)

{
  return param_1 / 2;
}
[decomp]> load function avg
Function avg: 0x0040012c
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling avg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling avg
Decompilation complete
[decomp]> print C

int4 avg(int4 param_1,int4 param_2)

{
  return (param_1 + param_2) / 2;
}
[decomp]> load function is_upper
Function is_upper: 0x00400140
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_upper
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_upper
Decompilation complete
[decomp]> print C

bool is_upper(char param_1)

{
  return (uint1)(param_1 + 0xbfU) < 0x1a;
}
[decomp]> load function count_neg
Function count_neg: 0x00400160
[decomp]> override flow r0x4001c4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001c8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001ec callreturn
Successfully added flow override
[decomp]> decompile
Decompiling count_neg
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling count_neg
Decompilation complete
[decomp]> print C

int4 count_neg(char *param_1,uint4 param_2)

{
  int4 iVar1;
  char *pcVar3;
  char *pcVar2;
  
  if (param_2 == 0) {
    return 0;
  }
  iVar1 = 0;
  pcVar3 = param_1;
  do {
    pcVar2 = pcVar3 + 1;
    iVar1 = iVar1 - ((int4)*pcVar3 >> 0x1f);
    pcVar3 = pcVar2;
  } while (pcVar2 != param_1 + param_2);
  return iVar1;
}
