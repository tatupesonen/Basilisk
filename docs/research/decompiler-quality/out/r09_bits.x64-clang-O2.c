// r09_bits, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r09_bits.x64-clang-O2.xml

[decomp]> load function bswap
Function bswap: 0x00200120
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling bswap
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling bswap
Decompilation complete
[decomp]> print C

uint4 bswap(uint4 param_1)

{
  return param_1 >> 0x18 | (param_1 & 0xff0000) >> 8 | (param_1 & 0xff00) << 8 | param_1 << 0x18;
}
[decomp]> load function rotl
Function rotl: 0x00200130
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling rotl
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling rotl
Decompilation complete
[decomp]> print C

uint4 rotl(uint4 param_1,uint1 param_2)

{
  return param_1 << (param_2 & 0x1f) | param_1 >> 0x20 - (param_2 & 0x1f);
}
[decomp]> load function popcnt
Function popcnt: 0x00200140
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling popcnt
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling popcnt
Decompilation complete
[decomp]> print C

int4 popcnt(uint8 param_1)

{
  int4 iVar1;
  
  iVar1 = 0;
  for (; param_1 != 0; param_1 = param_1 & param_1 - 1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}
[decomp]> load function clz
Function clz: 0x00200160
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clz
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clz
Decompilation complete
[decomp]> print C

uint4 clz(uint4 param_1)

{
  uint4 uVar1;
  
  uVar1 = 0x1f;
  if (param_1 != 0) {
    for (; param_1 >> uVar1 == 0; uVar1 = uVar1 - 1) {
    }
  }
  return uVar1 ^ 0x1f;
}
[decomp]> load function align_up
Function align_up: 0x00200170
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling align_up
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling align_up
Decompilation complete
[decomp]> print C

uint8 align_up(int8 param_1)

{
  return param_1 + 0xfU & 0xfffffffffffffff0;
}
[decomp]> load function is_pow2
Function is_pow2: 0x00200180
[decomp]> override flow r0x200230 callreturn
Successfully added flow override
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling is_pow2
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling is_pow2
Decompilation complete
[decomp]> print C

bool is_pow2(uint4 param_1)

{
  if (param_1 == 0) {
    return false;
  }
  return (param_1 & param_1 - 1) == 0;
}
