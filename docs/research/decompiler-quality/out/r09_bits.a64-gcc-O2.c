// r09_bits, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r09_bits.a64-gcc-O2.xml

[decomp]> load function bswap
Function bswap: 0x00400120
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
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
  uint4 uVar1;
  
  uVar1 = (param_1 & 0xff00ff00) >> 8 | (param_1 & 0xff00ff) << 8;
  return uVar1 >> 0x10 | uVar1 << 0x10;
}
[decomp]> load function rotl
Function rotl: 0x00400128
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling rotl
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling rotl
Decompilation complete
[decomp]> print C

uint4 rotl(uint4 param_1,int4 param_2)

{
  return param_1 >> (-param_2 & 0x1fU) | param_1 << 0x20 - (-param_2 & 0x1fU);
}
[decomp]> load function popcnt
Function popcnt: 0x00400140
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling popcnt
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling popcnt
Decompilation complete
[decomp]> print C

char popcnt(xunknown8 param_1)

{
  return POPCOUNT((char)param_1) + POPCOUNT((char)((uint8)param_1 >> 8)) +
         POPCOUNT((char)((uint8)param_1 >> 0x10)) + POPCOUNT((char)((uint8)param_1 >> 0x18)) +
         POPCOUNT((char)((uint8)param_1 >> 0x20)) + POPCOUNT((char)((uint8)param_1 >> 0x28)) +
         POPCOUNT((char)((uint8)param_1 >> 0x30)) + POPCOUNT((char)((uint8)param_1 >> 0x38));
}
[decomp]> load function clz
Function clz: 0x00400160
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
Successfully added flow override
[decomp]> decompile
Decompiling clz
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling clz
Decompilation complete
[decomp]> print C

int8 clz(xunknown4 param_1)

{
  return LZCOUNT(param_1);
}
[decomp]> load function align_up
Function align_up: 0x00400168
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
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
Function is_pow2: 0x00400180
[decomp]> override flow r0x4001d4 callreturn
Successfully added flow override
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001fc callreturn
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
  return (param_1 - 1 & param_1) == 0;
}
