// a15_struct_known, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/a15_struct_known.x64-clang-O2.xml

[decomp]> load function total
Function total: 0x00200120
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> override flow r0x2002b0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling total
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling total
Decompilation complete
[decomp]> print C

float8 total(item *v,int4 n)

{
  uint8 uVar1;
  uint8 uVar2;
  float8 *pfVar3;
  float8 fVar4;
  
  if (n < 1) {
    return 0.0;
  }
  if ((uint4)n < 4) {
    fVar4 = 0.0;
    uVar1 = 0;
  }
  else {
    pfVar3 = &v[3].w;
    fVar4 = 0.0;
    uVar1 = 0;
    do {
      fVar4 = fVar4 + pfVar3[-0xc] + pfVar3[-8] + pfVar3[-4] + *pfVar3;
      uVar1 = uVar1 + 4;
      pfVar3 = pfVar3 + 0x10;
    } while ((n & 0x7ffffffc) != uVar1);
  }
  if ((n & 3U) != 0) {
    uVar2 = 0;
    do {
      fVar4 = fVar4 + *(float8 *)(v[uVar1].name + uVar2 + 0x14);
      uVar2 = uVar2 + 0x20;
    } while ((n & 3U) << 5 != uVar2);
  }
  return fVar4;
}
[decomp]> load function find
Function find: 0x002001a0
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> override flow r0x2002b0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling find
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling find
Decompilation complete
[decomp]> print C

item * find(item *v,int4 n,int4 id)

{
  uint8 uVar1;
  
  if (0 < n) {
    uVar1 = (uint8)(uint4)n;
    do {
      if (v->id == id) {
        return v;
      }
      v = v + 1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  return (item *)0x0;
}
