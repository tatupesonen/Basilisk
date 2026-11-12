// a15_struct_known, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a15_struct_known.a64-gcc-O2.xml

[decomp]> load function total
Function total: 0x00400120
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x400200 callreturn
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
  float8 *pfVar2;
  float8 *pfVar1;
  float8 fVar3;
  
  if (n < 1) {
    return 0.0;
  }
  fVar3 = 0.0;
  pfVar1 = &v->w;
  do {
    pfVar2 = pfVar1 + 4;
    fVar3 = fVar3 + *pfVar1;
    pfVar1 = pfVar2;
  } while (pfVar2 != &v->w + (uint8)(uint4)n * 4);
  return fVar3;
}
[decomp]> load function find
Function find: 0x00400160
[decomp]> override flow r0x4001d8 callreturn
Successfully added flow override
[decomp]> override flow r0x4001dc callreturn
Successfully added flow override
[decomp]> override flow r0x400200 callreturn
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
  int4 *piVar1;
  item *piVar2;
  item *piVar3;
  
  if (0 < n) {
    piVar3 = v + (uint4)n;
    do {
      piVar1 = &v->id;
      piVar2 = v;
      v = v + 1;
      if (*piVar1 == id) {
        return piVar2;
      }
    } while (v != piVar3);
  }
  return (item *)0x0;
}
