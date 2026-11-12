// r16_simd, a64-gcc-O3 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r16_simd.a64-gcc-O3.xml

[decomp]> load function add_arrays
Function add_arrays: 0x00400120
[decomp]> override flow r0x400204 callreturn
Successfully added flow override
[decomp]> override flow r0x400208 callreturn
Successfully added flow override
[decomp]> override flow r0x40022c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling add_arrays
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling add_arrays
Decompilation complete
[decomp]> print C

void add_arrays(int8 param_1,int8 param_2,int8 param_3,uint4 param_4)

{
  int8 iVar1;
  float4 *pfVar2;
  int8 iVar3;
  uint4 uVar4;
  xunknown8 xVar5;
  xunknown8 xVar6;
  float4 fVar7;
  float4 fVar8;
  
  if (0 < (int4)param_4) {
    if (param_4 - 1 < 3) {
      uVar4 = 0;
    }
    else {
      iVar3 = 0;
      do {
        pfVar2 = (float4 *)(param_2 + iVar3);
        fVar7 = *pfVar2;
        fVar8 = pfVar2[1];
        xVar6 = ((xunknown8 *)(param_3 + iVar3))[1];
        xVar5 = *(xunknown8 *)(param_3 + iVar3);
        ((xunknown8 *)(param_1 + iVar3))[1] =
             CONCAT44(pfVar2[3] + (float4)((uint8)xVar6 >> 0x20),pfVar2[2] + (float4)xVar6);
        *(xunknown8 *)(param_1 + iVar3) =
             CONCAT44(fVar8 + (float4)((uint8)xVar5 >> 0x20),fVar7 + (float4)xVar5);
        iVar3 = iVar3 + 0x10;
      } while (iVar3 != (uint8)(param_4 >> 2) * 0x10);
      uVar4 = param_4 & 0xfffffffc;
      if (param_4 == uVar4) {
        return;
      }
    }
    iVar3 = (uint8)uVar4 * 4;
    *(float4 *)(param_1 + iVar3) = *(float4 *)(param_2 + iVar3) + *(float4 *)(param_3 + iVar3);
    if ((int4)(uVar4 + 1) < (int4)param_4) {
      iVar1 = iVar3 + 4;
      *(float4 *)(param_1 + iVar1) = *(float4 *)(param_2 + iVar1) + *(float4 *)(param_3 + iVar1);
      if ((int4)(uVar4 + 2) < (int4)param_4) {
        iVar3 = iVar3 + 8;
        *(float4 *)(param_1 + iVar3) = *(float4 *)(param_3 + iVar3) + *(float4 *)(param_2 + iVar3);
      }
    }
  }
  return;
}
