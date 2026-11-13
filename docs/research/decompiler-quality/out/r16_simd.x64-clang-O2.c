// r16_simd, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r16_simd.x64-clang-O2.xml

[decomp]> load function add_arrays
Function add_arrays: 0x00200120
[decomp]> override flow r0x200240 callreturn
Successfully added flow override
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
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
  float4 *pfVar1;
  float4 *pfVar2;
  float4 *pfVar3;
  float4 fVar4;
  float4 fVar5;
  float4 fVar6;
  float4 fVar7;
  float4 fVar8;
  float4 fVar9;
  float4 fVar10;
  float4 fVar11;
  float4 fVar12;
  float4 fVar13;
  float4 fVar14;
  float4 fVar15;
  float4 fVar16;
  float4 fVar17;
  uint8 uVar18;
  int8 iVar19;
  
  if (0 < (int4)param_4) {
    if (param_4 < 8) {
      uVar18 = 0;
    }
    else {
      uVar18 = (uint8)(param_4 & 0x7ffffff8);
      iVar19 = 0;
      do {
        pfVar1 = (float4 *)(param_2 + iVar19);
        fVar4 = pfVar1[1];
        fVar5 = pfVar1[2];
        fVar6 = pfVar1[3];
        pfVar2 = (float4 *)(param_2 + 0x10 + iVar19);
        fVar7 = *pfVar2;
        fVar8 = pfVar2[1];
        fVar9 = pfVar2[2];
        fVar10 = pfVar2[3];
        pfVar2 = (float4 *)(param_3 + iVar19);
        fVar11 = pfVar2[1];
        fVar12 = pfVar2[2];
        fVar13 = pfVar2[3];
        pfVar3 = (float4 *)(param_3 + 0x10 + iVar19);
        fVar14 = *pfVar3;
        fVar15 = pfVar3[1];
        fVar16 = pfVar3[2];
        fVar17 = pfVar3[3];
        pfVar3 = (float4 *)(param_1 + iVar19);
        *pfVar3 = *pfVar2 + *pfVar1;
        pfVar3[1] = fVar11 + fVar4;
        pfVar3[2] = fVar12 + fVar5;
        pfVar3[3] = fVar13 + fVar6;
        pfVar1 = (float4 *)(param_1 + 0x10 + iVar19);
        *pfVar1 = fVar14 + fVar7;
        pfVar1[1] = fVar15 + fVar8;
        pfVar1[2] = fVar16 + fVar9;
        pfVar1[3] = fVar17 + fVar10;
        iVar19 = iVar19 + 0x20;
      } while ((uint8)(param_4 >> 3 & 0xfffffff) * 0x20 != iVar19);
      if ((param_4 & 0x7ffffff8) == param_4) {
        return;
      }
    }
    do {
      *(float4 *)(param_1 + uVar18 * 4) =
           *(float4 *)(param_2 + uVar18 * 4) + *(float4 *)(param_3 + uVar18 * 4);
      uVar18 = uVar18 + 1;
    } while (param_4 != uVar18);
  }
  return;
}
