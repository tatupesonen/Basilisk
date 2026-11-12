// r03_jumptable, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r03_jumptable.a64-gcc-O2.xml

[decomp]> load function interp
Function interp: 0x00400120
[decomp]> override flow r0x400304 callreturn
Successfully added flow override
[decomp]> override flow r0x400308 callreturn
Successfully added flow override
[decomp]> override flow r0x40032c callreturn
Successfully added flow override
[decomp]> decompile
Decompiling interp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling interp
Decompilation complete
[decomp]> print C

uint8 interp(uint1 *param_1,uint8 param_2)

{
  uint1 uVar1;
  uint1 *puVar2;
  uint1 *puVar3;
  uint1 *puVar4;
  
code_r0x00400128:
  do {
    uVar1 = *param_1;
    puVar4 = param_1 + 1;
    puVar3 = param_1;
    while (param_1 = puVar4, uVar1 != 4) {
      if (4 < uVar1) {
        if (uVar1 == 6) {
code_r0x004001e0:
          puVar4 = puVar3 + 2;
          param_2 = ext_l(param_2,puVar3[1]);
code_r0x004001f0:
          do {
            uVar1 = *puVar4;
            puVar2 = puVar4 + 1;
            puVar3 = puVar4;
            while (puVar4 = puVar2, uVar1 != 4) {
              if (4 < uVar1) {
                if (uVar1 == 6) goto code_r0x004001e0;
                if (uVar1 == 7) {
                  if (param_2 == 0) {
                    puVar4 = puVar4 + puVar3[1];
                  }
                  else {
                    puVar4 = puVar3 + 2;
                  }
                }
                else {
                  if (uVar1 != 5) {
                    return 0xffffffffffffffff;
                  }
                  param_2 = param_2 ^ 0x55;
                }
                goto code_r0x004001f0;
              }
              if (uVar1 == 2) {
                puVar4 = puVar3 + 2;
                param_2 = param_2 - puVar3[1];
                goto code_r0x004001f0;
              }
              if (uVar1 == 3) {
                puVar4 = puVar3 + 2;
                param_2 = param_2 * puVar3[1];
                goto code_r0x004001f0;
              }
              if (uVar1 == 0) {
                return param_2;
              }
              param_2 = param_2 + puVar3[1];
              uVar1 = puVar3[2];
              puVar2 = puVar3 + 3;
              puVar3 = puVar3 + 2;
            }
            param_2 = -param_2;
          } while( true );
        }
        if (uVar1 == 7) {
          if (param_2 == 0) {
            param_1 = param_1 + puVar3[1];
          }
          else {
            param_1 = puVar3 + 2;
          }
        }
        else {
          if (uVar1 != 5) {
            return 0xffffffffffffffff;
          }
          param_2 = param_2 ^ 0x55;
        }
        goto code_r0x00400128;
      }
      if (uVar1 == 2) {
        param_1 = puVar3 + 2;
        param_2 = param_2 - puVar3[1];
        goto code_r0x00400128;
      }
      if (uVar1 == 3) {
        param_1 = puVar3 + 2;
        param_2 = param_2 * puVar3[1];
        goto code_r0x00400128;
      }
      if (uVar1 == 0) {
        return param_2;
      }
      param_2 = param_2 + puVar3[1];
      uVar1 = puVar3[2];
      puVar4 = puVar3 + 3;
      puVar3 = puVar3 + 2;
    }
    param_2 = -param_2;
  } while( true );
}
