// r03_jumptable, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r03_jumptable.x64-clang-O2.xml

[decomp]> load function interp
Function interp: 0x00200160
[decomp]> override flow r0x200280 callreturn
Successfully added flow override
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002e0 callreturn
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
  uint1 *puVar1;
  
  while (*param_1 < 8) {
    puVar1 = param_1 + 1;
    switch(*param_1) {
    case 0:
      goto code_r0x002001e2;
    case 1:
      puVar1 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 + *puVar1;
      break;
    case 2:
      puVar1 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 - *puVar1;
      break;
    case 3:
      puVar1 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 * *puVar1;
      break;
    case 4:
      param_2 = -param_2;
      param_1 = puVar1;
      break;
    case 5:
      param_2 = param_2 ^ 0x55;
      param_1 = puVar1;
      break;
    case 6:
      param_2 = ext_l(param_2,param_1[1]);
      param_1 = param_1 + 2;
      break;
    case 7:
      if (param_2 == 0) {
        param_2 = 0;
        param_1 = puVar1 + *puVar1;
      }
      else {
        param_1 = param_1 + 2;
      }
    }
  }
  param_2 = 0xffffffffffffffff;
code_r0x002001e2:
  return param_2;
}
