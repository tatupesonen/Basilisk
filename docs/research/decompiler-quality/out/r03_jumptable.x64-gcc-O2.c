// r03_jumptable, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r03_jumptable.x64-gcc-O2.xml

[decomp]> load function interp
Function interp: 0x00401010
[decomp]> override flow r0x4010e8 callreturn
Successfully added flow override
[decomp]> override flow r0x401102 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling interp
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling interp
Decompilation complete
[decomp]> print C

uint8 interp(xunknown1 *param_1,uint8 param_2)

{
  xunknown1 *pxVar1;
  uint1 *puVar2;
  
  do {
    pxVar1 = param_1 + 1;
    switch(*param_1) {
    case 0:
      return param_2;
    case 1:
      puVar2 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 + *puVar2;
      break;
    case 2:
      puVar2 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 - *puVar2;
      break;
    case 3:
      puVar2 = param_1 + 1;
      param_1 = param_1 + 2;
      param_2 = param_2 * *puVar2;
      break;
    case 4:
      param_2 = -param_2;
      param_1 = pxVar1;
      break;
    case 5:
      param_2 = param_2 ^ 0x55;
      param_1 = pxVar1;
      break;
    case 6:
      param_2 = ext_l(param_2,param_1[1]);
      param_1 = param_1 + 2;
      break;
    case 7:
      if (param_2 == 0) {
        param_1 = pxVar1 + (uint1)param_1[1];
      }
      else {
        param_1 = param_1 + 2;
      }
      break;
    default:
      return 0xffffffffffffffff;
    }
  } while( true );
}
