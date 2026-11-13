// r14_fnptr, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r14_fnptr.x64-clang-O2.xml

[decomp]> load function stream_copy
Function stream_copy: 0x00200120
[decomp]> override flow r0x200250 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> override flow r0x2002b0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling stream_copy
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling stream_copy
Decompilation complete
[decomp]> print C

int8 stream_copy(int8 *param_1,int8 *param_2)

{
  int8 iVar1;
  int8 iVar2;
  int8 iVar3;
  xunknown1 axStack_128 [256];
  
  iVar1 = (**(code **)*param_1)(param_1,axStack_128,0x100);
  if (iVar1 < 1) {
    iVar3 = 0;
  }
  else {
    iVar3 = 0;
    do {
      iVar2 = (**(code **)(*param_2 + 8))(param_2,axStack_128,iVar1);
      if (iVar2 != iVar1) {
        *(xunknown4 *)((int8)param_2 + 0xc) = 1;
        break;
      }
      iVar3 = iVar3 + iVar1;
      iVar1 = (**(code **)*param_1)(param_1,axStack_128,0x100);
    } while (0 < iVar1);
  }
  (**(code **)(*param_1 + 0x10))(param_1);
  return iVar3;
}
