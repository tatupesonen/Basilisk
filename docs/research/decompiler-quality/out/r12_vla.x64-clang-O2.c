// r12_vla, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r12_vla.x64-clang-O2.xml

[decomp]> load function reverse_print
Function reverse_print: 0x00200120
[decomp]> override flow r0x200290 callreturn
Successfully added flow override
[decomp]> override flow r0x2002a0 callreturn
Successfully added flow override
[decomp]> override flow r0x2002f0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling reverse_print
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling reverse_print
Decompilation complete
[decomp]> print C

void reverse_print(int8 param_1,uint4 param_2)

{
  int8 iVar1;
  int8 iVar2;
  uint8 uVar3;
  uint8 uVar4;
  uint8 uVar5;
  char *pcVar6;
  char *s;
  xunknown8 xStack_10;
  
  iVar2 = -((uint8)(param_2 + 1) + 0xf & 0xfffffffffffffff0);
  s = (char *)((int8)register_RSP + iVar2 + -8);
  if ((int4)param_2 < 1) {
    uVar5 = (uint8)(int4)param_2;
  }
  else {
    uVar5 = (uint8)param_2;
    iVar1 = param_1 + uVar5;
    if (param_2 < 4) {
      uVar3 = 0;
    }
    else {
      pcVar6 = (char *)(uVar5 + param_1 + -1);
      uVar3 = 0;
      do {
        s[uVar3] = *pcVar6;
        *(xunknown1 *)((int8)register_RSP + uVar3 + iVar2 + -7) =
             *(xunknown1 *)(iVar1 + (uVar3 ^ 0xfffffffffffffffe));
        *(xunknown1 *)((int8)register_RSP + uVar3 + iVar2 + -6) =
             *(xunknown1 *)(iVar1 + (uVar3 ^ 0xfffffffffffffffd));
        *(xunknown1 *)((int8)register_RSP + uVar3 + iVar2 + -5) =
             *(xunknown1 *)(iVar1 + (uVar3 ^ 0xfffffffffffffffc));
        uVar3 = uVar3 + 4;
        pcVar6 = pcVar6 + -4;
      } while ((param_2 & 0x7ffffffc) != uVar3);
    }
    if ((uint8)(param_2 & 3) != 0) {
      pcVar6 = (char *)(iVar1 + ~uVar3);
      uVar4 = 0;
      do {
        s[uVar4 + uVar3] = *pcVar6;
        uVar4 = uVar4 + 1;
        pcVar6 = pcVar6 + -1;
      } while ((param_2 & 3) != uVar4);
    }
  }
  s[uVar5] = '\0';
  *(xunknown8 *)((int8)&xStack_10 + iVar2) = 0x2001ec;
  puts(s);
  return;
}
