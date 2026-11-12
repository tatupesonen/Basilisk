// r01_goto, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r01_goto.x64-clang-O2.xml

[decomp]> load function classify
Function classify: 0x00200120
[decomp]> override flow r0x200145 callreturn
Successfully added flow override
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling classify
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling classify
Decompilation complete
[decomp]> print C

void classify(uint4 param_1,uint4 param_2,uint4 param_3)

{
  if ((int4)param_1 < 1) {
code_r0x00200135:
    param_1 = param_2;
    if (-1 < (int4)(param_3 & param_2)) goto code_r0x00200142;
  }
  else if ((int4)param_3 < 1 && (int4)param_2 < 1) goto code_r0x00200135;
  ext_v();
  param_3 = param_1;
code_r0x00200142:
  ext_i(param_3);
  return;
}
[decomp]> load function parse_kv
Function parse_kv: 0x00200150
[decomp]> override flow r0x200145 callreturn
Successfully added flow override
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling parse_kv
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling parse_kv
Decompilation complete
[decomp]> print C

xunknown8 parse_kv(int8 param_1,int4 *param_2,int4 *param_3)

{
  int4 iVar1;
  xunknown8 xVar2;
  int4 iVar3;
  char *pcVar4;
  char *pcVar5;
  char cVar6;
  
  pcVar4 = (char *)(param_1 + 1);
  do {
    cVar6 = pcVar4[-1];
    pcVar4 = pcVar4 + 1;
  } while (cVar6 == ' ');
  xVar2 = 0xffffffff;
  if (0xf5 < (uint1)(cVar6 - 0x3aU)) {
    iVar3 = 0;
    do {
      pcVar5 = pcVar4;
      iVar3 = (uint4)(uint1)(cVar6 - 0x30) + iVar3 * 10;
      cVar6 = pcVar5[-1];
      pcVar4 = pcVar5 + 1;
    } while ((uint1)(cVar6 - 0x30U) < 10);
    if ((cVar6 == '=') && (cVar6 = *pcVar5, 0xf5 < (uint1)(cVar6 - 0x3aU))) {
      iVar1 = 0;
      do {
        iVar1 = (uint4)(uint1)(cVar6 - 0x30) + iVar1 * 10;
        cVar6 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while ((uint1)(cVar6 - 0x30U) < 10);
      *param_2 = iVar3;
      *param_3 = iVar1;
      xVar2 = 0;
    }
  }
  return xVar2;
}
[decomp]> load function cleanup
Function cleanup: 0x002001f0
[decomp]> override flow r0x200145 callreturn
Successfully added flow override
[decomp]> override flow r0x200310 callreturn
Successfully added flow override
[decomp]> override flow r0x200320 callreturn
Successfully added flow override
[decomp]> override flow r0x200370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling cleanup
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling cleanup
Decompilation complete
[decomp]> print C

int4 cleanup(int4 param_1)

{
  void *buf;
  void *buf_00;
  size_t sVar1;
  int4 iVar2;
  size_t sVar3;
  size_t n;
  
  sVar3 = (size_t)param_1;
  buf = malloc(sVar3);
  if (buf == (void *)0x0) {
    iVar2 = -1;
  }
  else {
    n = (size_t)(param_1 * 2);
    buf_00 = malloc(n);
    if (buf_00 == (void *)0x0) {
      iVar2 = -1;
    }
    else {
      sVar1 = read(0,buf,sVar3);
      iVar2 = -1;
      if (sVar1 == sVar3) {
        sVar3 = write(1,buf_00,n);
        iVar2 = -(uint4)(sVar3 != n);
      }
      free(buf_00);
    }
    free(buf);
  }
  return iVar2;
}
