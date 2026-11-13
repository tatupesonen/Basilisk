// r01_goto, x64-gcc-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r01_goto.x64-gcc-O2.xml

[decomp]> load function classify
Function classify: 0x00401000
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling classify
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling classify
Decompilation complete
[decomp]> print C

void classify(int4 param_1,uint4 param_2,uint4 param_3)

{
  if ((0 < param_1) && ((0 < (int4)param_2 || (0 < (int4)param_3)))) {
    ext_v();
    ext_i(param_1);
    return;
  }
  if ((int4)(param_2 & param_3) < 0) {
    ext_v();
    ext_i(param_2);
    return;
  }
  ext_i(param_3);
  return;
}
[decomp]> load function parse_kv
Function parse_kv: 0x00401060
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling parse_kv
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling parse_kv
Decompilation complete
[decomp]> print C

xunknown8 parse_kv(char *param_1,int4 *param_2,int4 *param_3)

{
  char *pcVar1;
  char cVar2;
  int4 iVar3;
  int4 iVar4;
  
  cVar2 = *param_1;
  while (cVar2 == ' ') {
    pcVar1 = param_1 + 1;
    param_1 = param_1 + 1;
    cVar2 = *pcVar1;
  }
  if ((uint1)(cVar2 - 0x30U) < 10) {
    iVar4 = 0;
    cVar2 = *param_1;
    while ((uint1)(cVar2 - 0x30U) < 10) {
      param_1 = param_1 + 1;
      iVar4 = (int4)(char)(cVar2 + -0x30) + iVar4 * 10;
      cVar2 = *param_1;
    }
    if (cVar2 == '=') {
      cVar2 = param_1[1];
      param_1 = param_1 + 1;
      if ((uint1)(cVar2 - 0x30U) < 10) {
        iVar3 = 0;
        do {
          param_1 = param_1 + 1;
          iVar3 = (int4)(char)(cVar2 + -0x30) + iVar3 * 10;
          cVar2 = *param_1;
        } while ((uint1)(cVar2 - 0x30U) < 10);
        *param_2 = iVar4;
        *param_3 = iVar3;
        return 0;
      }
    }
  }
  return 0xffffffff;
}
[decomp]> load function cleanup
Function cleanup: 0x00401110
[decomp]> override flow r0x40101e callreturn
Successfully added flow override
[decomp]> override flow r0x401034 callreturn
Successfully added flow override
[decomp]> override flow r0x401052 callreturn
Successfully added flow override
[decomp]> override flow r0x4011de callreturn
Successfully added flow override
[decomp]> override flow r0x4011f8 callreturn
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
  size_t n;
  size_t sVar2;
  int4 iVar3;
  
  sVar2 = (size_t)param_1;
  buf = malloc(sVar2);
  if (buf == (void *)0x0) {
    iVar3 = -1;
  }
  else {
    n = (size_t)(param_1 * 2);
    buf_00 = malloc(n);
    if (buf_00 == (void *)0x0) {
      iVar3 = -1;
    }
    else {
      iVar3 = -1;
      sVar1 = read(0,buf,sVar2);
      if (sVar1 == sVar2) {
        sVar2 = write(1,buf_00,n);
        iVar3 = -(uint4)(n != sVar2);
      }
      free(buf_00);
    }
    free(buf);
  }
  return iVar3;
}
