// r01_goto, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/r01_goto.a64-gcc-O2.xml

[decomp]> load function classify
Function classify: 0x00400120
[decomp]> override flow r0x400158 callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x400348 callreturn
Successfully added flow override
[decomp]> override flow r0x40034c callreturn
Successfully added flow override
[decomp]> override flow r0x400370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling classify
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling classify
Decompilation complete
[decomp]> print C

int4 classify(int4 param_1,uint4 param_2,uint4 param_3)

{
  int4 iVar1;
  
  if ((0 < param_1) && (0 < (int4)param_2 || 0 < (int4)param_3)) {
    ext_v();
    iVar1 = ext_i(param_1);
    return iVar1;
  }
  if ((int4)(param_2 & param_3) < 0) {
    ext_v();
    iVar1 = ext_i(param_2);
    return iVar1;
  }
  iVar1 = ext_i(param_3);
  return iVar1;
}
[decomp]> load function parse_kv
Function parse_kv: 0x00400188
[decomp]> override flow r0x400158 callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x400348 callreturn
Successfully added flow override
[decomp]> override flow r0x40034c callreturn
Successfully added flow override
[decomp]> override flow r0x400370 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling parse_kv
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling parse_kv
Decompilation complete
[decomp]> print C

xunknown8 parse_kv(uint1 *param_1,int4 *param_2,int4 *param_3)

{
  uint1 uVar1;
  uint1 *puVar2;
  int4 iVar3;
  int4 iVar4;
  uint4 uVar5;
  
  uVar1 = *param_1;
  while (uVar1 == 0x20) {
    param_1 = param_1 + 1;
    uVar1 = *param_1;
  }
  if ((uint1)(uVar1 - 0x30) < 10) {
    iVar3 = 0;
    uVar1 = *param_1;
    while ((uVar1 - 0x30 & 0xff) < 10) {
      param_1 = param_1 + 1;
      iVar3 = (uVar1 - 0x30) + iVar3 * 10;
      uVar1 = *param_1;
    }
    if (uVar1 == 0x3d) {
      puVar2 = param_1 + 1;
      uVar5 = param_1[1] - 0x30;
      if ((uVar5 & 0xff) < 10) {
        iVar4 = 0;
        do {
          puVar2 = puVar2 + 1;
          iVar4 = uVar5 + iVar4 * 10;
          uVar5 = *puVar2 - 0x30;
        } while ((uVar5 & 0xff) < 10);
        *param_2 = iVar3;
        *param_3 = iVar4;
        return 0;
      }
    }
  }
  return 0xffffffff;
}
[decomp]> load function cleanup
Function cleanup: 0x00400260
[decomp]> override flow r0x400158 callreturn
Successfully added flow override
[decomp]> override flow r0x40016c callreturn
Successfully added flow override
[decomp]> override flow r0x400184 callreturn
Successfully added flow override
[decomp]> override flow r0x400348 callreturn
Successfully added flow override
[decomp]> override flow r0x40034c callreturn
Successfully added flow override
[decomp]> override flow r0x400370 callreturn
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
    n = (size_t)(param_1 << 1);
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
