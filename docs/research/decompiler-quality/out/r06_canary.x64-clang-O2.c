// r06_canary, x64-clang-O2 (x86:LE:64:default:gcc)
// Ghidra reference decomp output; inputs: frag/r06_canary.x64-clang-O2.xml

[decomp]> load function greet
Function greet: 0x00200120
[decomp]> override flow r0x200200 callreturn
Successfully added flow override
[decomp]> override flow r0x200210 callreturn
Successfully added flow override
[decomp]> override flow r0x200260 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling greet
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling greet
Decompilation complete
[decomp]> print C

void greet(char *param_1)

{
  int8 in_FS_OFFSET;
  char acStack_48 [64];
  int8 iStack_8;
  
  iStack_8 = *(int8 *)(in_FS_OFFSET + 0x28);
  builtin_strncpy(acStack_48,"hello, ",8);
  strcpy(acStack_48 + 7,param_1);
  puts(acStack_48);
  if (*(int8 *)(in_FS_OFFSET + 0x28) != iStack_8) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
