// a10_struct_copy, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a10_struct_copy.a64-gcc-O2.xml

[decomp]> load function copy_struct
Function copy_struct: 0x00401000
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling copy_struct
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling copy_struct
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void copy_struct(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function zero_init
Function zero_init: 0x00401020
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling zero_init
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling zero_init
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void zero_init(void)

{
  xunknown1 in_w12;
  xunknown1 *unaff_x26;
  
  LOAcquire();
  *unaff_x26 = in_w12;
  LORelease();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function copy16
Function copy16: 0x00401050
[decomp]> override flow r0x401086 callreturn
Successfully added flow override
[decomp]> override flow r0x4010a0 callreturn
Successfully added flow override
[decomp]> decompile
Decompiling copy16
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling copy16
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void copy16(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
