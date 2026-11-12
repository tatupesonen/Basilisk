// a01_ptr_param, a64-gcc-O2 (AARCH64:LE:64:v8A:default)
// Ghidra reference decomp output; inputs: frag/a01_ptr_param.a64-gcc-O2.xml

[decomp]> load function get
Function get: 0x00401000
[decomp]> override flow r0x401090 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> decompile
Decompiling get
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling get
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void get(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function sum_array
Function sum_array: 0x00401010
[decomp]> override flow r0x401090 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> decompile
Decompiling sum_array
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling sum_array
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void sum_array(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
[decomp]> load function list_sum
Function list_sum: 0x00401040
[decomp]> override flow r0x401090 callreturn
Successfully added flow override
[decomp]> override flow r0x4010aa callreturn
Successfully added flow override
[decomp]> decompile
Decompiling list_sum
Decompilation complete
[decomp]> decompile
Clearing old decompilation
Decompiling list_sum
Decompilation complete
[decomp]> print C

/* WARNING: Control flow encountered bad instruction data */

void list_sum(xunknown8 param_1,xunknown8 param_2)

{
  xunknown1 in_z17 [32];
  xunknown4 in_p0;
  
  SVE_ld1rw(in_z17,in_p0,param_2,0x20);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
