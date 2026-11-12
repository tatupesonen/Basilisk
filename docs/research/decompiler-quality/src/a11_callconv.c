// A static helper that the compiler gives a non-standard calling convention
// (32-bit x86: arguments in registers instead of on the stack).
//! targets: x86-clang-O2
//! funcs: helper caller
#include "libc.h"
__attribute__((noinline)) static int helper(int a, int b, int c) { return ext_i(a * b) + c; }
int caller(int x) { return helper(x, 3, 5) + helper(7, x, x); }
