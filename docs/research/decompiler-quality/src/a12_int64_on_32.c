// 64-bit arithmetic on a 32-bit target.
//! targets: x86-clang-O2
//! funcs: add64 mul64 shl64 cmp64
#include "libc.h"
long long add64(long long a, long long b) { return a + b; }
long long mul64(long long a, long long b) { return a * b; }
unsigned long long shl64(unsigned long long a, int n) { return a << n; }
int cmp64(long long a, long long b) { return a < b; }
