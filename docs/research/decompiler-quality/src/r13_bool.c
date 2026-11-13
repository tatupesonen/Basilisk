// Boolean expressions returned as values.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: in_range valid either
#include "libc.h"
int in_range(int x, int lo, int hi) { return x >= lo && x <= hi; }
int valid(const int *p, int n) { return p && n > 0 && p[0] == n; }
int either(int a, int b, int c) { return (a && b) || c; }
