//! targets: x64-clang-O2 a64-clang-O2 a64-gcc-O2 x86-clang-O2
//! funcs: sum
#include "libc.h"
int table[16];
int sum(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] * table[i & 15];
    printf("sum=%d\n", s);
    return s;
}
