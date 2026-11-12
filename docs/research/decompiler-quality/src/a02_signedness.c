// Signedness: signed division by a power of two, signed average, char tests.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: half avg is_upper count_neg
#include "libc.h"
int half(int a) { return a / 2; }
int avg(int a, int b) { return (a + b) / 2; }
int is_upper(char c) { return c >= 'A' && c <= 'Z'; }
int count_neg(const signed char *p, unsigned n) {
    int k = 0;
    for (unsigned i = 0; i < n; i++) if (p[i] < 0) k++;
    return k;
}
