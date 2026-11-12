// Branch-free code: min/max, abs, clamp, sign, conditional increments.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: max3 iabs clamp sign count_if
#include "libc.h"
int max3(int a, int b, int c) { int m = a > b ? a : b; return m > c ? m : c; }
int iabs(int x) { return x < 0 ? -x : x; }
int clamp(int x, int lo, int hi) { if (x < lo) return lo; if (x > hi) return hi; return x; }
int sign(int x) { return (x > 0) - (x < 0); }
int count_if(const int *a, int n, int lo) {
    int c = 0;
    for (int i = 0; i < n; i++) if (a[i] >= lo) c++;
    return c;
}
