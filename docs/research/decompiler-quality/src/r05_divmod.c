// Division and remainder by constants, which compilers turn into
// multiplications and shifts.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: udiv7 sdiv7 umod10 sdiv64 divisible3 digits to_hms
#include "libc.h"
unsigned udiv7(unsigned x) { return x / 7; }
int sdiv7(int x) { return x / 7; }
unsigned umod10(unsigned x) { return x % 10; }
long sdiv64(long x) { return x / 1000; }
int divisible3(unsigned x) { return x % 3 == 0; }
int digits(unsigned x) { int n = 0; do { n++; x /= 10; } while (x); return n; }
void to_hms(unsigned secs, unsigned *h, unsigned *m, unsigned *s) {
    *h = secs / 3600; *m = secs % 3600 / 60; *s = secs % 60;
}
