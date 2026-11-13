// Return values the decompiler drops: the returned register is also used
// inside the function, or comes straight from the last call.
//! targets: x64-clang-O2 a64-gcc-O2 x64-gcc-O2
//! funcs: inc find_idx after_call
#include "libc.h"
int inc(int *p) { return ++*p; }
int find_idx(const int *a, int n, int key) {
    int i;
    for (i = 0; i < n; i++) if (a[i] == key) break;
    return i;
}
int after_call(const char *s) {
    char b[32];
    strcpy(b, s);
    return puts(b);
}
