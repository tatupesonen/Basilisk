// a16_retval again, with the three prototypes given to the decompiler (as debug
// information or a user would): the same code is then printed correctly.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: inc find_idx after_call
//! pre: parse line extern int4 inc(int4 *p);
//! pre: parse line extern int4 find_idx(int4 *a, int4 n, int4 key);
//! pre: parse line extern int4 after_call(char *s);
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
