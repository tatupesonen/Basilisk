// Structured source (no goto) that compilers turn into shapes Ghidra prints
// with goto: shared tails, short-circuit conditions, error paths.
//! targets: x64-clang-O2 a64-gcc-O2 x64-gcc-O2
//! funcs: classify parse_kv cleanup
//! pre: parse line extern int4 ext_i(int4 x);
#include "libc.h"
int classify(int a, int b, int c) {
    if (a > 0 && (b > 0 || c > 0)) {
        ext_v();
        return ext_i(a);
    }
    if (b < 0 && c < 0) {
        ext_v();
        return ext_i(b);
    }
    return ext_i(c);
}
int parse_kv(const char *s, int *key, int *val) {
    int k = 0, v = 0;
    while (*s == ' ') s++;
    if (*s < '0' || *s > '9') return -1;
    while (*s >= '0' && *s <= '9') k = k * 10 + (*s++ - '0');
    if (*s != '=') return -1;
    s++;
    if (*s < '0' || *s > '9') return -1;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    *key = k;
    *val = v;
    return 0;
}
int cleanup(int n) {
    int rc = -1;
    char *a = malloc(n);
    if (a) {
        char *b = malloc(n * 2);
        if (b) {
            if (read(0, a, n) == n) {
                if (write(1, b, n * 2) == n * 2) rc = 0;
            }
            free(b);
        }
        free(a);
    }
    return rc;
}
