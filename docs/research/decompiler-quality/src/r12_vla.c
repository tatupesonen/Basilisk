// A variable-length array (dynamic stack allocation).
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: reverse_print
#include "libc.h"
void reverse_print(const char *s, int n) {
    char buf[n + 1];
    for (int i = 0; i < n; i++) buf[i] = s[n - 1 - i];
    buf[n] = 0;
    puts(buf);
}
