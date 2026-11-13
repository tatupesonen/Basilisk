// A variadic function: the register save area and va_arg expansion.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: sum_ints
#include "libc.h"
int sum_ints(int n, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return s;
}
