// The same loop as elsewhere, with the compiler's auto-vectoriser left on.
//! targets: x64-clang-O2 a64-gcc-O3
//! vectorize: yes
//! funcs: add_arrays
#include "libc.h"
void add_arrays(float *restrict d, const float *restrict a, const float *restrict b, int n) {
    for (int i = 0; i < n; i++) d[i] = a[i] + b[i];
}
