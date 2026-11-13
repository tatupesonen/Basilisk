// Wrapping arithmetic and overflow checks: what the output says and whether it
// would mean the same if compiled again.
//! targets: x64-clang-O2
//! cflags: -fwrapv
//! funcs: add_overflows uadd_overflows mul_checked next_id
#include "libc.h"
int add_overflows(int x) { return x + 100 < x; }
int uadd_overflows(unsigned a, unsigned b) { return a + b < a; }
int mul_checked(int a, int b, int *out) { return __builtin_mul_overflow(a, b, out); }
int next_id(int x) { if (x + 1 > 0) return x + 1; return 1; }
