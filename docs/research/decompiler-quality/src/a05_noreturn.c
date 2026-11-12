// A call to a function that does not return, which the decompiler has not
// been told about (a program-specific die()).
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: checked_get die after
#include "libc.h"
__attribute__((noreturn, noinline)) void die(const char *msg) { puts(msg); exit(1); }
int checked_get(const int *p) {
    if (!p) die("null pointer");
    return *p;
}
int after(int x) { return x * 7 + 1; }
