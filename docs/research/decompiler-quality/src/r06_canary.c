// Stack protector: compiler-generated code around every function with a buffer.
//! targets: x64-clang-O2 a64-gcc-O2
//! cflags: -fstack-protector-strong
//! funcs: greet
#include "libc.h"
int greet(const char *name) {
    char buf[64];
    strcpy(buf, "hello, ");
    strcpy(buf + 7, name);
    return puts(buf);
}
