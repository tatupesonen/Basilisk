// Constants a reader wants in another form: flag sets, octal modes, character
// constants, negative numbers, sizes.
//! targets: x64-clang-O2
//! funcs: create is_space neg
#include "libc.h"
int create(const char *path) { return open(path, 01 | 0100 | 01000, 0644); }
int is_space(int c) { return c == ' ' || c == '\t' || c == '\n'; }
int neg(int x) { return x == -1 ? -2 : x - 100; }
