// Struct assignment, zero initialisation and small fixed-size memcpy, all of
// which compilers expand inline.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: copy_struct zero_init copy16
#include "libc.h"
struct big { long a, b, c, d, e, f; };
void copy_struct(struct big *dst, const struct big *src) { *dst = *src; }
void zero_init(void) { struct big b = {0}; b.c = 7; ext_p(&b); }
void copy16(char *dst, const char *src) { memcpy(dst, src, 16); }
