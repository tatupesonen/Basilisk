// Tail calls: direct, and through a function pointer.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: direct_tail indirect_tail dispatch
#include "libc.h"
typedef int (*handler)(int);
struct ops { handler open; handler close; };
int direct_tail(int x) { return ext_i(x + 1); }
int indirect_tail(handler h, int x) { return h(x + 1); }
int dispatch(const struct ops *o, int which, int x) {
    return which ? o->close(x) : o->open(x);
}
