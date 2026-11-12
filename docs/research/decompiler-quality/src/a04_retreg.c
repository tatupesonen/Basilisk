// Return storage of a callee whose prototype is unknown: a struct returned in
// two registers, and a bool return.
//! targets: x64-clang-O2
//! funcs: use_pair is_ready
#include "libc.h"
struct pair { long a, b; };
struct pair ext_pair(int x);
_Bool ext_flag(int x);
__attribute__((noinline)) struct pair ext_pair(int x) { struct pair r = { x, x * 2L }; return r; }
__attribute__((noinline)) _Bool ext_flag(int x) { return x > 3; }
long use_pair(int x) { struct pair p = ext_pair(x); return p.a * p.b; }
int is_ready(int x) { if (ext_flag(x)) return 10; return 20; }
