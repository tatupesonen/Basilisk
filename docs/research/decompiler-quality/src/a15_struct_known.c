// Array of structs when the struct and the prototype are known to the
// decompiler (what DWARF or a user would supply).
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: total find
//! pre: parse line struct item { int4 id; char name[20]; float8 w; };
//! pre: parse line extern float8 total(item *v, int4 n);
//! pre: parse line extern item *find(item *v, int4 n, int4 id);
#include "libc.h"
struct item { int id; char name[20]; double w; };
double total(const struct item *v, int n) {
    double t = 0;
    for (int i = 0; i < n; i++) t += v[i].w;
    return t;
}
struct item *find(struct item *v, int n, int id) {
    for (int i = 0; i < n; i++) if (v[i].id == id) return &v[i];
    return 0;
}
