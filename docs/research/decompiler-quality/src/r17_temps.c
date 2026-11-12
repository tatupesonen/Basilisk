// Straight-line code with common subexpressions and a value used across a
// call: how many temporaries the output needs and where they are declared.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: checksum update
#include "libc.h"
struct acct { long balance; long limit; int ops; int flags; };
unsigned checksum(const unsigned char *p, unsigned n) {
    unsigned a = 1, b = 0;
    for (unsigned i = 0; i < n; i++) { a = (a + p[i]) % 65521; b = (b + a) % 65521; }
    return b << 16 | a;
}
int update(struct acct *a, long delta) {
    long nb = a->balance + delta;
    if (nb < -a->limit) { a->flags |= 4; return -1; }
    a->balance = nb;
    a->ops++;
    if (nb < 0) a->flags |= 1; else a->flags &= ~1;
    return a->ops;
}
