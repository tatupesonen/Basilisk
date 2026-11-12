// The same struct code as a15 and r17, with nothing declared: what the
// decompiler recovers of the data structure on its own.
//! targets: x64-clang-O2
//! funcs: init_acct total
#include "libc.h"
struct acct { long balance; long limit; int ops; int flags; char owner[16]; struct acct *next; };
void init_acct(struct acct *a, long limit) {
    a->balance = 0; a->limit = limit; a->ops = 0; a->flags = 0;
    memset(a->owner, 0, 16);
    a->next = 0;
}
long total(const struct acct *a) {
    long t = 0;
    for (; a; a = a->next) if (!(a->flags & 2)) t += a->balance;
    return t;
}
