// A local array and a local struct whose address escapes to a callee.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: local_array local_struct
#include "libc.h"
struct conf { int id; int flags; long size; char tag[8]; };
int local_array(void) {
    int a[4];
    ext_p(a);
    return a[1] + a[3];
}
long local_struct(int id) {
    struct conf c;
    c.id = id;
    c.flags = 3;
    c.size = 4096;
    memcpy(c.tag, "basilisk", 8);
    ext_p(&c);
    return c.size + c.flags;
}
