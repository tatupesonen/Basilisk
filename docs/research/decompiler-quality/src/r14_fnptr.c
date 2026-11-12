// Calls through a table of function pointers in a struct (a C "vtable"), with
// and without the struct known to the decompiler.
//! targets: x64-clang-O2
//! funcs: stream_copy
#include "libc.h"
struct stream;
struct stream_ops {
    long (*read)(struct stream *, void *, long);
    long (*write)(struct stream *, const void *, long);
    void (*close)(struct stream *);
};
struct stream { const struct stream_ops *ops; int fd; int err; };
long stream_copy(struct stream *in, struct stream *out) {
    char buf[256];
    long total = 0, n;
    while ((n = in->ops->read(in, buf, sizeof buf)) > 0) {
        if (out->ops->write(out, buf, n) != n) { out->err = 1; break; }
        total += n;
    }
    in->ops->close(in);
    return total;
}
