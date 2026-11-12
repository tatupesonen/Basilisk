// Bit-fields, with and without the struct declared to the decompiler.
//! targets: x64-clang-O2
//! funcs: get_kind set_kind
#include "libc.h"
struct hdr { unsigned kind : 3; unsigned flags : 5; unsigned len : 24; };
unsigned get_kind(const struct hdr *h) { return h->kind + h->len; }
void set_kind(struct hdr *h, unsigned k) { h->kind = k; h->flags |= 1; }
