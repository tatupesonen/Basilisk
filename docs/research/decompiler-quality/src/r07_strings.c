// Strings: literals passed to known and unknown callees, a string built on
// the stack, and an inlined comparison against a short literal.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: log_it stack_string is_yes
#include "libc.h"
void log_it(int code) {
    printf("error %d: %s\n", code, "disk full");
    ext_p("not a known prototype");
}
void stack_string(void) {
    char name[] = "basilisk decompiler";
    ext_p(name);
}
int is_yes(const char *s) { return strcmp(s, "yes") == 0; }
