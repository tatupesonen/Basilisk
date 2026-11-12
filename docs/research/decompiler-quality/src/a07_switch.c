// Switch statements in the shapes compilers lower them to: jump table,
// sparse compare tree, bit test, lookup table.
//! targets: x64-clang-O2 a64-gcc-O2 x64-gcc-O2
//! funcs: dense sparse bittest lookup
#include "libc.h"
int dense(int x) {
    switch (x) {
    case 0: return ext_i(10);
    case 1: return ext_i(22);
    case 2: return ext_i(35);
    case 3: return ext_i(41);
    case 4: return ext_i(57);
    case 5: return ext_i(63);
    default: return -1;
    }
}
int sparse(int x) {
    switch (x) {
    case 1: return ext_i(10);
    case 10: return ext_i(22);
    case 100: return ext_i(35);
    case 1000: return ext_i(41);
    case 10000: return ext_i(57);
    default: return -1;
    }
}
int bittest(int c) {
    switch (c) {
    case ' ': case '\t': case '\n': case '\r': case ',': case ';':
        return 1;
    default:
        return 0;
    }
}
const char *lookup(int x) {
    switch (x) {
    case 0: return "zero";
    case 1: return "one";
    case 2: return "two";
    case 3: return "three";
    case 4: return "four";
    default: return "many";
    }
}
