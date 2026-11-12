// A switch that is compiled to a jump table, inside a loop (a small
// interpreter): the shape Ghidra's switch recovery is built for.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: interp
#include "libc.h"
long interp(const unsigned char *code, long acc) {
    for (;;) {
        switch (*code++) {
        case 0: return acc;
        case 1: acc += *code++; break;
        case 2: acc -= *code++; break;
        case 3: acc *= *code++; break;
        case 4: acc = -acc; break;
        case 5: acc ^= 0x55; break;
        case 6: acc = ext_l(acc, *code++); break;
        case 7: if (acc == 0) code += *code; else code++; break;
        default: return -1;
        }
    }
}
