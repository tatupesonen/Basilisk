// Globals: scalars, an array, a struct, an array of structs.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: bump lookup_name
#include "libc.h"
struct entry { int id; const char *name; };
int counter;
int history[32];
struct entry table[8];
int bump(int by) {
    counter += by;
    history[counter & 31] = by;
    return counter;
}
const char *lookup_name(int id) {
    for (int i = 0; i < 8; i++) if (table[i].id == id) return table[i].name;
    return 0;
}
