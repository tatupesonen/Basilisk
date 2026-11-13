// Mixed-width integer code: sign and zero extension, truncation, and the
// casts and CONCAT/SUB/ZEXT/SEXT operators the output carries.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: widen index8 mulhi pack
#include "libc.h"
long widen(int a, short b, signed char c, unsigned char d) { return (long)a * b + c - d; }
int index8(const int *tab, unsigned char i, signed char j) { return tab[i] + tab[j]; }
unsigned long mulhi(unsigned long a, unsigned long b) { return ((unsigned __int128)a * b) >> 64; }
unsigned pack(unsigned char a, unsigned char b, unsigned short c) { return (unsigned)a << 24 | (unsigned)b << 16 | c; }
