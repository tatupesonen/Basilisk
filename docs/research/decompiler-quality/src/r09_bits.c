// Bit manipulation idioms: byte swap, rotate, population count, leading zeros,
// alignment, power-of-two test.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: bswap rotl popcnt clz align_up is_pow2
#include "libc.h"
unsigned bswap(unsigned x) { return x >> 24 | (x >> 8 & 0xff00) | (x << 8 & 0xff0000) | x << 24; }
unsigned rotl(unsigned x, int n) { return x << (n & 31) | x >> (-n & 31); }
int popcnt(unsigned long x) { int c = 0; while (x) { x &= x - 1; c++; } return c; }
int clz(unsigned x) { return x ? __builtin_clz(x) : 32; }
unsigned long align_up(unsigned long x) { return (x + 15) & ~15UL; }
int is_pow2(unsigned x) { return x && !(x & (x - 1)); }
