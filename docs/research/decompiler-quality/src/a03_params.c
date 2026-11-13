// Parameter recovery: unused parameters, mixed integer and floating-point
// parameters, a small struct passed and returned by value.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: third mixed area mkpair
#include "libc.h"
struct pt { double x, y; };
struct pair { long a, b; };
int third(int a, int b, int c) { return c * 3; }
double mixed(int a, double b, int c, double d) { return a * b + c * d; }
double area(struct pt p, struct pt q) { return (q.x - p.x) * (q.y - p.y); }
struct pair mkpair(long a, long b) { struct pair r = { a + b, a - b }; return r; }
