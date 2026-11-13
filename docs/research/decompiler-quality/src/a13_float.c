// Floating point: min, abs, conversion, comparison.
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: fmin2 fabs2 to_int lerp below
#include "libc.h"
double fmin2(double a, double b) { return a < b ? a : b; }
double fabs2(double x) { return x < 0 ? -x : x; }
int to_int(float f) { return (int)(f * 100.0f + 0.5f); }
float lerp(float a, float b, float t) { return a + (b - a) * t; }
int below(double a, double b) { return !(a >= b); }
