// Loop shapes: a counted for loop, a while loop with break and continue, a
// nested loop, and a strlen-style loop.
//! targets: x64-clang-O2 a64-gcc-O2 x64-clang-O0
//! funcs: fill find_first count_pairs my_strlen
#include "libc.h"
void fill(int *a, int n, int v) {
    for (int i = 0; i < n; i++) a[i] = v + i;
}
int find_first(const int *a, int n, int key) {
    int i = 0;
    while (i < n) {
        if (a[i] < 0) { i += 2; continue; }
        if (a[i] == key) break;
        i++;
    }
    return i;
}
int count_pairs(const int *a, int n, int sum) {
    int c = 0;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (a[i] + a[j] == sum) c++;
    return c;
}
size_t my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}
