// Pointer parameters, array indexing and a linked list, with no type information
// for the function itself (the stripped-binary case).
//! targets: x64-clang-O2 a64-gcc-O2
//! funcs: get sum_array list_sum
#include "libc.h"
struct node { int val; struct node *next; };
int get(const int *a, long i) { return a[i]; }
long sum_array(const int *a, int n) {
    long s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}
int list_sum(const struct node *p) {
    int s = 0;
    for (; p; p = p->next) s += p->val;
    return s;
}
