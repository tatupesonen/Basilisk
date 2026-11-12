extern int ext_value;
extern int ext_func(int);
static int a, b, c, d, e, f, g, h;
int *table[] = { &a, &b, &c, &d, &e, &f, &g, &h, &a, &c, &e, &g, 0, &b, &d, &f, &h };
static int *sparse[64] = { [0] = &a, [3] = &b, [40] = &c, [63] = &d };
int **sparse_ptr = sparse;
int *ext_ptr = &ext_value;
int call_ext(int x) { return ext_func(x) + *table[x & 7] + ext_value; }
