/* Trivial bodies for the functions the cases call, so every call in a linked
 * fragment has a named target. Compiled separately with -fno-builtin; the
 * bodies are never examined. */
#include "libc.h"

void *memcpy(void *dst, const void *src, size_t n) { (void)src; (void)n; return dst; }
void *memset(void *dst, int c, size_t n) { (void)c; (void)n; return dst; }
size_t strlen(const char *s) { (void)s; return 0; }
int strcmp(const char *a, const char *b) { (void)a; (void)b; return 0; }
char *strcpy(char *dst, const char *src) { (void)src; return dst; }
int printf(const char *fmt, ...) { (void)fmt; return 0; }
int puts(const char *s) { (void)s; return 0; }
void *malloc(size_t n) { (void)n; return 0; }
void free(void *p) { (void)p; }
void exit(int code) { (void)code; for (;;) {} }
void abort(void) { for (;;) {} }
ssize_t read(int fd, void *buf, size_t n) { (void)fd; (void)buf; (void)n; return 0; }
ssize_t write(int fd, const void *buf, size_t n) { (void)fd; (void)buf; (void)n; return 0; }
int open(const char *path, int flags, ...) { (void)path; (void)flags; return 0; }
int close(int fd) { (void)fd; return 0; }
void __stack_chk_fail(void) { for (;;) {} }
unsigned long __stack_chk_guard = 0x595e9fbd94fda766UL;

int ext_i(int x) { return x; }
void ext_v(void) {}
void ext_p(void *p) { (void)p; }
long ext_l(long a, long b) { return a + b; }
