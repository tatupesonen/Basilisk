/* Declarations of the few library functions the cases call. The cases are
 * compiled without a C library's headers; `stubs.c` gives each function a
 * trivial body so that the linked fragment has a symbol at every call target.
 * `libc.proto` gives Ghidra's console the same prototypes, standing in for the
 * data-type archives a full Ghidra applies to imported library functions. */
#ifndef CASE_LIBC_H
#define CASE_LIBC_H

typedef unsigned long size_t;
typedef long ssize_t;

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
char *strcpy(char *dst, const char *src);
int printf(const char *fmt, ...);
int puts(const char *s);
void *malloc(size_t n);
void free(void *p);
void exit(int code) __attribute__((noreturn));
void abort(void) __attribute__((noreturn));
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int open(const char *path, int flags, ...);
int close(int fd);
void __stack_chk_fail(void) __attribute__((noreturn));

/* Opaque helpers with no known prototype on the Ghidra side. */
int ext_i(int x);
void ext_v(void);
void ext_p(void *p);
long ext_l(long a, long b);

#endif
