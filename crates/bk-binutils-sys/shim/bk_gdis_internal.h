/* Shared between the two shim sources; not part of the Rust-facing API. */
#ifndef BK_GDIS_INTERNAL_H
#define BK_GDIS_INTERNAL_H

#include <stdarg.h>

#if defined(__GNUC__) || defined(__clang__)
# define BK_NORETURN __attribute__ ((__noreturn__))
# define BK_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n)))
#else
# define BK_NORETURN
# define BK_PRINTF(m, n)
#endif

/* Remembers a message for bk_gdis_take_message (the first one wins). */
void bk_gdis_note (const char *fmt, ...) BK_PRINTF (1, 2);
void bk_gdis_vnote (const char *fmt, va_list ap);

/* Remembers a message and abandons the shim call in progress, which then
   returns BK_GDIS_ABORTED. */
void bk_gdis_fatal (const char *fmt, ...) BK_NORETURN BK_PRINTF (1, 2);

/* What abort() and exit() in the vendored sources are compiled to. */
void bk_gdis_abort (void) BK_NORETURN;
void bk_gdis_exit (int code) BK_NORETURN;
void bk_gdis_assert_fail (const char *expr, const char *file, int line)
  BK_NORETURN;

#endif /* BK_GDIS_INTERNAL_H */
