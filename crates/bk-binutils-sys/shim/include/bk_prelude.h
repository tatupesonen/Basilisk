/* Included in front of every vendored binutils unit by the build (-include,
 * or /FI for MSVC-style compilers), before anything the unit includes.
 *
 * abort() and exit() inside binutils must end the current shim call, not
 * the process (bk_gdis.c, "Trap").  The C library declares both in
 * <stdlib.h>; it is included here first, so its declarations are made
 * under their own names (on Windows with __declspec(dllimport)), and only
 * then are the names redirected for the code that follows.  Renaming them
 * on the command line instead would rename the C library's declarations
 * too.
 *
 * Not config.h: bfd/sysdep.h insists on including that itself.  Only what
 * config.h would otherwise set before the first system header is set here.
 */
#ifndef BK_PRELUDE_H
#define BK_PRELUDE_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
void bk_gdis_abort (void) __attribute__ ((__noreturn__));
void bk_gdis_exit (int) __attribute__ ((__noreturn__));
#elif defined(_MSC_VER)
__declspec(noreturn) void bk_gdis_abort (void);
__declspec(noreturn) void bk_gdis_exit (int);
#else
void bk_gdis_abort (void);
void bk_gdis_exit (int);
#endif

#ifdef _WIN32
/* Neither the UCRT nor MinGW-w64 has stpcpy, which i386-dis.c and
   aarch64-dis.c use; shim/bk_compat.c defines it. */
char *stpcpy (char *dst, const char *src);
#endif

#ifdef _MSC_VER
/* MSVC's C library (and clang-cl, which defines _MSC_VER): the BSD names
   are spelled differently, alloca is declared in <malloc.h>, and __STDC__
   is not defined, without which include/symcat.h falls back to K&R token
   pasting (a/[comment]b) that a C99 preprocessor does not paste.  */
# include <string.h>
# include <malloc.h>
# define strcasecmp _stricmp
# define strncasecmp _strnicmp
# ifndef alloca
#  define alloca _alloca
# endif
# ifndef ALMOST_STDC
#  define ALMOST_STDC 1
# endif
/* In MSVC mode static_assert is a keyword even in C, but
   opcodes/mips-formats.h names an array static_assert (its compile-time
   check, one per block); binutils never uses static_assert itself.  */
# define static_assert bk_static_assert_array
#endif

#define abort bk_gdis_abort
#define exit bk_gdis_exit

#endif /* BK_PRELUDE_H */
