/* C library functions binutils uses that a target's C library lacks.
 * Their declarations are in shim/include/bk_prelude.h. */
#include "config.h"

#include <string.h>

#ifdef _WIN32
/* Neither the UCRT nor MinGW-w64 has stpcpy (i386-dis.c, aarch64-dis.c). */
char *
stpcpy (char *dst, const char *src)
{
  size_t n = strlen (src);

  memcpy (dst, src, n + 1);
  return dst + n;
}
#else
/* ISO C forbids an empty translation unit. */
typedef int bk_compat_unused;
#endif
