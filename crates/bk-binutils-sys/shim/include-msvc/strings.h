/* <strings.h> for MSVC's C library, which has none; on the include path
 * only for *-windows-msvc targets.  opcodes/microblaze-dis.c includes it
 * unconditionally for strcasecmp, which shim/include/bk_prelude.h maps to
 * _stricmp. */
#ifndef BK_STRINGS_H
#define BK_STRINGS_H
#include <string.h>
#endif
