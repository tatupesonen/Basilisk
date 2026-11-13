/* Configuration header for the binutils 2.41 subset built by bk-binutils-sys.
 *
 * binutils' own build generates one config.h per directory with autoconf.
 * The files compiled here (sources.list) consult only the few results
 * below, and those are the same on every host this crate builds for
 * (64-bit, hosted C99 with a POSIX-like or MinGW C library), so they are
 * written out once instead of probed.  One header serves opcodes, bfd and
 * libiberty alike.
 *
 * Deliberately NOT defined:
 *   ENABLE_NLS                        - messages stay untranslated;
 *   HAVE_DLFCN_H, HAVE_WINDOWS_H      - no dlopen (bfd/xtensa-dynconfig.c);
 *   HAVE_BFD_MIPS_ELF_GET_ABIFLAGS    - needs the MIPS ELF backend, and is
 *                                       only used when disassembling a
 *                                       section of an object file;
 *   HAVE_SBRK, HAVE_REALPATH, ...     - libiberty then takes its portable
 *                                       fallbacks.
 */
#ifndef BK_BINUTILS_CONFIG_H
#define BK_BINUTILS_CONFIG_H

/* glibc and musl declare stpcpy, asprintf and friends only on request. */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

/* bfd.h refuses to be included unless config.h came first, and tells by
   these. */
#define PACKAGE "bk-binutils-sys"
#define PACKAGE_VERSION "2.41"

#define STDC_HEADERS 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIMITS_H 1
#define HAVE_STDDEF_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_FCNTL_H 1
#define HAVE_LONG_LONG 1
#define HAVE_INTPTR_T 1
#define HAVE_UINTPTR_T 1
#define HAVE_STRINGIZE 1

#ifndef _WIN32
# define HAVE_UNISTD_H 1
# define HAVE_STRINGS_H 1
#endif

/* "The C library declares this function": when 0, binutils' headers
   declare it themselves, which clashes with libraries that implement the
   function as a macro. */
#define HAVE_DECL_BASENAME 1
#define HAVE_DECL_FFS 1
#define HAVE_DECL_ASPRINTF 1
#define HAVE_DECL_VASPRINTF 1
#define HAVE_DECL_SNPRINTF 1
#define HAVE_DECL_VSNPRINTF 1
#define HAVE_DECL_STRNLEN 1
#define HAVE_DECL_STRTOL 1
#define HAVE_DECL_STRTOUL 1
#define HAVE_DECL_STRTOLL 1
#define HAVE_DECL_STRTOULL 1
#define HAVE_DECL_STRVERSCMP 1
#define HAVE_DECL_GETOPT 1
#define HAVE_DECL_MALLOC 1
#define HAVE_DECL_CALLOC 1
#define HAVE_DECL_REALLOC 1
#define HAVE_DECL_STPCPY 1

#ifdef __SIZEOF_POINTER__
# define SIZEOF_VOID_P __SIZEOF_POINTER__
#else
# define SIZEOF_VOID_P 8
#endif

#endif /* BK_BINUTILS_CONFIG_H */
