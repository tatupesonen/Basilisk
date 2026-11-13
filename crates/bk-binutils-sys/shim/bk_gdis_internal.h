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

/* bk_state.c.  These need bfd.h's enum bfd_architecture.  */
#ifdef __BFD_H_SEEN__
/* The option string a disassembler of ARCH is given for the user's options
   USER (or NULL): USER behind the options that restore the target's
   defaults.  malloc'd, or NULL for none; *NO_MEMORY tells the two apart. */
char *bk_effective_options (enum bfd_architecture arch, const char *user,
                            int *no_memory);
/* Resets target globals that no option can (C-SKY's using_abi). */
void bk_reset_target_globals (enum bfd_architecture arch);
/* For targets that apply options once per process: BK_GDIS_OK if USER
   agrees with the first disassembler's options (recording USER as those
   when RECORD and there was none yet), else BK_GDIS_OPTIONS_CONFLICT. */
int32_t bk_once_check (enum bfd_architecture arch, const char *user,
                       int record);
#endif
#include <stdint.h>
/* After an abort inside a target: refuse its family from now on. */
void bk_quarantine (uint32_t arch);
int bk_quarantined (uint32_t arch);

#endif /* BK_GDIS_INTERNAL_H */
