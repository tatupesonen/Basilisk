/* The shim between Rust and binutils' libopcodes (see bk_gdis.h).
 *
 * It does what Ghidra's gdis (GPL/GnuDisassembler/src/gdis/c/disasm_1.c)
 * does per request - set up a disassemble_info for an architecture, run
 * the target's print function over a buffer, capture the printed text -
 * and adds the three protections the Rust side relies on:
 *
 *   Reads   every read binutils makes goes through bk_read_memory, which
 *           refuses anything outside the caller's buffer;
 *   Writes  text is appended to the caller's buffer with a running bound;
 *   Trap    abort(), exit() and failed assertions inside binutils end the
 *           current call with BK_GDIS_ABORTED instead of the process.
 */

/* The vendored sources are compiled with -Dabort=bk_gdis_abort and
   -Dexit=bk_gdis_exit.  This file defines those two and needs the real
   ones. */
#undef abort
#undef exit

#include "config.h"

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bfd.h"
#include "dis-asm.h"

#include "bk_gdis.h"
#include "bk_gdis_internal.h"

struct bk_gdis
{
  struct disassemble_info info;
  disassembler_ftype print;     /* the target's print_insn function */
  enum bfd_architecture arch;
  unsigned long mach;
  enum bfd_endian endian;
  char *options;                /* as given, or NULL */
  char *options_scratch;        /* the copy binutils may edit, or NULL */
  int info_live;                /* info holds target state to free */

  /* Stand-in for the BFD gdis passes to disassembler(); see bk_abfd.  */
  bfd abfd;
  bfd_target xvec;
  bfd_arch_info_type arch_info;

  /* The buffer and text of the bk_gdis_step in progress.  */
  const uint8_t *buf;
  size_t buf_len;
  uint64_t buf_vma;
  char *text;
  size_t text_cap;
  size_t text_len;
  int text_truncated;
  int read_fault;
  uint64_t fault_address;
};

/* The layouts src/real.rs declares; the same numbers are asserted there.  */
_Static_assert (sizeof (bk_gdis_insn) == 40
                && offsetof (bk_gdis_insn, fault_address) == 16
                && offsetof (bk_gdis_insn, target2) == 32,
                "bk_gdis_insn layout");
_Static_assert (sizeof (void *) != 8 || sizeof (bk_gdis_arch) == 40,
                "bk_gdis_arch layout");

/* The disassembler whose static state libopcodes currently holds.  */
static bk_gdis *bk_owner;

/* ---- Trap ------------------------------------------------------------ */

/* sigsetjmp-free variants where they exist: the signal mask is of no
   interest and saving it costs a system call per instruction.  */
#if defined(_WIN32)
# define BK_SETJMP(env) setjmp (env)
# define BK_LONGJMP(env, v) longjmp (env, v)
#else
# define BK_SETJMP(env) _setjmp (env)
# define BK_LONGJMP(env, v) _longjmp (env, v)
#endif

static jmp_buf bk_trap;
static int bk_trap_armed;
static char bk_message[256];
static int bk_message_set;

/* Arms the trap for the rest of the enclosing function.  Only C frames of
   this shim and of binutils lie between the setjmp and any longjmp.  */
#define BK_GUARD(on_abort)                      \
  do                                            \
    {                                           \
      if (BK_SETJMP (bk_trap) != 0)             \
        {                                       \
          bk_trap_armed = 0;                    \
          on_abort;                             \
        }                                       \
      bk_trap_armed = 1;                        \
    }                                           \
  while (0)

#define BK_UNGUARD() (bk_trap_armed = 0)

static void
bk_vnote (const char *fmt, va_list ap)
{
  if (bk_message_set)
    return;
  vsnprintf (bk_message, sizeof bk_message, fmt, ap);
  bk_message_set = 1;
}

void
bk_gdis_note (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  bk_vnote (fmt, ap);
  va_end (ap);
}

void
bk_gdis_vnote (const char *fmt, va_list ap)
{
  bk_vnote (fmt, ap);
}

void
bk_gdis_fatal (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  bk_vnote (fmt, ap);
  va_end (ap);
  if (bk_trap_armed)
    BK_LONGJMP (bk_trap, 1);
  /* Not reachable through this shim: every entry point arms the trap.  */
  abort ();
}

/* abort() in the vendored sources.  */
void
bk_gdis_abort (void)
{
  bk_gdis_fatal ("binutils called abort()");
}

/* exit() in the vendored sources (out-of-memory paths).  */
void
bk_gdis_exit (int code)
{
  bk_gdis_fatal ("binutils called exit(%d)", code);
}

/* A failed assert() in the vendored sources (shim/include/assert.h).  */
void
bk_gdis_assert_fail (const char *expr, const char *file, int line)
{
  bk_gdis_fatal ("binutils assertion failed: %s (%s:%d)", expr, file, line);
}

size_t
bk_gdis_take_message (char *buf, size_t cap)
{
  size_t n;

  if (!bk_message_set || cap == 0)
    return 0;
  n = strlen (bk_message);
  if (n >= cap)
    n = cap - 1;
  memcpy (buf, bk_message, n);
  buf[n] = '\0';
  bk_message_set = 0;
  return n;
}

/* ---- Callbacks handed to libopcodes ---------------------------------- */

static int
bk_vappend (bk_gdis *d, const char *fmt, va_list ap)
{
  size_t room;
  int n;

  if (d->text == NULL || d->text_cap == 0)
    return 0;
  /* Invariant: text_len < text_cap, so room >= 1 and the NUL fits.  */
  room = d->text_cap - d->text_len;
  n = vsnprintf (d->text + d->text_len, room, fmt, ap);
  if (n < 0)
    {
      d->text[d->text_len] = '\0';
      return n;
    }
  if ((size_t) n >= room)
    {
      d->text_len = d->text_cap - 1;
      d->text_truncated = 1;
    }
  else
    d->text_len += (size_t) n;
  return n;
}

static int
bk_printf (void *stream, const char *fmt, ...)
{
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = bk_vappend ((bk_gdis *) stream, fmt, ap);
  va_end (ap);
  return n;
}

static int
bk_printf_styled (void *stream, enum disassembler_style style, const char *fmt,
                  ...)
{
  va_list ap;
  int n;

  (void) style;
  va_start (ap, fmt);
  n = bk_vappend ((bk_gdis *) stream, fmt, ap);
  va_end (ap);
  return n;
}

static void
bk_fault (bk_gdis *d, bfd_vma memaddr)
{
  if (!d->read_fault)
    {
      d->read_fault = 1;
      d->fault_address = (uint64_t) memaddr;
    }
}

/* The only way libopcodes obtains bytes: copies LENGTH bytes at MEMADDR
   if, and only if, all of them lie inside the buffer of the current
   step.  */
static int
bk_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
                struct disassemble_info *info)
{
  bk_gdis *d = (bk_gdis *) info->application_data;
  uint64_t offset;

  if (d->buf == NULL || (uint64_t) memaddr < d->buf_vma)
    goto refuse;
  offset = (uint64_t) memaddr - d->buf_vma;
  if (offset > d->buf_len || length > d->buf_len - offset)
    goto refuse;
  memcpy (myaddr, d->buf + offset, length);
  return 0;

 refuse:
  bk_fault (d, memaddr);
  return EIO;
}

/* gdis lets libopcodes print "Address 0x... is out of bounds." into the
   instruction text here; the fault is recorded for Rust instead.  */
static void
bk_memory_error (int status, bfd_vma memaddr, struct disassemble_info *info)
{
  (void) status;
  bk_fault ((bk_gdis *) info->application_data, memaddr);
}

/* ---- Setup ----------------------------------------------------------- */

/* The BFD argument of disassembler().  gdis passes the BFD of a dummy
   file opened with target "pef" and no format check: a BFD without
   sections or ELF data, whose target has no symbol prefix.  Among the
   targets that look at the argument, only CRIS behaves differently for
   such a BFD than for none (it picks the v32 decoder from the BFD's
   machine), so CRIS gets a stand-in with exactly those properties and
   every other target gets NULL - which also keeps ARC from searching a
   BFD that has no section table.  */
static bfd *
bk_abfd (bk_gdis *d)
{
  if (d->arch != bfd_arch_cris)
    return NULL;
  memset (&d->abfd, 0, sizeof d->abfd);
  memset (&d->xvec, 0, sizeof d->xvec);
  memset (&d->arch_info, 0, sizeof d->arch_info);
  d->xvec.flavour = bfd_target_unknown_flavour;
  d->xvec.byteorder = d->endian;
  d->xvec.symbol_leading_char = 0;
  d->arch_info.arch = d->arch;
  d->arch_info.mach = d->mach;
  d->abfd.xvec = &d->xvec;
  d->abfd.arch_info = &d->arch_info;
  return &d->abfd;
}

static void
bk_release_info (bk_gdis *d)
{
  if (d->info_live)
    {
      d->info_live = 0;
      disassemble_free_target (&d->info);
    }
}

/* Brings D to the state of a fresh gdis request.  Differences from gdis'
   sequence, each recorded in docs/features/gnu-disasm.md:
     - the options are in place before the target is initialised, as in
       objdump, so targets that read them then (PowerPC, S/390) see them;
     - endian_code is set along with endian, as in objdump;
     - the flavour is ELF where gdis ends up with PEF;
     - memory errors are recorded, not printed.  */
static int32_t
bk_setup (bk_gdis *d)
{
  bk_release_info (d);

  init_disassemble_info (&d->info, d, bk_printf, bk_printf_styled);
  d->info.application_data = d;
  d->info.arch = d->arch;
  d->info.mach = d->mach;
  d->info.flavour = bfd_target_elf_flavour;
  d->info.endian = d->endian;
  d->info.endian_code = d->endian;
  d->info.display_endian = d->endian;
  d->info.read_memory_func = bk_read_memory;
  d->info.memory_error_func = bk_memory_error;
  if (d->options != NULL)
    {
      /* Targets edit the string (remove_whitespace_and_extra_commas) and
         clear the pointer once parsed, so each request gets a new copy.  */
      strcpy (d->options_scratch, d->options);
      d->info.disassembler_options = d->options_scratch;
    }
  d->info_live = 1;
  disassemble_init_for_target (&d->info);

  /* disassembler() also resets static state of some targets (RISC-V's
     subset list, C-SKY's ISA flags), so it runs again whenever another
     disassembler has used libopcodes in between.  */
  if (bk_owner != d || d->print == NULL)
    {
      bk_owner = NULL;
      d->print = disassembler (d->arch, d->endian == BFD_ENDIAN_BIG, d->mach,
                               bk_abfd (d));
      if (d->print == NULL)
        return BK_GDIS_NO_DISASSEMBLER;
      bk_owner = d;
    }
  return BK_GDIS_OK;
}

/* ---- Entry points ---------------------------------------------------- */

int32_t
bk_gdis_arch_list (char *buf, size_t cap, size_t *needed)
{
  const char **list;
  size_t used = 0;
  size_t total = 0;
  size_t i;

  if (needed == NULL || (buf == NULL && cap != 0))
    return BK_GDIS_BAD_ARGUMENT;
  *needed = 0;
  BK_GUARD (return BK_GDIS_ABORTED);
  list = bfd_arch_list ();
  if (list == NULL)
    {
      BK_UNGUARD ();
      return BK_GDIS_NO_MEMORY;
    }
  for (i = 0; list[i] != NULL; i++)
    {
      size_t n = strlen (list[i]) + 1;

      if (total == used && n <= cap - used)
        {
          memcpy (buf + used, list[i], n);
          used += n;
        }
      total += n;
    }
  free (list);
  BK_UNGUARD ();
  *needed = total;
  return BK_GDIS_OK;
}

int32_t
bk_gdis_scan_arch (const char *name, bk_gdis_arch *out)
{
  const bfd_arch_info_type *info;

  if (name == NULL || out == NULL)
    return BK_GDIS_BAD_ARGUMENT;
  memset (out, 0, sizeof *out);
  BK_GUARD (return BK_GDIS_ABORTED);
  info = bfd_scan_arch (name);
  BK_UNGUARD ();
  if (info == NULL)
    return BK_GDIS_UNKNOWN_ARCH;
  out->arch = (uint32_t) info->arch;
  out->mach = (uint64_t) info->mach;
  out->bits_per_word = (uint32_t) info->bits_per_word;
  out->bits_per_address = (uint32_t) info->bits_per_address;
  out->arch_name = info->arch_name;
  out->printable_name = info->printable_name;
  return BK_GDIS_OK;
}

bk_gdis *
bk_gdis_create (uint32_t arch, uint64_t mach, int big_endian,
                const char *options, int32_t *status)
{
  /* volatile: read after a longjmp back into this frame.  */
  bk_gdis *volatile d = NULL;
  int32_t dummy;
  int32_t rc;

  if (status == NULL)
    status = &dummy;
  *status = BK_GDIS_NO_MEMORY;

  d = (bk_gdis *) calloc (1, sizeof (bk_gdis));
  if (d == NULL)
    return NULL;
  d->arch = (enum bfd_architecture) arch;
  d->mach = (unsigned long) mach;
  d->endian = big_endian ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
  if (options != NULL)
    {
      size_t n = strlen (options) + 1;

      d->options = (char *) malloc (n);
      d->options_scratch = (char *) malloc (n);
      if (d->options == NULL || d->options_scratch == NULL)
        goto fail;
      memcpy (d->options, options, n);
    }

  BK_GUARD ({ *status = BK_GDIS_ABORTED; goto fail_unowned; });
  rc = bk_setup (d);
  BK_UNGUARD ();
  if (rc != BK_GDIS_OK)
    {
      *status = rc;
      goto fail_unowned;
    }
  *status = BK_GDIS_OK;
  return d;

 fail_unowned:
  if (bk_owner == d)
    bk_owner = NULL;
  /* The target state of a setup that did not complete is not released:
     freeing what an aborted initialisation left behind is not safe.  */
 fail:
  free (d->options);
  free (d->options_scratch);
  free (d);
  return NULL;
}

int32_t
bk_gdis_begin (bk_gdis *d)
{
  int32_t rc;

  if (d == NULL)
    return BK_GDIS_BAD_ARGUMENT;
  BK_GUARD ({
    /* Whatever the aborted setup left in info is abandoned.  */
    d->info_live = 0;
    d->print = NULL;
    if (bk_owner == d)
      bk_owner = NULL;
    return BK_GDIS_ABORTED;
  });
  rc = bk_setup (d);
  BK_UNGUARD ();
  return rc;
}

int32_t
bk_gdis_step (bk_gdis *d, uint8_t *buf, size_t len, uint64_t vma,
              size_t offset, char *text, size_t text_cap, bk_gdis_insn *out)
{
  int n;

  if (d == NULL || out == NULL || buf == NULL || text == NULL || text_cap == 0
      || offset >= len || d->print == NULL || !d->info_live)
    return BK_GDIS_BAD_ARGUMENT;
  memset (out, 0, sizeof *out);

  d->buf = buf;
  d->buf_len = len;
  d->buf_vma = vma;
  d->text = text;
  d->text_cap = text_cap;
  d->text_len = 0;
  d->text_truncated = 0;
  d->read_fault = 0;
  d->fault_address = 0;
  text[0] = '\0';

  /* A few targets look at the buffer directly instead of calling
     read_memory_func (tic30-dis.c, csky-dis.c); they bound themselves by
     these fields, as gdis sets them.  */
  d->info.buffer = buf;
  d->info.buffer_length = len;
  d->info.buffer_vma = vma;

  /* gdis clears only insn_info_valid; the rest is cleared too so that a
     target which sets nothing does not report the previous instruction's
     values.  */
  d->info.insn_info_valid = 0;
  d->info.branch_delay_insns = 0;
  d->info.data_size = 0;
  d->info.insn_type = dis_noninsn;
  d->info.target = 0;
  d->info.target2 = 0;

  BK_GUARD ({
    /* The target was interrupted mid-instruction: whatever it keeps in
       info is abandoned (not freed), and the next bk_gdis_begin starts
       over.  */
    d->buf = NULL;
    d->text = NULL;
    d->info_live = 0;
    d->print = NULL;
    if (bk_owner == d)
      bk_owner = NULL;
    return BK_GDIS_ABORTED;
  });
  n = d->print ((bfd_vma) (vma + offset), &d->info);
  BK_UNGUARD ();

  out->length = (int32_t) n;
  out->text_len = (uint32_t) d->text_len;
  out->text_truncated = (uint8_t) d->text_truncated;
  out->read_fault = (uint8_t) d->read_fault;
  out->fault_address = d->fault_address;
  out->insn_info_valid = (uint8_t) (d->info.insn_info_valid != 0);
  out->branch_delay_insns = (uint8_t) d->info.branch_delay_insns;
  out->data_size = (uint8_t) d->info.data_size;
  out->insn_type = (uint8_t) d->info.insn_type;
  out->target = (uint64_t) d->info.target;
  out->target2 = (uint64_t) d->info.target2;

  /* Nothing of the caller's is kept after the call.  */
  d->buf = NULL;
  d->text = NULL;
  d->info.buffer = NULL;
  d->info.buffer_length = 0;
  return BK_GDIS_OK;
}

int32_t
bk_gdis_destroy (bk_gdis *d)
{
  /* volatile: written before and read after a possible longjmp.  */
  volatile int32_t rc = BK_GDIS_OK;

  if (d == NULL)
    return BK_GDIS_OK;
  if (bk_owner == d)
    bk_owner = NULL;
  if (BK_SETJMP (bk_trap) != 0)
    {
      bk_trap_armed = 0;
      rc = BK_GDIS_ABORTED;
    }
  else
    {
      bk_trap_armed = 1;
      bk_release_info (d);
      bk_trap_armed = 0;
    }
  free (d->options);
  free (d->options_scratch);
  free (d);
  return rc;
}
