/* The whole C surface of bk-binutils-sys: a few functions over binutils'
 * libopcodes, so that Rust never sees struct disassemble_info or a BFD.
 *
 * None of these functions is reentrant or thread-safe: libopcodes keeps
 * static state.  The Rust side holds one process-wide lock around every
 * call (src/real.rs).
 *
 * Every function returns normally even when binutils calls abort(), exit()
 * or fails an assertion: the call is abandoned and BK_GDIS_ABORTED is
 * reported (bk_gdis.c, "Trap").
 */
#ifndef BK_GDIS_H
#define BK_GDIS_H

#include <stddef.h>
#include <stdint.h>

/* Status codes (int32_t). */
#define BK_GDIS_OK 0
#define BK_GDIS_UNKNOWN_ARCH 1     /* no architecture of that name */
#define BK_GDIS_NO_DISASSEMBLER 2  /* libopcodes has no disassembler for it */
#define BK_GDIS_NO_MEMORY 3
#define BK_GDIS_ABORTED 4          /* binutils called abort()/exit()/assert */
#define BK_GDIS_BAD_ARGUMENT 5

typedef struct bk_gdis bk_gdis;

/* What bfd_scan_arch() found.  The strings are static storage in BFD. */
typedef struct bk_gdis_arch
{
  uint32_t arch;              /* enum bfd_architecture */
  uint64_t mach;
  uint32_t bits_per_word;
  uint32_t bits_per_address;
  const char *arch_name;      /* family, e.g. "i386" */
  const char *printable_name; /* e.g. "i386:x86-64" */
} bk_gdis_arch;

/* What one call of the disassembler reported. */
typedef struct bk_gdis_insn
{
  int32_t length;             /* the disassembler's return value: octets
                                 consumed, or <= 0 on failure */
  uint32_t text_len;          /* bytes of text written, without the NUL */
  uint8_t text_truncated;     /* the text did not fit the caller's buffer */
  uint8_t read_fault;         /* a read outside the buffer was refused */
  uint8_t insn_info_valid;    /* the fields below were set by the target */
  uint8_t branch_delay_insns;
  uint8_t data_size;
  uint8_t insn_type;          /* enum dis_insn_type */
  uint64_t fault_address;     /* address of the first refused read */
  uint64_t target;
  uint64_t target2;
} bk_gdis_insn;

/* Writes the printable names of all architectures (bfd_arch_list), each
   NUL-terminated, into BUF, as many whole names as fit in CAP bytes.
   Stores the number of bytes needed for all of them in *NEEDED. */
int32_t bk_gdis_arch_list (char *buf, size_t cap, size_t *needed);

/* Looks NAME up with bfd_scan_arch. */
int32_t bk_gdis_scan_arch (const char *name, bk_gdis_arch *out);

/* Creates a disassembler.  ARCH and MACH are BFD's numbers; OPTIONS is a
   NUL-terminated disassembler option string (objdump -M) or NULL, and is
   copied.  Returns NULL and sets *STATUS on failure. */
bk_gdis *bk_gdis_create (uint32_t arch, uint64_t mach, int big_endian,
                         const char *options, int32_t *status);

/* Starts a request: resets the disassembler to the state a fresh gdis
   request has (new disassemble_info, target initialised, options applied).
   Call before the first bk_gdis_step of a block. */
int32_t bk_gdis_begin (bk_gdis *d);

/* Disassembles the instruction at address VMA + OFFSET, where BUF[0..LEN)
   holds the bytes at addresses VMA .. VMA + LEN.  Reads outside the buffer
   are refused.  The text goes to TEXT[0..TEXT_CAP), always NUL-terminated
   and never overrun.
   BUF is not const: binutils is allowed to modify the bytes it reads
   (csky-dis.c rewrites an instruction in place), so the caller must own
   BUF exclusively and must not hand in read-only memory. */
int32_t bk_gdis_step (bk_gdis *d, uint8_t *buf, size_t len, uint64_t vma,
                      size_t offset, char *text, size_t text_cap,
                      bk_gdis_insn *out);

/* Frees a disassembler.  NULL is allowed. */
int32_t bk_gdis_destroy (bk_gdis *d);

/* Copies the first message binutils reported (error handler, abort,
   failed assertion) since the last call of this function into BUF,
   NUL-terminated, and forgets it.  Returns its length, 0 if none. */
size_t bk_gdis_take_message (char *buf, size_t cap);

#endif /* BK_GDIS_H */
