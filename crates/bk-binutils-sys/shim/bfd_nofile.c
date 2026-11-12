/* The BFD entry points that the compiled subset of binutils refers to but
 * that live in BFD's object-file machinery.
 *
 * libopcodes and the handful of BFD files built here (architecture tables,
 * byte-order helpers, RISC-V subset parsing, the Xtensa ISA tables) refer to
 * the functions below.  In binutils they are defined in bfd.c, section.c,
 * bfdio.c, reloc.c, elf.c, aout-ns32k.c and elf32-xtensa.c, and linking
 * those pulls in all of libbfd: every object-file backend (290 objects with
 * --enable-targets=all), plus zlib, zstd and libsframe.  A disassembler fed
 * from a byte buffer has no object file, so here they are defined for that
 * situation instead:
 *
 *   - error reporting is real: messages are kept for the Rust side;
 *   - bfd_scan_vma is the host-integer branch of the original;
 *   - everything that needs a section, a file or a relocation cannot be
 *     reached without a BFD (the shim passes none, and no section or
 *     symbol table).  Should one be reached anyway, the call is abandoned
 *     and reported as an error - never answered with made-up data.
 *
 * The prototypes come from binutils' headers, so a mismatch with the
 * originals is a compile error.
 */
#undef abort
#undef exit

#include "sysdep.h"   /* bfd/sysdep.h: config.h and the system headers */
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "ns32k.h"
#include "xtensa-isa.h"
#include "elf/xtensa.h"

#include "bk_gdis_internal.h"

/* libbfd.h turns abort() into _bfd_abort() for BFD's own files; this file
   wants neither. */
#undef abort

#define BK_NO_FILE(name) \
  bk_gdis_fatal ("binutils called %s, which needs an object file", name)

/* ---- Error reporting (bfd.c) ------------------------------------------ */

/* BFD's and libopcodes' way of reporting a problem (bad disassembler
   option, internal inconsistency).  The original prints to stderr.  The
   %pA and %pB extensions of the original take one pointer argument each,
   as plain %p does, so the argument list stays in step.  */
void
_bfd_error_handler (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  bk_gdis_vnote (fmt, ap);
  va_end (ap);
}

static bfd_error_type bk_bfd_error;

void
bfd_set_error (bfd_error_type error_tag)
{
  bk_bfd_error = error_tag;
}

/* BFD_ASSERT: the original reports and carries on. */
void
bfd_assert (const char *file, int line)
{
  bk_gdis_note ("BFD assertion failed (%s:%d)", file, line);
}

/* abort() inside BFD's files. */
void
_bfd_abort (const char *file, int line, const char *fn)
{
  bk_gdis_fatal ("BFD internal error in %s (%s:%d)", fn ? fn : "?", file,
                 line);
}

/* ---- Number parsing (bfd.c) -------------------------------------------- */

/* The original defers to strtoull when bfd_vma fits unsigned long long,
   which it does on every host this builds for. */
bfd_vma
bfd_scan_vma (const char *string, const char **end, int base)
{
  return (bfd_vma) strtoull (string, (char **) end, base);
}

/* ---- Sections (section.c) ---------------------------------------------- */

/* The standard sections exist as objects (code compares section pointers
   against them); nothing here ever hands them out. */
asection _bfd_std_section[4];

asection *
bfd_get_section_by_name (bfd *abfd ATTRIBUTE_UNUSED,
                         const char *name ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_get_section_by_name");
}

bool
bfd_get_section_contents (bfd *abfd ATTRIBUTE_UNUSED,
                          asection *section ATTRIBUTE_UNUSED,
                          void *location ATTRIBUTE_UNUSED,
                          file_ptr offset ATTRIBUTE_UNUSED,
                          bfd_size_type count ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_get_section_contents");
}

bool
bfd_malloc_and_get_section (bfd *abfd ATTRIBUTE_UNUSED,
                            asection *section ATTRIBUTE_UNUSED,
                            bfd_byte **buf ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_malloc_and_get_section");
}

bool
bfd_set_section_contents (bfd *abfd ATTRIBUTE_UNUSED,
                          asection *section ATTRIBUTE_UNUSED,
                          const void *data ATTRIBUTE_UNUSED,
                          file_ptr offset ATTRIBUTE_UNUSED,
                          bfd_size_type count ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_set_section_contents");
}

/* ---- File access (bfdio.c) --------------------------------------------- */

bfd_size_type
bfd_bread (void *ptr ATTRIBUTE_UNUSED, bfd_size_type size ATTRIBUTE_UNUSED,
           bfd *abfd ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_bread");
}

bfd_size_type
bfd_bwrite (const void *ptr ATTRIBUTE_UNUSED,
            bfd_size_type size ATTRIBUTE_UNUSED, bfd *abfd ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_bwrite");
}

int
bfd_seek (bfd *abfd ATTRIBUTE_UNUSED, file_ptr position ATTRIBUTE_UNUSED,
          int direction ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_seek");
}

/* ---- Relocations (reloc.c, elf.c, aout-ns32k.c) ------------------------ */

/* Named by the relocation tables in elfxx-riscv.c and cpu-ns32k.c; only a
   linker or an object-file reader calls them. */

bfd_reloc_status_type
bfd_elf_generic_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                       arelent *reloc_entry ATTRIBUTE_UNUSED,
                       asymbol *symbol ATTRIBUTE_UNUSED,
                       void *data ATTRIBUTE_UNUSED,
                       asection *input_section ATTRIBUTE_UNUSED,
                       bfd *output_bfd ATTRIBUTE_UNUSED,
                       char **error_message ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_elf_generic_reloc");
}

bool
bfd_reloc_offset_in_range (reloc_howto_type *howto ATTRIBUTE_UNUSED,
                           bfd *abfd ATTRIBUTE_UNUSED,
                           asection *section ATTRIBUTE_UNUSED,
                           bfd_size_type offset ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("bfd_reloc_offset_in_range");
}

bfd_reloc_status_type
_bfd_ns32k_relocate_contents (reloc_howto_type *howto ATTRIBUTE_UNUSED,
                              bfd *input_bfd ATTRIBUTE_UNUSED,
                              bfd_vma relocation ATTRIBUTE_UNUSED,
                              bfd_byte *location ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("_bfd_ns32k_relocate_contents");
}

/* ---- Xtensa (elf32-xtensa.c) ------------------------------------------- */

/* The ISA description the Xtensa disassembler creates on first use. */
xtensa_isa xtensa_default_isa;

/* Property tables are read from an object file's sections; xtensa-dis.c
   asks for them only when given a section. */
int
xtensa_read_table_entries (bfd *abfd ATTRIBUTE_UNUSED,
                           asection *section ATTRIBUTE_UNUSED,
                           property_table_entry **table_p ATTRIBUTE_UNUSED,
                           const char *sec_name ATTRIBUTE_UNUSED,
                           bool output_addr ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("xtensa_read_table_entries");
}

int
xtensa_compute_fill_extra_space (property_table_entry *entry ATTRIBUTE_UNUSED)
{
  BK_NO_FILE ("xtensa_compute_fill_extra_space");
}
