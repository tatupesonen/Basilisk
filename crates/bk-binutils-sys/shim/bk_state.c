/* libopcodes' static state that outlives one disassembler, and what the
 * shim does about it.
 *
 * gdis serves one configuration per process, so binutils' disassemblers
 * keep their options in static variables and parse them only when an
 * option string is given - or only once per process.  In process, a
 * disassembler created after another of the same architecture would
 * inherit what that one set (ARM staying in Thumb after "force-thumb").
 * The shim guarantees instead that a disassembler created with given
 * options behaves the same whatever was created before it:
 *
 *   Reset     for targets whose options persist but can be set back, the
 *             option string is prefixed with the options that restore
 *             binutils' defaults (or a global is reset directly);
 *   Once      for targets that apply options once per process, every
 *             disassembler must agree with the first one created, or its
 *             creation fails with BK_GDIS_OPTIONS_CONFLICT;
 *   Quarantine after binutils aborted inside a target, that target's
 *             static state may be half-updated, so its architecture family
 *             is refused (BK_GDIS_QUARANTINED) for the rest of the process.
 *
 * Every function here runs under the Rust side's lock, like the rest of
 * the shim.
 */
#undef abort
#undef exit

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "bfd.h"

#include "bk_gdis.h"
#include "bk_gdis_internal.h"

/* csky-dis.c: set by the "abi-names" option and never reset there.  It is
   a global, not a static, so the shim can reset it.  */
extern int using_abi;

/* ---- Reset ------------------------------------------------------------ */

/* Options that restore a target's defaults, or NULL when the target needs
   none.  The empty string means "any option string": the target resets
   its defaults whenever it parses one.  */
static const char *
bk_reset_prefix (enum bfd_architecture arch)
{
  switch (arch)
    {
    case bfd_arch_arm:
      /* arm-dis.c resets force_thumb whenever it parses options, but not
         the register names (regname_selected = 1: "reg-names-gcc") or the
         CDE coprocessors (cde_coprocs = 0: all generic).  */
      return "reg-names-gcc,"
             "coproc0=generic,coproc1=generic,coproc2=generic,coproc3=generic,"
             "coproc4=generic,coproc5=generic,coproc6=generic,coproc7=generic";
    case bfd_arch_aarch64:
      /* aarch64-dis.c: no_aliases = 0, no_notes = 1; its
         set_default_aarch64_dis_options does nothing.  */
      return "aliases,no-notes";
    case bfd_arch_riscv:
      /* riscv-dis.c calls set_default_riscv_dis_options (register names,
         aliases) for any option string, but keeps what it had when given
         none.  An empty string makes it complain about an empty option,
         which the Rust side discards.  */
      return "";
    default:
      return NULL;
    }
}

char *
bk_effective_options (enum bfd_architecture arch, const char *user,
                      int *no_memory)
{
  const char *prefix = bk_reset_prefix (arch);
  size_t np, nu;
  char *out;

  *no_memory = 0;
  if (user == NULL)
    user = "";
  if (prefix == NULL && *user == '\0')
    return NULL;
  if (prefix == NULL)
    prefix = "";
  np = strlen (prefix);
  nu = strlen (user);
  out = (char *) malloc (np + nu + 2);
  if (out == NULL)
    {
      *no_memory = 1;
      return NULL;
    }
  memcpy (out, prefix, np);
  if (np != 0 && nu != 0)
    out[np++] = ',';
  memcpy (out + np, user, nu + 1);
  return out;
}

void
bk_reset_target_globals (enum bfd_architecture arch)
{
  if (arch == bfd_arch_csky)
    using_abi = 0;
}

/* ---- Once ------------------------------------------------------------- */

struct bk_once
{
  enum bfd_architecture arch;
  int set;
  char *first;  /* the key of the first disassembler created */
};

/* arc-dis.c accumulates options (print_hex, the decode list) and keeps the
   last "cpu=" when given none; loongarch-dis.c and vax-dis.c parse options
   at most once per process; riscv-dis.c keeps the first privileged spec
   version for good (default_priv_spec).  */
static struct bk_once bk_once_table[] = {
  { bfd_arch_arc, 0, NULL },
  { bfd_arch_loongarch, 0, NULL },
  { bfd_arch_vax, 0, NULL },
  { bfd_arch_riscv, 0, NULL },
};

/* What must agree between disassemblers of ARCH: the whole option string,
   or for RISC-V its "priv-spec=" options.  Returns a malloc'd string, or
   NULL when out of memory.  */
static char *
bk_once_key (enum bfd_architecture arch, const char *user)
{
  const char *p;
  char *key;
  size_t n = 0;

  if (user == NULL)
    user = "";
  key = (char *) malloc (strlen (user) + 1);
  if (key == NULL)
    return NULL;
  if (arch != bfd_arch_riscv)
    {
      strcpy (key, user);
      return key;
    }
  for (p = user; *p != '\0';)
    {
      const char *end = strchr (p, ',');
      size_t len = end != NULL ? (size_t) (end - p) : strlen (p);

      if (len >= 10 && strncmp (p, "priv-spec=", 10) == 0)
        {
          if (n != 0)
            key[n++] = ',';
          memcpy (key + n, p, len);
          n += len;
        }
      p += len;
      if (*p == ',')
        p++;
    }
  key[n] = '\0';
  return key;
}

int32_t
bk_once_check (enum bfd_architecture arch, const char *user, int record)
{
  size_t i;
  char *key;

  for (i = 0; i < sizeof bk_once_table / sizeof bk_once_table[0]; i++)
    {
      struct bk_once *e = &bk_once_table[i];

      if (e->arch != arch)
        continue;
      key = bk_once_key (arch, user);
      if (key == NULL)
        return BK_GDIS_NO_MEMORY;
      if (e->set)
        {
          int same = strcmp (key, e->first) == 0;

          free (key);
          return same ? BK_GDIS_OK : BK_GDIS_OPTIONS_CONFLICT;
        }
      if (record)
        {
          e->first = key;
          e->set = 1;
        }
      else
        free (key);
      return BK_GDIS_OK;
    }
  return BK_GDIS_OK;
}

/* ---- Quarantine ------------------------------------------------------- */

/* One flag per architecture; values past bfd_arch_last share the last.  */
static unsigned char bk_quarantine_flags[(size_t) bfd_arch_last + 1];

/* Architectures whose disassemblers share one source file, and so one set
   of static variables, share their quarantine: the representative here.  */
static enum bfd_architecture
bk_family (uint32_t arch)
{
  if (arch >= (uint32_t) bfd_arch_last)
    return bfd_arch_last;
  switch ((enum bfd_architecture) arch)
    {
    case bfd_arch_iamcu:
      return bfd_arch_i386;               /* i386-dis.c */
    case bfd_arch_rs6000:
      return bfd_arch_powerpc;            /* ppc-dis.c */
    case bfd_arch_v850_rh850:
      return bfd_arch_v850;               /* v850-dis.c */
    case bfd_arch_m68hc12:
    case bfd_arch_m9s12x:
    case bfd_arch_m9s12xg:
      return bfd_arch_m68hc11;            /* m68hc11-dis.c */
    default:
      return (enum bfd_architecture) arch;
    }
}

void
bk_quarantine (uint32_t arch)
{
  bk_quarantine_flags[bk_family (arch)] = 1;
}

int
bk_quarantined (uint32_t arch)
{
  return bk_quarantine_flags[bk_family (arch)] != 0;
}
