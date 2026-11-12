/* Replacement for the C library's <assert.h>, seen only by the vendored
 * binutils sources (this directory comes first on their include path).
 *
 * binutils is built with assertions enabled, and a failed assertion calls
 * abort().  The bytes being disassembled come from untrusted binaries, so a
 * failed assertion must not take the process down, and it must not be
 * compiled out either (code after a failed assertion may index out of
 * bounds).  Here a failed assertion ends the current shim call and is
 * reported to Rust as an error; see bk_gdis_fatal() in bk_gdis.c.
 *
 * No include guard: like the real header, this one may be included again.
 */
#undef assert

#if defined(__GNUC__) || defined(__clang__)
void bk_gdis_assert_fail (const char *expr, const char *file, int line)
  __attribute__ ((__noreturn__));
#else
void bk_gdis_assert_fail (const char *expr, const char *file, int line);
#endif

#define assert(e) \
  ((e) ? (void) 0 : bk_gdis_assert_fail (#e, __FILE__, __LINE__))

#if !defined(static_assert) && !defined(__cplusplus)
# define static_assert _Static_assert
#endif
