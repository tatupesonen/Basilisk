// The handlers of UndefinedBehaviorSanitizer's minimal runtime, replaced so
// that every event is recorded against the current oracle row (the stock
// runtime reports each source location only once per process). Each handler
// appends " ub=<kind>@<pc>" for the instrumented code's call site, once per
// (kind, pc) per row. Linked only into the --marks=ub build (regen.sh).

#include <cstdio>
#include <cstring>

extern "C" {
extern char bk_ub_marks[4096];
extern unsigned bk_ub_len;
}

static void record(const char *kind, void *pc) {
  char item[96];
  int n = snprintf(item, sizeof item, " ub=%s@%lx", kind, (unsigned long)pc);
  if (n <= 0) return;
  bk_ub_marks[bk_ub_len] = 0;
  if (strstr(bk_ub_marks, item) != nullptr) return;
  if (bk_ub_len + (unsigned)n + 1 >= sizeof bk_ub_marks) return;
  memcpy(bk_ub_marks + bk_ub_len, item, (size_t)n + 1);
  bk_ub_len += (unsigned)n;
}

#define HANDLER(name)                                                                  \
  extern "C" __attribute__((noinline)) void __ubsan_handle_##name##_minimal() {        \
    record(#name, __builtin_return_address(0));                                        \
  }                                                                                    \
  extern "C" __attribute__((noinline)) void __ubsan_handle_##name##_minimal_abort() {  \
    record(#name, __builtin_return_address(0));                                        \
  }

HANDLER(type_mismatch)
HANDLER(alignment_assumption)
HANDLER(add_overflow)
HANDLER(sub_overflow)
HANDLER(mul_overflow)
HANDLER(negate_overflow)
HANDLER(divrem_overflow)
HANDLER(shift_out_of_bounds)
HANDLER(out_of_bounds)
HANDLER(local_out_of_bounds)
HANDLER(builtin_unreachable)
HANDLER(missing_return)
HANDLER(vla_bound_not_positive)
HANDLER(float_cast_overflow)
HANDLER(load_invalid_value)
HANDLER(invalid_builtin)
HANDLER(invalid_objc_cast)
HANDLER(function_type_mismatch)
HANDLER(implicit_conversion)
HANDLER(nonnull_arg)
HANDLER(nonnull_return)
HANDLER(nullability_arg)
HANDLER(nullability_return)
HANDLER(pointer_overflow)
HANDLER(cfi_check_fail)
