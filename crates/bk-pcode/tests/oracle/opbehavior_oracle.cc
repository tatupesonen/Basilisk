// Differential oracle for bk-pcode's u64 path: evaluates every p-code
// operation with Ghidra's own C++ OpBehavior classes (opbehavior.cc and
// float.cc, linked from the reference build's libsla.a) on a fixed,
// deterministic set of operands and sizes, and prints one line per case.
//
// Built and run by regen.sh; its output is tests/data/opbehavior_cpp.txt,
// which tests/cpp_oracle.rs compares with Basilisk. Not part of the Rust
// build.
//
// The inputs, and their order, are the same on every host and compiler:
// every random draw is a separate statement (never two in one argument
// list, whose evaluation order C++ leaves unspecified). Only the results
// may differ between hosts, so two tables compare line by line.
//
// Line format (hexadecimal numbers, no prefix):
//   U <op> <sizeout> <sizein> <in1> = <result>|E
//   B <op> <sizeout> <sizein> <in1> <in2> = <result>|E
//   T <op> <sizeout> <sizein> <in1> <in2> <in3> = <result>|E
//   RU <op> <sizeout> <out> <sizein> = <result>|E
//   RB <op> <slot> <sizeout> <out> <sizein> <in> = <result>|E
// where E means the C++ threw (an evaluation or low-level error).

#include "opbehavior.hh"
#include "translate.hh"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace ghidra;

namespace {

// A Translate that only carries the default float formats (4 and 8 bytes),
// which is all the float behaviours ask it for.
class FormatsOnly : public Translate {
public:
  FormatsOnly(void) { setDefaultFloatFormats(); }
  void initialize(DocumentStorage &store) override {}
  const VarnodeData &getRegister(const string &nm) const override { throw LowlevelError("unused"); }
  string getRegisterName(AddrSpace *base, uintb off, int4 size) const override { return ""; }
  string getExactRegisterName(AddrSpace *base, uintb off, int4 size) const override { return ""; }
  void getAllRegisters(map<VarnodeData, string> &reglist) const override {}
  void getUserOpNames(vector<string> &res) const override {}
  int4 instructionLength(const Address &baseaddr) const override { return 0; }
  int4 oneInstruction(PcodeEmit &emit, const Address &baseaddr) const override { return 0; }
  int4 printAssembly(AssemblyEmit &emit, const Address &baseaddr) const override { return 0; }
};

uint64_t rng_state = 0x0123456789abcdefULL;

// splitmix64
uint64_t next_random(void) {
  uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

uint64_t mask(int size) { return size >= 8 ? ~0ULL : ((1ULL << (8 * size)) - 1); }

// Integer operands of `size` bytes: edge values, then random ones, then a
// few with bits above the size (Ghidra's callers normally keep operands
// clean, but the behaviours are defined on any u64).
vector<uint64_t> int_values(int size, int randoms) {
  uint64_t m = mask(size);
  uint64_t sign = (m >> 1) + 1;
  vector<uint64_t> v = {0, 1, 2, 3, 7, 8, m, m - 1, sign, sign - 1, sign + 1,
                        0x5555555555555555ULL & m, 0xaaaaaaaaaaaaaaaaULL & m};
  for (int i = 0; i < randoms; ++i) v.push_back(next_random() & m);
  if (size < 8) {
    v.push_back(next_random());
    v.push_back(m + 1);
  }
  return v;
}

// Shift amounts.
vector<uint64_t> shift_values(void) {
  vector<uint64_t> v = {0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 23, 24, 31, 32, 33,
                        39, 40, 47, 48, 55, 56, 63, 64, 65, 127, 128, 0x100000000ULL, ~0ULL};
  return v;
}

uint64_t f4(float f) { uint32_t b; memcpy(&b, &f, 4); return b; }
uint64_t f8(double d) { uint64_t b; memcpy(&b, &d, 8); return b; }

// Float encodings of `size` (4 or 8) bytes: classes and rounding edges.
vector<uint64_t> float_values(int size, int randoms) {
  vector<uint64_t> v;
  if (size == 4) {
    float list[] = {0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 1.5f, 2.5f, -2.5f, 3.5f, 0.49999997f,
                    -1.234f, 1e10f, -1e10f, 3e9f, 1e30f, -1e30f, 9.2233720e18f, -9.2233720e18f, 0.1f};
    for (float f : list) v.push_back(f4(f));
    uint64_t bits[] = {1, 0x80000001, 0x007fffff, 0x807fffff, 0x00800000, 0x80800000,
                       0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fc00000, 0xffc00000,
                       0x7f800001, 0xff800001, 0x7fffffff, 0x4b000001, 0x5f000000, 0xdf000000};
    for (uint64_t b : bits) v.push_back(b);
    for (int i = 0; i < randoms; ++i) v.push_back(next_random() & 0xffffffffULL);
  } else {
    double list[] = {0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1.5, 2.5, -2.5, 3.5, 0.49999999999999994,
                     -1.234, 1e10, -1e10, 3e9, 1e300, -1e300, 9.2233720368547758e18,
                     -9.2233720368547758e18, 0.1, 1e-310, 3.4028235677973366e38,
                     1.1754942807573643e-38, 1.401298464324817e-45, 7.006492321624085e-46};
    for (double d : list) v.push_back(f8(d));
    uint64_t bits[] = {1, 0x8000000000000001ULL, 0x000fffffffffffffULL, 0x0010000000000000ULL,
                       0x7fefffffffffffffULL, 0xffefffffffffffffULL, 0x7ff0000000000000ULL,
                       0xfff0000000000000ULL, 0x7ff8000000000000ULL, 0xfff8000000000000ULL,
                       0x7ff0000000000001ULL, 0xfff0000000000001ULL, 0x7fffffffffffffffULL,
                       0x43e0000000000000ULL, 0xc3e0000000000000ULL, 0x43e0000000000001ULL,
                       0x380fffffefffffffULL, 0x380ffffff0000000ULL, 0x36a0000000000000ULL};
    for (uint64_t b : bits) v.push_back(b);
    for (int i = 0; i < randoms; ++i) v.push_back(next_random());
  }
  return v;
}

const char *E = "E";

void print_result(bool ok, uint64_t r) {
  if (ok) printf("%llx\n", (unsigned long long)r);
  else printf("%s\n", E);
}

void unary(const OpBehavior *b, int op, int out, int in, uint64_t a) {
  printf("U %x %x %x %llx = ", op, out, in, (unsigned long long)a);
  uint64_t r = 0;
  bool ok = true;
  try { r = b->evaluateUnary(out, in, a); } catch (...) { ok = false; }
  print_result(ok, r);
}

void binary(const OpBehavior *b, int op, int out, int in, uint64_t a, uint64_t c) {
  printf("B %x %x %x %llx %llx = ", op, out, in, (unsigned long long)a, (unsigned long long)c);
  uint64_t r = 0;
  bool ok = true;
  try { r = b->evaluateBinary(out, in, a, c); } catch (...) { ok = false; }
  print_result(ok, r);
}

void ternary(const OpBehavior *b, int op, int out, int in, uint64_t a, uint64_t c, uint64_t d) {
  printf("T %x %x %x %llx %llx %llx = ", op, out, in, (unsigned long long)a,
         (unsigned long long)c, (unsigned long long)d);
  uint64_t r = 0;
  bool ok = true;
  try { r = b->evaluateTernary(out, in, a, c, d); } catch (...) { ok = false; }
  print_result(ok, r);
}

void recover_unary(const OpBehavior *b, int op, int out, uint64_t o, int in) {
  printf("RU %x %x %llx %x = ", op, out, (unsigned long long)o, in);
  uint64_t r = 0;
  bool ok = true;
  try { r = b->recoverInputUnary(out, o, in); } catch (...) { ok = false; }
  print_result(ok, r);
}

void recover_binary(const OpBehavior *b, int op, int slot, int out, uint64_t o, int in, uint64_t x) {
  printf("RB %x %x %x %llx %x %llx = ", op, slot, out, (unsigned long long)o, in,
         (unsigned long long)x);
  uint64_t r = 0;
  bool ok = true;
  try { r = b->recoverInputBinary(slot, out, o, in, x); } catch (...) { ok = false; }
  print_result(ok, r);
}

// A binary case on two random operands of `bytes` bytes. The draws are
// sequenced explicitly, second operand first: C++ leaves the order in which
// function arguments are evaluated unspecified (GCC on x86-64 evaluates
// right to left, clang left to right), and the table must not depend on the
// compiler. The order is the one GCC used for the table checked in on
// 2026-11-14, so this generator reproduces its inputs on every host.
void random_pair(const OpBehavior *b, int op, int out, int in, int bytes) {
  uint64_t c = next_random() & mask(bytes);
  uint64_t a = next_random() & mask(bytes);
  binary(b, op, out, in, a, c);
}

bool is_float_op(int op) { return op >= CPUI_FLOAT_EQUAL && op <= CPUI_FLOAT_ROUND; }

bool is_shift(int op) { return op == CPUI_INT_LEFT || op == CPUI_INT_RIGHT || op == CPUI_INT_SRIGHT; }

}  // namespace

int main(void) {
  FormatsOnly trans;
  vector<OpBehavior *> inst;
  OpBehavior::registerInstructions(inst, &trans);
  // The decompiler's wiring (typeop.cc) of the two pointer operations.
  inst[CPUI_PTRADD] = new OpBehaviorPtradd();
  inst[CPUI_PTRSUB] = new OpBehaviorPtrsub();

  const int int_sizes[] = {1, 2, 3, 4, 5, 6, 7, 8};
  for (int op = 1; op < CPUI_MAX; ++op) {
    const OpBehavior *b = inst[op];
    if (b == (const OpBehavior *)0) continue;
    if (b->isSpecial()) {
      // No arithmetic: every entry point throws.
      unary(b, op, 4, 4, 1);
      binary(b, op, 4, 4, 1, 2);
      ternary(b, op, 4, 4, 1, 2, 3);
      continue;
    }
    if (is_float_op(op)) {
      // Same-size operations at 4 and 8 bytes, plus the size changes each
      // conversion allows and sizes with no format.
      for (int fs : {4, 8}) {
        vector<uint64_t> vals = float_values(fs, 1);
        if (b->isUnary()) {
          vector<int> outs;
          if (op == CPUI_FLOAT_NAN) outs = {1};
          else if (op == CPUI_FLOAT_TRUNC) outs = {1, 2, 4, 8};
          else if (op == CPUI_FLOAT_FLOAT2FLOAT) outs = {4, 8, 2};
          else outs = {fs};
          if (op == CPUI_FLOAT_INT2FLOAT) {
            for (int in : {1, 2, 4, 8, 3})
              for (uint64_t a : int_values(in, 6)) unary(b, op, fs, in, a);
            continue;
          }
          for (int out : outs)
            for (uint64_t a : vals) unary(b, op, out, fs, a);
        }
        else {
          int out = (op <= CPUI_FLOAT_NAN) ? 1 : fs;
          for (uint64_t a : vals)
            for (uint64_t c : vals) binary(b, op, out, fs, a, c);
        }
      }
      // No float format for 2 or 10 bytes.
      if (b->isUnary()) unary(b, op, 2, 2, 0x3c00);
      else binary(b, op, 2, 2, 0x3c00, 0x3c00);
      continue;
    }
    if (op == CPUI_PTRADD) {
      for (int s : {1, 2, 4, 8})
        for (int i = 0; i < 40; ++i) {
          // Last operand drawn first: see random_pair.
          uint64_t d = next_random() & 0x1f;
          uint64_t c = next_random() & 0xff;
          uint64_t a = next_random() & mask(s);
          ternary(b, op, s, s, a, c, d);
        }
      continue;
    }
    if (b->isUnary()) {
      for (int in : int_sizes) {
        vector<int> outs = {in, 1, 2, 4, 8};
        for (int out : outs)
          for (uint64_t a : int_values(in, 3)) unary(b, op, out, in, a);
      }
      // Size 0 and recovery.
      unary(b, op, 0, 0, 5);
      for (int in : {1, 2, 4, 8}) {
        for (int out : {in, 8})
          for (uint64_t o : int_values(out, 1)) recover_unary(b, op, out, o, in);
      }
      continue;
    }
    // Binary integer and boolean operations: every pair of edge values at
    // 1, 4 and 8 bytes, random pairs at the other sizes.
    for (int in : int_sizes) {
      vector<int> outs;
      if (op == CPUI_PIECE) outs = {in * 2 > 8 ? 8 : in * 2, in + 1 > 8 ? 8 : in + 1};
      else if (op == CPUI_SUBPIECE) outs = {1, in, (in + 1) / 2};
      else outs = {in};
      bool full = (in == 1 || in == 4 || in == 8);
      vector<uint64_t> vals = int_values(in, full ? 2 : 0);
      vector<uint64_t> seconds = vals;
      if (is_shift(op)) seconds = shift_values();
      if (op == CPUI_SUBPIECE) seconds = {0, 1, 2, 3, 4, 7, 8, 9, 64, ~0ULL};
      for (int out : outs) {
        if (full || is_shift(op) || op == CPUI_SUBPIECE) {
          for (uint64_t a : vals)
            for (uint64_t c : seconds) binary(b, op, out, in, a, c);
        }
        else {
          for (int i = 0; i < 24; ++i) random_pair(b, op, out, in, in);
        }
      }
    }
    // A differing output size.
    for (int i = 0; i < 24; ++i) {
      random_pair(b, op, 8, 4, 4);
      random_pair(b, op, 2, 4, 4);
    }
    binary(b, op, 0, 0, 5, 3);
    // Recovery of either input.
    for (int in : {1, 2, 4, 8}) {
      uint64_t m = mask(in);
      // A braced list is evaluated left to right on every compiler.
      vector<uint64_t> vals = {0, 1, m, (m >> 1) + 1, next_random() & m, next_random() & m};
      for (int slot : {0, 1})
        for (uint64_t o : vals)
          for (uint64_t x : (is_shift(op) ? vector<uint64_t>{0, 1, 3, 8, 31, 63, 64} : vals))
            recover_binary(b, op, slot, in, o, in, x);
    }
  }
  return 0;
}
