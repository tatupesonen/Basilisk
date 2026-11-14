// Prints the results of Ghidra's compiled CircleRange (rangeutil.cc) for a
// fixed set of inputs, one line per case; tests/oracle_replay.rs replays every
// line against bk-decomp-range. Built by regen.sh against the reference
// build's objects with -fno-access-control (the fields are private).
//
// Usage: circlerange_oracle [--extended] [--marks=ub|--marks=uninit]
//   (no option)     the table (the base set of cases)
//   --extended      the full set of cases (larger sections, same generator)
//   --marks=ub      one line per table row: the UndefinedBehaviorSanitizer
//                   events of that row, " ub=<kind>@<pc>,..." (needs the
//                   objects built with -fsanitize-minimal-runtime and
//                   ubsan_hooks.cc linked in; regen.sh resolves the pcs)
//   --marks=uninit  one line per table row: " uninit" when, under valgrind,
//                   the row's result depends on the uninitialised fields of
//                   an empty range (needs -DBK_VALGRIND and valgrind)
//
// Every input comes from a fixed-seed generator, so the output is a function
// of the compiled code alone. Line formats are described in tests/data/README.md.

#include "rangeutil.hh"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#ifdef BK_VALGRIND
#include <valgrind/memcheck.h>
#endif

using namespace ghidra;
using std::string;
using std::vector;

namespace {

enum Mode { TABLE, MARK_UB, MARK_UNINIT };
Mode mode = TABLE;
string line;   // the row being built
string out;    // buffered output

void flushOut(bool force) {
  if (force || out.size() > (1 << 20)) {
    fwrite(out.data(), 1, out.size(), stdout);
    out.clear();
  }
}

}  // namespace

// The UB events of the current row, filled by ubsan_hooks.cc.
extern "C" {
char bk_ub_marks[4096];
unsigned bk_ub_len = 0;
}

namespace {

#ifdef BK_VALGRIND
unsigned rowErrors = 0;
#endif

void beginRow() {
  line.clear();
  bk_ub_len = 0;
  bk_ub_marks[0] = 0;
#ifdef BK_VALGRIND
  rowErrors = VALGRIND_COUNT_ERRORS;
#endif
}

void endRow() {
  switch (mode) {
    case TABLE:
      out += line;
      break;
    case MARK_UB:
      out.append(bk_ub_marks, bk_ub_len);
      break;
    case MARK_UNINIT:
#ifdef BK_VALGRIND
      if (VALGRIND_COUNT_ERRORS != rowErrors) out += " uninit";
#endif
      break;
  }
  out += '\n';
  flushOut(false);
}

void hex(uintb v) {
  char b[24];
  snprintf(b, sizeof b, "%llx", (unsigned long long)v);
  line += b;
}

void dec(long long v) {
  char b[24];
  snprintf(b, sizeof b, "%lld", v);
  line += b;
}

void tok(const char *s) { line += s; }
void sp() { line += ' '; }

// A range: l,r,m,s (hex, hex, hex, decimal), with a leading '!' when empty.
// Under valgrind the fields of an empty range are not printed: they carry no
// meaning and may be uninitialised; formatting them would count as a use.
void rng(const CircleRange &r) {
  if (r.isempty) {
    line += '!';
    if (mode == MARK_UNINIT) return;
  }
  hex(r.left);
  line += ',';
  hex(r.right);
  line += ',';
  hex(r.mask);
  line += ',';
  dec(r.step);
}

void flag(bool b) { line += b ? '1' : '0'; }

// An empty range. Ghidra's default constructor leaves the other fields
// uninitialised; the table gives them the values Basilisk uses (0, 0, 0, 1),
// and the uninit run leaves them undefined for valgrind to track.
CircleRange makeEmpty() {
  CircleRange r;
  r.left = 0;
  r.right = 0;
  r.mask = 0;
  r.step = 1;
#ifdef BK_VALGRIND
  if (mode == MARK_UNINIT) VALGRIND_MAKE_MEM_UNDEFINED(&r, sizeof r);
#endif
  r.isempty = true;
  return r;
}

CircleRange raw(uintb l, uintb r, uintb m, int4 s, bool e) {
  CircleRange c = makeEmpty();
  c.left = l;
  c.right = r;
  c.mask = m;
  c.step = s;
  c.isempty = e;
  return c;
}

// splitmix64
uint8 state = 0x0123456789abcdefULL;
uint8 next64() {
  uint8 z = (state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}
uint8 below(uint8 n) { return next64() % n; }

// A value of the domain `mask`, biased to the edges: 0, the sign boundary,
// the top, small offsets from them, a few random bits, or anything.
uintb interesting(uintb mask) {
  uintb half = (mask >> 1) + 1;
  uintb d = below(9);
  switch (below(10)) {
    case 0: return d;
    case 1: return (mask - d) & mask;
    case 2: return (half + d) & mask;
    case 3: return (half - 1 - d) & mask;
    case 4: return (uintb)1 << below(64) & mask;
    case 5: {
      uintb byte = below(256);
      return (byte << (8 * below(8))) & mask;
    }
    case 6: return next64() & mask;
    default: return below(64) & mask;
  }
}

const int4 STEPS[] = {1, 1, 1, 1, 1, 2, 2, 4, 4, 8, 16, 32};
const int4 SIZES[] = {2, 4, 8};

// A random well-formed (bounds congruent modulo the step) range of `size`
// bytes; full, empty, single, wrapping and sign-crossing on purpose.
CircleRange randomRange(int4 size) {
  uintb mask = calc_mask(size);
  int4 step = STEPS[below(sizeof STEPS / sizeof STEPS[0])];
  uintb rem = below(step);
  uintb left = (interesting(mask) & ~(uintb)(step - 1)) | rem;
  left &= mask;
  uintb right;
  uintb half = (mask >> 1) + 1;
  switch (below(8)) {
    case 0: return makeEmpty();
    case 1: right = left; break;                                 // full (stepped)
    case 2: right = left + step; break;                          // single
    case 3: right = left + step * (1 + below(16)); break;        // short
    case 4: left = (half - step * (1 + below(8)) + rem) & mask;  // across the sign
            right = half + step * below(8) + rem; break;
    case 5: left = (mask - step * below(8)) & ~(uintb)(step - 1) | rem;  // wrapping
            right = step * below(8) + rem; break;
    default: right = (interesting(mask) & ~(uintb)(step - 1)) | rem; break;
  }
  return CircleRange(left, right, size, step);
}

int4 sizeOf(const CircleRange &r) {
  for (int4 s = 1; s <= 8; ++s)
    if (calc_mask(s) == r.mask) return s;
  return 8;
}

// --- set A: every 1-byte range with step 1, 2, 4 or 8 and bounds aligned
// to the step, and the empty range.
vector<CircleRange> setA() {
  vector<CircleRange> v;
  v.push_back(makeEmpty());
  const int4 steps[] = {1, 2, 4, 8};
  for (int4 step : steps)
    for (uintb l = 0; l < 256; l += step)
      for (uintb r = 0; r < 256; r += step) v.push_back(CircleRange(l, r, 1, step));
  return v;
}

vector<CircleRange> pick(const vector<CircleRange> &from, size_t n) {
  vector<CircleRange> v;
  v.push_back(from[0]);  // the empty range
  while (v.size() < n) v.push_back(from[below(from.size())]);
  return v;
}

vector<CircleRange> randomSet(size_t n) {
  vector<CircleRange> v;
  for (size_t i = 0; i < n; ++i) v.push_back(randomRange(SIZES[below(3)]));
  return v;
}

void t2op(const CircleRange &r) {
  OpCode opc = CPUI_COPY;
  uintb c = 0;
  int4 slot = 0;
  int4 code = r.translate2Op(opc, c, slot);
  dec(code);
  if (code == 0) {
    line += ':';
    dec(opc);
    line += ':';
    hex(c);
    line += ':';
    dec(slot);
  }
}

// Q: the queries of one range. `bitmap` adds contains(v) for v = 0..255.
void queries(const CircleRange &r, bool bitmap) {
  beginRow();
  tok("Q ");
  rng(r);
  tok(" = ");
  hex(r.getSize());
  sp();
  dec(r.getMaxInfo());
  sp();
  hex(r.getMax());
  sp();
  flag(r.isSingle());
  flag(r.isFull());
  sp();
  uintb v = r.getMin();
  bool more = r.getNext(v);
  hex(v);
  line += ',';
  flag(more);
  sp();
  t2op(r);
  sp();
  CircleRange inv = r;
  dec(inv.invert());
  line += ',';
  rng(inv);
  sp();
  {
    std::ostringstream s;
    r.printRaw(s);
    line += s.str();
  }
  sp();
  if (bitmap) {
    for (int i = 0; i < 256; i += 4) {
      int nib = 0;
      for (int j = 0; j < 4; ++j) nib |= r.contains((uintb)(i + j)) ? (8 >> j) : 0;
      line += "0123456789abcdef"[nib];
    }
  } else {
    uintb probes[] = {r.left, r.right, r.left - 1, r.right - 1, r.left + 1, 0, (r.mask >> 1) + 1, r.mask};
    for (uintb p : probes) flag(r.contains(p));
  }
  endRow();
}

// S: setStride for several steps and remainders.
void strides(const CircleRange &r) {
  beginRow();
  tok("S ");
  rng(r);
  tok(" =");
  const int4 steps[] = {1, 2, 4, 8, 16};
  const uintb rems[] = {0, 1, 3};
  for (int4 s : steps)
    for (uintb rem : rems) {
      CircleRange c = r;
      c.setStride(s, rem);
      sp();
      rng(c);
    }
  endRow();
}

// P: the two-range methods on one pair.
void pairRow(const CircleRange &a, const CircleRange &b) {
  beginRow();
  tok("P ");
  rng(a);
  sp();
  rng(b);
  tok(" = ");
  CircleRange c = a;
  dec(c.intersect(b));
  line += ':';
  rng(c);
  sp();
  c = a;
  dec(c.circleUnion(b));
  line += ':';
  rng(c);
  sp();
  flag(a.contains(b));
  flag(a == b);
  sp();
  c = a;
  flag(c.minimalContainer(b, 32));
  line += ':';
  rng(c);
  sp();
  c = a;
  c.widen(b, true);
  rng(c);
  sp();
  c = a;
  c.widen(b, false);
  rng(c);
  int4 size = sizeOf(a);
  sp();
  c = makeEmpty();
  flag(c.pushForwardBinary(CPUI_INT_ADD, a, b, size, size, 32));
  line += ':';
  rng(c);
  sp();
  c = makeEmpty();
  flag(c.pushForwardBinary(CPUI_INT_MULT, a, b, size, size, 32));
  line += ':';
  rng(c);
  endRow();
}

// M: minimalContainer of two single values over several maxStep bounds.
void singles(uintb x, uintb y, int4 size) {
  CircleRange a(x, size), b(y, size);
  beginRow();
  tok("M ");
  rng(a);
  sp();
  rng(b);
  tok(" =");
  const int4 maxSteps[] = {-1, 0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256};
  for (int4 m : maxSteps) {
    CircleRange c = a;
    sp();
    flag(c.minimalContainer(b, m));
    line += ':';
    rng(c);
  }
  endRow();
}

// N: setNZMask on a fixed non-empty receiver.
void nzmask(uintb nz, int4 size) {
  beginRow();
  tok("N ");
  hex(nz);
  sp();
  dec(size);
  tok(" = ");
  CircleRange c(0x11, 0x33, 2, 2);
  flag(c.setNZMask(nz, size));
  line += ':';
  rng(c);
  endRow();
}

const OpCode PULL_UNARY[] = {CPUI_BOOL_NEGATE, CPUI_COPY, CPUI_INT_2COMP, CPUI_INT_NEGATE, CPUI_INT_ZEXT, CPUI_INT_SEXT};
const OpCode PUSH_UNARY[] = {CPUI_CAST, CPUI_COPY, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_2COMP, CPUI_INT_NEGATE, CPUI_BOOL_NEGATE, CPUI_FLOAT_NAN};
const int4 SIZE_SET[] = {1, 2, 4, 8};

// UP: pullBackUnary of every handled op (and one unhandled) for one size pair.
void pullUnary(const CircleRange &r, int4 in, int4 outSize) {
  beginRow();
  tok("UP ");
  rng(r);
  sp();
  dec(in);
  sp();
  dec(outSize);
  tok(" =");
  for (OpCode op : PULL_UNARY) {
    CircleRange c = r;
    sp();
    flag(c.pullBackUnary(op, in, outSize));
    line += ':';
    rng(c);
  }
  CircleRange c = r;
  sp();
  flag(c.pullBackUnary(CPUI_INT_ADD, in, outSize));
  endRow();
}

// UF: pushForwardUnary of every handled op (and one unhandled).
void pushUnary(const CircleRange &r, int4 in, int4 outSize) {
  beginRow();
  tok("UF ");
  rng(r);
  sp();
  dec(in);
  sp();
  dec(outSize);
  tok(" =");
  for (OpCode op : PUSH_UNARY) {
    CircleRange c = makeEmpty();
    sp();
    flag(c.pushForwardUnary(op, r, in, outSize));
    line += ':';
    rng(c);
  }
  CircleRange c = makeEmpty();
  sp();
  flag(c.pushForwardUnary(CPUI_POPCOUNT, r, in, outSize));
  endRow();
}

uintb CONSTS[] = {0,    1,    2,    3,    4,     7,      8,      15,         16,         31,         32,
                  63,   64,   65,   0x7f, 0x80,  0xff,   0x100,  0x7fff,     0x8000,     0xffff,     0x1234,
                  0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffffULL, 0x8000000000000000ULL,
                  0xffffffffffffffffULL};

// B: pullBackBinary for one op, slot and input size over every constant.
void pullBinary(const CircleRange &r, OpCode op, int4 slot, int4 in, int4 outSize) {
  beginRow();
  tok("B ");
  rng(r);
  sp();
  dec(op);
  sp();
  dec(slot);
  sp();
  dec(in);
  sp();
  dec(outSize);
  tok(" =");
  for (uintb v : CONSTS) {
    CircleRange c = r;
    sp();
    flag(c.pullBackBinary(op, v, slot, in, outSize));
    line += ':';
    rng(c);
  }
  endRow();
}

// The second inputs of the shift-like push-forwards: single values (as
// 8-byte singles, so any value is single) and one range that is not single.
vector<CircleRange> shiftInputs() {
  const uintb vals[] = {0,  1,  2,  3,  4,   5,   7,   8,          9,           15,         16,         17,
                        24, 31, 32, 33, 48,  56,  63,  64,         65,          127,        128,        0x20000000,
                        0x7fffffff, 0x80000000, 0xffffffff, 0x100000000ULL, 0xffffffffffffffffULL};
  vector<CircleRange> v;
  for (uintb x : vals) v.push_back(CircleRange(x, 8));
  v.push_back(CircleRange(1, 3, 8, 1));
  return v;
}

// F: pushForwardBinary of a shift-like op over every second input.
void pushShift(const CircleRange &r, OpCode op, int4 in, int4 outSize, int4 maxStep, const vector<CircleRange> &in2s) {
  beginRow();
  tok("F ");
  rng(r);
  sp();
  dec(op);
  sp();
  dec(in);
  sp();
  dec(outSize);
  sp();
  dec(maxStep);
  tok(" =");
  for (const CircleRange &b : in2s) {
    CircleRange c = makeEmpty();
    sp();
    flag(c.pushForwardBinary(op, r, b, in, outSize, maxStep));
    line += ':';
    rng(c);
  }
  endRow();
}

const OpCode BOOL_OUT[] = {CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS,
                           CPUI_INT_LESSEQUAL, CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW, CPUI_BOOL_XOR,
                           CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS,
                           CPUI_FLOAT_LESSEQUAL, CPUI_PTRSUB, CPUI_INT_XOR};

// K: pushForwardBinary of the boolean-valued ops (and PTRSUB, and an
// unhandled op) on one pair.
void pushBool(const CircleRange &a, const CircleRange &b) {
  beginRow();
  tok("K ");
  rng(a);
  sp();
  rng(b);
  tok(" =");
  for (OpCode op : BOOL_OUT) {
    CircleRange c = makeEmpty();
    sp();
    flag(c.pushForwardBinary(op, a, b, sizeOf(a), 1, 32));
    line += ':';
    rng(c);
  }
  endRow();
}

// T: pushForwardTrinary (PTRADD, and one other op).
void trinary(const CircleRange &a, const CircleRange &b, const CircleRange &c3) {
  beginRow();
  tok("T ");
  rng(a);
  sp();
  rng(b);
  sp();
  rng(c3);
  tok(" = ");
  int4 size = sizeOf(a);
  CircleRange c = makeEmpty();
  flag(c.pushForwardTrinary(CPUI_PTRADD, a, b, c3, size, size, 32));
  line += ':';
  rng(c);
  sp();
  c = makeEmpty();
  flag(c.pushForwardTrinary(CPUI_INT_ADD, a, b, c3, size, size, 32));
  endRow();
}

}  // namespace

// How many cases each section has. The checked-in table is the base set;
// --extended is the full set of docs/features/decomp-range.md 6.2, which
// tests/oracle_regen.rs replays live where the reference build exists.
struct Counts {
  size_t random, fromA, sample, pullBinary, pushShift, maxStep;
  int pairs, trinary;
};
const Counts BASE = {1000, 1000, 100, 300, 400, 150, 10000, 2000};
const Counts EXTENDED = {8000, 4000, 300, 2000, 4000, 500, 200000, 5000};

int main(int argc, char **argv) {
  Counts N = BASE;
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--extended")) N = EXTENDED;
    else if (!strcmp(argv[i], "--marks=ub")) mode = MARK_UB;
    else if (!strcmp(argv[i], "--marks=uninit")) mode = MARK_UNINIT;
    else {
      fprintf(stderr, "usage: %s [--extended] [--marks=ub|--marks=uninit]\n", argv[0]);
      return 2;
    }
  }
#ifndef BK_VALGRIND
  if (mode == MARK_UNINIT) {
    fprintf(stderr, "built without -DBK_VALGRIND\n");
    return 2;
  }
#endif
  vector<CircleRange> a = setA();
  // Q over set A (with the contains bitmap) and over random ranges.
  for (const CircleRange &r : a) queries(r, true);
  vector<CircleRange> rnd = randomSet(N.random);
  for (const CircleRange &r : rnd) queries(r, false);

  // Set B: ranges of set A and the random ones.
  vector<CircleRange> b = pick(a, N.fromA);
  b.insert(b.end(), rnd.begin(), rnd.end());
  for (const CircleRange &r : b) strides(r);

  // Unary pull-back and push-forward for each size pair.
  for (const CircleRange &r : b) {
    int4 size = r.isempty ? 1 : sizeOf(r);
    for (int4 s : SIZE_SET) pullUnary(r, s, size);
    for (int4 s : SIZE_SET) pushUnary(r, size, s);
  }

  // Pairs: a sample of set A against itself, then random pairs (sizes 2,
  // 4, 8; one pair in five of mixed sizes).
  vector<CircleRange> s300 = pick(a, N.sample);
  for (const CircleRange &x : s300)
    for (const CircleRange &y : s300) pairRow(x, y);
  for (int i = 0; i < N.pairs; ++i) {
    int4 s1 = SIZES[below(3)];
    int4 s2 = below(5) == 0 ? SIZES[below(3)] : s1;
    CircleRange x = randomRange(s1);
    CircleRange y = randomRange(s2);
    pairRow(x, y);
  }
  for (int i = 0; i < 2000; ++i) {
    int4 s1 = SIZES[below(3)];
    CircleRange x = randomRange(s1);
    CircleRange y = randomRange(s1);
    pushBool(x, y);
  }

  // minimalContainer on single values.
  const uintb sv[] = {0, 1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64, 65, 0x7f, 0x80, 0x81, 0xfe, 0xff};
  for (int4 size : {1, 2, 8})
    for (uintb x : sv)
      for (uintb y : sv) singles(x, y, size);

  // setNZMask: every 1-byte value, runs of ones at every position, random.
  for (uintb v = 0; v < 256; ++v) nzmask(v, 1);
  for (int lo = 0; lo < 64; ++lo)
    for (int hi = lo; hi < 64; ++hi) {
      uintb run = (hi == 63 ? ~(uintb)0 : (((uintb)1 << (hi + 1)) - 1)) & ~(((uintb)1 << lo) - 1);
      for (int4 size : {2, 4, 8}) nzmask(run, size);
    }
  for (int i = 0; i < 2000; ++i) {
    uintb v = interesting(~(uintb)0);  // two statements: argument order is unspecified
    nzmask(v, SIZES[below(3)]);
  }
  for (int4 size : {0, 3, 9}) {
    nzmask(0xf0, size);
    nzmask(0xff, size);
    nzmask(0, size);
  }

  // pullBackBinary. ADD and SUB over ranges of set B; the shifts over
  // ranges of set B for each input size; the comparisons (which see only
  // whether 0 and 1 are in the range) over 64 ranges, each slot and size.
  vector<CircleRange> pb = pick(b, N.pullBinary);
  for (const CircleRange &r : pb) {
    int4 size = r.isempty ? 1 : sizeOf(r);
    pullBinary(r, CPUI_INT_ADD, 0, size, size);
    pullBinary(r, CPUI_INT_SUB, 0, size, size);
    pullBinary(r, CPUI_INT_SUB, 1, size, size);
    pullBinary(r, CPUI_INT_MULT, 0, size, size);
    for (int4 s : SIZE_SET) {
      pullBinary(r, CPUI_INT_RIGHT, 0, s, size);
      pullBinary(r, CPUI_INT_SRIGHT, 0, s, size);
    }
  }
  const OpCode cmps[] = {CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
                         CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_CARRY};
  vector<CircleRange> boolish;
  boolish.push_back(CircleRange(true));
  boolish.push_back(CircleRange(false));
  boolish.push_back(CircleRange(0, 2, 1, 1));
  boolish.push_back(CircleRange(2, 0, 1, 1));
  boolish.push_back(CircleRange(5, 9, 1, 1));
  while (boolish.size() < 64) boolish.push_back(b[below(b.size())]);
  for (const CircleRange &r : boolish)
    for (OpCode op : cmps)
      for (int4 slot = 0; slot < 2; ++slot)
        for (int4 s : SIZE_SET) pullBinary(r, op, slot, s, 1);

  // Shift-like push-forwards over ranges of set B.
  vector<CircleRange> in2s = shiftInputs();
  vector<CircleRange> fb = pick(b, N.pushShift);
  for (const CircleRange &r : fb) {
    int4 size = r.isempty ? 1 : sizeOf(r);
    pushShift(r, CPUI_INT_LEFT, size, size, 32, in2s);
    for (int4 s : SIZE_SET) {
      pushShift(r, CPUI_SUBPIECE, size, s, 32, in2s);
      pushShift(r, CPUI_INT_RIGHT, size, s, 32, in2s);
      pushShift(r, CPUI_INT_SRIGHT, size, s, 32, in2s);
    }
  }
  // The step bound of INT_LEFT. Not above 2^30: there the doubling of the
  // int4 step overflows, reaches 0, and normalize() divides by it (SIGFPE on
  // x86-64; with a shift of 2^32-1 the loop also runs four billion times).
  vector<CircleRange> smallShifts(in2s.begin(), in2s.begin() + 23);
  smallShifts.push_back(in2s.back());
  const int4 maxSteps[] = {-1, 0, 1, 4, 1 << 20, 1 << 30};
  for (size_t i = 0; i < N.maxStep; ++i) {
    const CircleRange &r = fb[i];
    int4 size = r.isempty ? 1 : sizeOf(r);
    for (int4 m : maxSteps) pushShift(r, CPUI_INT_LEFT, size, size, m, smallShifts);
  }

  // PTRADD.
  for (int i = 0; i < N.trinary; ++i) {
    int4 s = SIZES[below(3)];
    CircleRange x = randomRange(s), y = randomRange(s), z = randomRange(s);
    if (below(2)) y = CircleRange(interesting(calc_mask(s)), s);
    if (below(2)) z = CircleRange((uintb)below(17), s);
    trinary(x, y, z);
  }
  flushOut(true);
  return 0;
}
