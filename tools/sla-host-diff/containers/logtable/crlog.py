"""Correctly rounded log(k/n) for 1 <= k < n <= N, hashed as logtable.c
does, so a C library's log can be checked for correct rounding on the
inputs DecisionNode::getScore gives it.

    python3 -I crlog.py N > logtable-cr.txt

p is the double k/n (Python float division is IEEE, correctly rounded);
log(p) is computed with 60 significant digits by `decimal` and rounded to
the nearest double (float(Decimal) rounds correctly). A value within
1e-40 relative of a rounding boundary is reported on stderr as a hard
case (none is expected at this precision for these inputs)."""
import decimal
import struct
import sys

ctx = decimal.Context(prec=60)
N = int(sys.argv[1])
FNV_OFF, FNV_PRIME, MASK = 1469598103934665603, 1099511628211, (1 << 64) - 1


def bits(d):
    return struct.unpack("<Q", struct.pack("<d", d))[0]


def crlog(p):
    v = ctx.ln(decimal.Decimal(p))
    return float(v)


print("log2 %016x" % bits(crlog(2.0)))
for n in range(2, N + 1):
    h = FNV_OFF
    for k in range(1, n):
        h = ((h ^ bits(crlog(k / n))) * FNV_PRIME) & MASK
    print("%d %016x" % (n, h))
