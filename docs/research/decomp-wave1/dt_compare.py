"""Compare two dt_run.sh output directories: per file, identical / differs
only in host pointers (#0x…, i0x… with 9+ hex digits) and the order of
lines that carry them / differs otherwise.  usage: dt_compare.py A B"""
import os, re, sys
a, b = sys.argv[1], sys.argv[2]
ptr = re.compile(r'(#|i)0x[0-9a-f]{8,}')
res = {'identical': [], 'pointer-only': [], 'other': []}
for n in sorted(os.listdir(os.path.join(a, 'raw'))):
    if not n.endswith('.norm'): continue
    x = open(os.path.join(a, 'raw', n)).read().split('\n')
    y = open(os.path.join(b, 'raw', n)).read().split('\n')
    if x == y: res['identical'].append(n); continue
    nx = [ptr.sub(r'\1PTR', l) for l in x]; ny = [ptr.sub(r'\1PTR', l) for l in y]
    rest_x = [l for l in x if not ptr.search(l)]; rest_y = [l for l in y if not ptr.search(l)]
    if sorted(nx) == sorted(ny) and rest_x == rest_y: res['pointer-only'].append(n)
    else: res['other'].append(n)
for k, v in res.items():
    print(k, len(v), ' '.join(v[:12]))
