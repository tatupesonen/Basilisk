import random, sys, os
def gen(rng, n):
    outs = []
    for i in range(n):
        r = rng.random()
        k = 0 if r < 0.1 else 1 if r < 0.55 else 2 if r < 0.9 else rng.randint(3,6)
        outs.append([rng.randrange(n) for _ in range(k)])
    return outs
def xml(outs):
    n = len(outs)
    ins = [[] for _ in range(n)]
    for s, lst in enumerate(outs):
        for slot, t in enumerate(lst):
            ins[t].append((s, slot))
    lines = ['<block index="0">']
    lines += ['<bhead index="%d" type="plain"/>' % i for i in range(n)]
    for i in range(n):
        lines.append('<block index="%d">' % i + ''.join('<edge end="%d" rev="%d"/>' % e for e in ins[i]) + '</block>')
    lines.append('</block>')
    return '\n'.join(lines) + '\n'
seed, count, maxn, outdir = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rng = random.Random(seed)
for c in range(count):
    n = rng.randint(1, maxn)
    open(os.path.join(outdir, 'g%05d.xml' % c), 'w').write(xml(gen(rng, n)))
