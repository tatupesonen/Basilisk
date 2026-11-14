"""Write one console script per data test: the test's own commands, and
after every decompile: print raw, print tree varnode, print tree block.
usage: python3 -I dt_scripts.py DATATESTS_DIR OUTDIR"""
import os, re, sys, html
src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
for name in sorted(os.listdir(src)):
    if not name.endswith('.xml'):
        continue
    text = open(os.path.join(src, name), encoding='utf-8').read()
    def content(c):
        parts = re.split(r'(<!\[CDATA\[.*?\]\]>)', c, flags=re.S)
        c = ''.join(p[9:-3] if p.startswith('<![CDATA[') else html.unescape(p) for p in parts)
        return c.replace('\r', '').replace('\n', ' ').strip()
    coms = [content(c) for c in re.findall(r'<com>(.*?)</com>', text, re.S)]
    lines = ['load test file ' + os.path.join(src, name)]
    for c in coms:
        if c.split()[:1] == ['quit']:
            break
        lines.append(c)
        if c.split()[:1] in (['decompile'], ['dec']):
            lines += ['print raw', 'print tree varnode', 'print tree block']
    lines.append('quit')
    open(os.path.join(out, name[:-4] + '.txt'), 'w').write('\n'.join(lines) + '\n')
