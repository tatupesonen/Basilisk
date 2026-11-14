import math
def f(v):
    s=f'{v:.1f}'.rstrip('0').rstrip('.'); return '0' if s=='-0' else s
def letters(W=16):
    h=W/2; r=50-h
    out=[]
    def b(x): return [('s',f'M{f(x+h)} 0 V140'),('s',f'M{f(x+h)} 90 a{f(r)} {f(r)} 0 1 0 {f(2*r)} 0 a{f(r)} {f(r)} 0 1 0 {f(-2*r)} 0')],100
    def B(x):
        # capital B: stem as tall as l and k (cap height = ascender, y 0..140); two
        # bowls of a horizontal bar and a half circle each, the lower one wider
        mid=66; r1=(mid-h)/2; r2=(140-h-mid)/2; ru,rl=78,84  # bar centre, bowl right edges
        c1,c2=x+ru-r1,x+rl-r2
        return [('s',f'M{f(x+h)} 0 V140'),
                ('s',f'M{f(x+h)} {f(h)} H{f(c1)} A{f(r1)} {f(r1)} 0 0 1 {f(c1)} {f(mid)} H{f(x+h)}'),
                ('s',f'M{f(x+h)} {f(mid)} H{f(c2)} A{f(r2)} {f(r2)} 0 0 1 {f(c2)} {f(140-h)} H{f(x+h)}')],rl+h
    def a(x): return [('s',f'M{f(x+100-h)} 40 V140'),('s',f'M{f(x+h)} 90 a{f(r)} {f(r)} 0 1 0 {f(2*r)} 0 a{f(r)} {f(r)} 0 1 0 {f(-2*r)} 0')],100
    def s(x):
        sk=[(65,62),(60,54),(50,50),(38,50),(22,50),(11,58),(11,69),(11,82),(24,86),(38,90),(52,94),(65,98),(65,111),(65,122),(54,130),(38,130),(26,130),(16,126),(10,117)]
        ky=(50-h)/40; kx=(38-h)/28
        pts=[(x+38+(px-38)*kx, 90+(py-90)*ky) for px,py in sk]
        d=f'M{f(pts[0][0])} {f(pts[0][1])}'
        for i in range(1,len(pts),3):
            d+=' C'+' '.join(f'{f(p[0])} {f(p[1])}' for p in pts[i:i+3])
        return [('s',d)],76
    def i(x):
        w=h+5
        return [('s',f'M{f(x+h)} 40 V140'),('d',f'M{f(x+h)} -6 Q{f(x+h+2*w*0.62)} 11 {f(x+h)} 28 Q{f(x+h-2*w*0.62)} 11 {f(x+h)} -6 Z')],W
    def l(x): return [('s',f'M{f(x+h)} 0 V140')],W
    def k(x):
        sx=x+W  # right edge of stem
        # arm: centreline (sx,100)->(sx+50,40)
        dx,dy=50,-60; L=math.hypot(dx,dy); hc=W/(abs(dy)/L); vc=W/(dx/L)
        arm=f'M{f(sx-4)} {f(100-vc/2)} H{f(sx)} L{f(sx+50-hc/2)} 40 H{f(sx+50+hc/2)} L{f(sx)} {f(100+vc/2)} H{f(sx-4)} Z'
        # leg: centreline (sx+18,84)->(sx+54,140)
        ax,ay,bx,by=sx+18,84,sx+54,140; dx,dy=bx-ax,by-ay; L=math.hypot(dx,dy); nx,ny=dy/L*h,-dx/L*h; hc=W/(dy/L)
        leg=f'M{f(ax+nx)} {f(ay+ny)} L{f(bx+hc/2)} 140 H{f(bx-hc/2)} L{f(ax-nx)} {f(ay-ny)} Z'
        return [('s',f'M{f(x+h)} 0 V140'),('f',arm),('f',leg)],W+54+hc/2
    seq=[(B,14),(a,20),(s,18),(i,24),(l,24),(i,18),(s,18),(k,0)]
    x=0
    for fn,gap in seq:
        parts,w=fn(x); out+=parts; x+=w+gap
    return out,x
def word_svg(ink, dot, indent='    ', W=16):
    parts,w=letters(W)
    strokes=' '.join(d for k,d in parts if k=='s')
    fills=' '.join(d for k,d in parts if k=='f')
    dots=' '.join(d for k,d in parts if k=='d')
    s=f'{indent}<path fill="none" stroke="{ink}" stroke-width="{W}" d="{strokes}"/>\n'
    s+=f'{indent}<path fill="{ink}" d="{fills}"/>\n'
    s+=f'{indent}<path fill="{dot}" d="{dots}"/>\n'
    return s,w
