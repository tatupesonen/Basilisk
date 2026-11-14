import math, os, subprocess
RES=os.path.expanduser('~/.cargo/bin/resvg')
CX,CY,R=128,148,100
def f(v):
    s=f'{v:.1f}'.rstrip('0').rstrip('.'); return '0' if s=='-0' else s
def P(r,th):
    a=math.radians(th); return (CX+r*math.cos(a), CY-r*math.sin(a))
def pf(p): return f'{f(p[0])} {f(p[1])}'
def bezb(fn, brk):
    out=[]; e=1e-3
    for t0,t1 in zip(brk,brk[1:]):
        h=t1-t0; p0=fn(t0); p3=fn(t1)
        d0=[(fn(t0+e)[k]-fn(t0-e)[k])/(2*e) for k in (0,1)]
        d1=[(fn(t1+e)[k]-fn(t1-e)[k])/(2*e) for k in (0,1)]
        p1=(p0[0]+d0[0]*h/3,p0[1]+d0[1]*h/3); p2=(p3[0]-d1[0]*h/3,p3[1]-d1[1]*h/3)
        out.append(f'C{pf(p1)} {pf(p2)} {pf(p3)}')
    return ' '.join(out)
def lens(px,py,h,w):
    r=(h*h+w*w)/(2*w)
    return f'M{f(px)} {f(py-h)} A{f(r)} {f(r)} 0 0 1 {f(px)} {f(py+h)} A{f(r)} {f(r)} 0 0 1 {f(px)} {f(py-h)} Z'
def small(tn=42,tm=36,th_a=328,q=0.85,e=2.0,th_neck=104,th_tail=395,th_fore=72,snout_top=(202,73),snout_bot=(198,87),jaw=(128,120),
          cth=(106,90,74),chs=(32,48,32),cw=8,leans=(5,0,-5),pup=(128,170,42,20),scale=0.8,dy=0,fill='#FF6A2B',tile='#150F0D'):
    def t(th):
        if th<=th_a: return tn+(tm-tn)*(th-th_neck)/(th_a-th_neck)
        u=min(max((th-th_a)/(th_tail-th_a),0),1)
        return tm*(1-u**e)**q
    inner=lambda th: P(R-t(th),th)
    span=th_tail-th_a
    brk=[th_tail-0.6,th_tail-0.08*span,th_tail-0.25*span,th_tail-0.55*span,th_a]+[th_a+(th_neck-th_a)*i/5 for i in range(1,6)]
    body='M'+pf(P(R,th_fore))+f' A{R} {R} 0 1 0 {pf(P(R,th_tail))} L{pf(inner(brk[0]))} '+bezb(inner,brk)+f' L{pf(jaw)} L{pf(snout_bot)} L{pf(snout_top)} Z'
    pts=[]
    for i,(th,h,l) in enumerate(zip(cth,chs,leans)):
        pts+=[P(R-1.5 if i==0 else R+3,th+cw),P(R+h,th+l)]
    pts.append(P(R-1.5,cth[-1]-cw))
    crown='M'+' L'.join(pf(x) for x in pts)+' Z'
    tx=128*(1-scale); ty=128*(1-scale)+dy
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="basilisk">
  <!-- simplified artwork for 16-32 px: heavier ring, no head eye, pupil centred on the pixel grid -->
  <rect width="256" height="256" rx="58" fill="{tile}"/>
  <g fill="{fill}" transform="translate({f(tx)} {f(ty)}) scale({scale})">
    <!-- serpent: head, body tapering round to the tail -->
    <path d="{body}"/>
    <!-- crown -->
    <path d="{crown}"/>
    <!-- slit pupil -->
    <path d="{lens(*pup)}"/>
  </g>
</svg>
'''
if __name__=='__main__':
    from PIL import Image
    vars=[('cur',{}),('fuller tail',dict(th_a=352,tm=38,tn=44)),('fuller+crown',dict(th_a=352,tm=38,tn=44,chs=(36,54,36),cw=9,cth=(108,90,72),pup=(128,170,42,24))),('heavier',dict(th_a=356,tm=42,tn=46,chs=(36,54,36),cw=9,cth=(108,90,72),pup=(128,172,40,25),jaw=(128,124),snout_bot=(198,90)))]
    im=Image.new('RGB',(len(vars)*420,520),'#3A3632')
    for i,(n,kw) in enumerate(vars):
        open(f's{i}.svg','w').write(small(**kw))
        x=i*420
        for sz,pos,k in ((32,(x+10,10),6),(16,(x+212,10),12),(32,(x+10,220),1),(16,(x+60,220),1),(200,(x+10,280),1)):
            subprocess.run([RES,'-w',str(sz),f's{i}.svg','t.png'],check=True)
            t=Image.open('t.png').convert('RGBA')
            if k>1: t=t.resize((sz*k,sz*k),Image.NEAREST)
            im.paste(t,pos,t)
    im.save('smalls.png')
