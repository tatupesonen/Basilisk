import sys, math, os, subprocess; sys.path.insert(0,'.')
import word
OUT='/Users/tatu/slop/basilisk-wt/logo/assets/brand'
VENOM,MOSS,OBSIDIAN,BONE='#B8F03C','#4A8500','#0F1412','#E9EEE2'
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
def build(tn=36,p=0.75,th_neck=104,th_tail=398,th_fore=70,
          snout_top=(196,68),snout_bot=(192,82),jaw=(128,110),
          eye=((146,72),(176,77),(151,84)),
          cth=(103,90,77),chs=(26,40,26),cw=6.5,leans=(5,0,-5),
          pup=(137,167,42,15)):
    def t(th):
        s=(th-th_neck)/(th_tail-th_neck); s=min(max(s,0),1)
        return tn*(1-s)**p
    inner=lambda th: P(R-t(th),th)
    brk=[th_tail-1,th_tail-5,th_tail-14,th_tail-34]
    n=5; a=th_tail-34
    brk+=[a+(th_neck-a)*i/n for i in range(1,n+1)]
    body='M'+pf(P(R,th_fore))+f' A{R} {R} 0 1 0 {pf(P(R,th_tail))} L{pf(inner(brk[0]))} '+bezb(inner,brk)
    body+=f' L{pf(jaw)} L{pf(snout_bot)} L{pf(snout_top)} Z'
    eyep='M'+' L'.join(pf(e) for e in eye)+' Z' if eye else ''
    pts=[]
    for i,(th,h,l) in enumerate(zip(cth,chs,leans)):
        pts+=[P(R-1.5 if i==0 else R+3,th+cw),P(R+h,th+l)]
    pts.append(P(R-1.5,cth[-1]-cw))
    crown='M'+' L'.join(pf(q) for q in pts)+' Z'
    px,py,h,w=pup
    pupil=f'M{px} {py-h} Q{px+2*w} {py} {px} {py+h} Q{px-2*w} {py} {px} {py-h} Z'
    return body,eyep,crown,pupil
FULL=build()
SMALL=build(tn=44,p=0.6,th_tail=396,eye=None,chs=(32,48,32),cw=8,cth=(106,90,74),pup=(128,170,42,20),jaw=(126,118),snout_top=(198,70),snout_bot=(193,86))
def mark_paths(parts, ind='  '):
    body,eyep,crown,pupil=parts
    s=''
    if eyep:
        s+=f'{ind}<!-- serpent: head, body tapering round to the tail; the second subpath is the eye -->\n'
        s+=f'{ind}<path fill-rule="evenodd" d="{body} {eyep}"/>\n'
    else:
        s+=f'{ind}<!-- serpent: head, body tapering round to the tail -->\n'
        s+=f'{ind}<path d="{body}"/>\n'
    s+=f'{ind}<!-- crown -->\n{ind}<path d="{crown}"/>\n'
    s+=f'{ind}<!-- slit pupil -->\n{ind}<path d="{pupil}"/>\n'
    return s
def mark(fill, parts=FULL, title='basilisk'):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="{title}">
  <g fill="{fill}">
{mark_paths(parts,'    ')}  </g>
</svg>
'''
def icon(parts, scale, dy, note=''):
    tx=128*(1-scale); ty=128*(1-scale)+dy
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="basilisk">
{note}  <rect width="256" height="256" rx="58" fill="{OBSIDIAN}"/>
  <g fill="{VENOM}" transform="translate({f(tx)} {f(ty)}) scale({scale})">
{mark_paths(parts,'    ')}  </g>
</svg>
'''
def logo(markc, ink, dot, s=0.74, wx=244, W=16):
    wy=CY-90*s
    w,ww=word.word_svg(ink,dot,'    ',W)
    Wd=round(wx+ww*s+12)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {Wd} 256" role="img" aria-label="basilisk">
  <g fill="{markc}" transform="translate(-16 0)">
{mark_paths(FULL,'    ')}  </g>
  <!-- wordmark: monoline letters drawn as strokes (no font needed); the i-dots repeat the slit pupil -->
  <g transform="translate({wx} {f(wy)}) scale({s})">
{w}  </g>
</svg>
'''
def w(name,s): open(os.path.join(OUT,name),'w').write(s)
def resvg(src,dst,size,bg=None):
    cmd=[os.path.expanduser('~/.cargo/bin/resvg'),'-w',str(size)]
    if bg: cmd+=['--background',bg]
    subprocess.run(cmd+[os.path.join(OUT,src),os.path.join(OUT,dst)],check=True)
if __name__=='__main__':
    os.makedirs(OUT+'/png',exist_ok=True); os.makedirs(OUT+'/concepts',exist_ok=True)
    w('basilisk-mark.svg',mark(VENOM))
    w('basilisk-mark-light.svg',mark(MOSS))
    w('basilisk-mark-mono.svg',mark('currentColor'))
    w('basilisk-logo.svg',logo(MOSS,OBSIDIAN,MOSS))
    w('basilisk-logo-dark.svg',logo(VENOM,BONE,VENOM))
    w('basilisk-icon.svg',icon(FULL,0.7,4))
    w('basilisk-icon-small.svg',icon(SMALL,0.8,0,'  <!-- simplified artwork for 16-32 px: heavier ring, no head eye, pupil centred on the pixel grid -->\n'))
    for sz in (16,32): resvg('basilisk-icon-small.svg',f'png/basilisk-icon-{sz}.png',sz)
    for sz in (64,128,256,512,1024): resvg('basilisk-icon.svg',f'png/basilisk-icon-{sz}.png',sz)
    resvg('basilisk-mark.svg','png/preview-mark.png',1024,OBSIDIAN)
    resvg('basilisk-logo-dark.svg','png/preview-logo-dark.png',1400,OBSIDIAN)
    resvg('basilisk-logo.svg','png/preview-logo-light.png',1400,'#FFFFFF')
