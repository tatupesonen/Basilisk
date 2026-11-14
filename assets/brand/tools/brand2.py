import sys, math, os, subprocess; sys.path.insert(0,'.')
import brand
from brand import P, pf, f, bezb, R, CX, CY
def vesica(px,py,h,w):
    r=(h*h+w*w)/(2*w)
    return f'M{f(px)} {f(py-h)} A{f(r)} {f(r)} 0 0 1 {f(px)} {f(py+h)} A{f(r)} {f(r)} 0 0 1 {f(px)} {f(py-h)} Z'
def build2(tn=38,tm=30,th_a=322,q=0.85,e=2.0,th_neck=104,th_tail=397,th_fore=72,
           snout_top=(202,72),snout_bot=(199,83),jaw=(128,114),
           eye=((150,73),(184,79.5),(156,87)),
           cth=(103,90,77),chs=(28,44,28),cw=6.5,leans=(5,0,-5),
           pup=(128,168,42,16)):
    def t(th):
        if th<=th_a: return tn+(tm-tn)*(th-th_neck)/(th_a-th_neck)
        u=min(max((th-th_a)/(th_tail-th_a),0),1)
        # smooth join: thickness eases from tm to 0
        return tm*(1-u**e)**q
    inner=lambda th: P(R-t(th),th)
    span=th_tail-th_a
    brk=[th_tail-0.6,th_tail-0.08*span,th_tail-0.25*span,th_tail-0.55*span,th_a]
    n=5
    brk+=[th_a+(th_neck-th_a)*i/n for i in range(1,n+1)]
    body='M'+pf(P(R,th_fore))+f' A{R} {R} 0 1 0 {pf(P(R,th_tail))} L{pf(inner(brk[0]))} '+bezb(inner,brk)
    body+=f' L{pf(jaw)} L{pf(snout_bot)} L{pf(snout_top)} Z'
    eyep='M'+' L'.join(pf(e) for e in eye)+' Z' if eye else ''
    pts=[]
    for i,(th,h,l) in enumerate(zip(cth,chs,leans)):
        pts+=[P(R-1.5 if i==0 else R+3,th+cw),P(R+h,th+l)]
    pts.append(P(R-1.5,cth[-1]-cw))
    crown='M'+' L'.join(pf(q_) for q_ in pts)+' Z'
    return body,eyep,crown,vesica(*pup)
FULL=build2()
SMALL=build2(tn=42,tm=36,th_a=328,th_tail=395,eye=None,chs=(32,48,32),cw=8,cth=(106,90,74),pup=(128,170,42,20),jaw=(128,120),snout_top=(202,73),snout_bot=(198,87))
def write_all():
    brand.FULL=FULL
    w,mark,logo,icon,resvg=brand.w,brand.mark,brand.logo,brand.icon,brand.resvg
    V,M,O,B=brand.VENOM,brand.MOSS,brand.OBSIDIAN,brand.BONE
    w('basilisk-mark.svg',mark(V,FULL)); w('basilisk-mark-light.svg',mark(M,FULL)); w('basilisk-mark-mono.svg',mark('currentColor',FULL))
    w('basilisk-logo.svg',logo(M,O,M)); w('basilisk-logo-dark.svg',logo(V,B,V))
    w('basilisk-icon.svg',icon(FULL,0.76,0))
    w('basilisk-icon-small.svg',icon(SMALL,0.8,0,'  <!-- simplified artwork for 16-32 px: heavier ring, no head eye, pupil centred on the pixel grid -->\n'))
    for sz in (16,32): resvg('basilisk-icon-small.svg',f'png/basilisk-icon-{sz}.png',sz)
    for sz in (64,128,256,512,1024): resvg('basilisk-icon.svg',f'png/basilisk-icon-{sz}.png',sz)
    resvg('basilisk-mark.svg','png/preview-mark.png',1024,O)
    resvg('basilisk-logo-dark.svg','png/preview-logo-dark.png',1400,O)
    resvg('basilisk-logo.svg','png/preview-logo-light.png',1400,'#FFFFFF')
if __name__=='__main__':
    write_all()
