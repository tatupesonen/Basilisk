import subprocess, os, glob
from PIL import Image, ImageDraw, ImageFont
B='/Users/tatu/slop/basilisk-wt/logo/assets/brand/'; T='/Users/tatu/slop/basilisk-wt/logo/.tmp-brand/t.png'
RES=os.path.expanduser('~/.cargo/bin/resvg'); SOOT='#150F0D'
def r(src,w,bg=None):
    cmd=[RES,'-w',str(w)]
    if bg: cmd+=['--background',bg]
    subprocess.run(cmd+[src,T],check=True); return Image.open(T).convert('RGBA')
def png(sz): return Image.open(B+f'png/basilisk-icon-{sz}.png').convert('RGBA')
# overview
W=1600
im=Image.new('RGB',(W,1600),'#211C19')
t=png(512); im.paste(t,(24,24),t)
im.paste(r(B+'basilisk-mark.svg',250,SOOT),(560,24))
im.paste(r(B+'basilisk-mark-light.svg',250,'#FFFFFF'),(560,286))
x=834
t=png(256); im.paste(t,(x,24),t)
t=png(128); im.paste(t,(x+276,24),t)
t=png(64); im.paste(t,(x+276,172),t); t=png(32); im.paste(t,(x+360,172),t); t=png(16); im.paste(t,(x+412,172),t)
strip=Image.new('RGB',(204,84),'#F3F3F0'); im.paste(strip,(x+430,24))
t=png(64); im.paste(t,(x+440,34),t); t=png(32); im.paste(t,(x+524,34),t); t=png(16); im.paste(t,(x+576,34),t)
im.paste(r(B+'basilisk-mark-mono.svg',120,'#F3F3F0'),(x+430,128))
t=png(32).resize((224,224),Image.NEAREST); im.paste(t,(x,312),t)
t=png(16).resize((224,224),Image.NEAREST); im.paste(t,(x+244,312),t)
ld=r(B+'basilisk-logo-dark.svg',760,SOOT); im.paste(ld,(20,570))
ll=r(B+'basilisk-logo.svg',760,'#FFFFFF'); im.paste(ll,(820,570))
y=570+ld.height+30
for i,c in enumerate(sorted(glob.glob(B+'concepts/*.svg'))):
    im.paste(r(c,210,'#0F1412'),(20+i*224,y))
im.crop((0,0,W,y+230)).save(B+'png/preview-overview.png')
# variants sheet with updated labels
labels={'A1':'Venom on Obsidian (first version)','A2':'Obsidian on Venom','A3':'Gold on warm black','A4':'Ember on warm black (chosen)','A5':'Glass cyan on blue-black','A6':'Nightshade violet','A7':'Bone on Obsidian','A8':'Bone, Venom pupil','A9':'Venom, Ember pupil',
 'B1':'Even ring, lens pupil (current)','B2':'Tapered ring (first version)','B3':'Gem pupil','B4':'Iris disc, slit cut out','B5':'Bar pupil (a 0 and a 1)','B6':'Bold','B7':'Fine line','B8':'Closed ring (tail tucked under the jaw)','B9':'Five-point crown',
 'C1':'Round tile','C2':'Hexagon tile','C3':'No tile'}
files={os.path.basename(p)[:2]:p for p in glob.glob(B+'variants/*.svg')}
font=ImageFont.truetype('/System/Library/Fonts/Helvetica.ttc',15); fb=ImageFont.truetype('/System/Library/Fonts/Helvetica.ttc',19)
cw,ch,S=228,270,196
im=Image.new('RGB',(9*cw+24,3*ch+70),'#1B211E'); d=ImageDraw.Draw(im)
y=10
for title,row in (('A  Colour variants (same shape)','A'),('B  Shape variants (shown in the first green; the chosen colour is A4)','B'),('C  Tile shapes','C')):
    d.text((16,y),title,fill='#E9EEE2',font=fb); y+=30
    for i,code in enumerate(sorted(k for k in files if k[0]==row)):
        x=16+i*cw
        t=r(files[code],S); im.paste(t,(x,y),t)
        d.text((x,y+S+6),code,fill='#FF6A2B' if code=='A4' else '#B8F03C',font=fb)
        line=''; lines=[]
        for w in labels[code].split(' '):
            if d.textlength((line+' '+w).strip(),font=font)>S-34: lines.append(line); line=w
            else: line=(line+' '+w).strip()
        lines.append(line); ly=y+S+8
        for ln in lines[:2]: d.text((x+34,ly),ln,fill='#AEB8A8',font=font); ly+=18
    y+=ch-26
im.crop((0,0,9*cw+24,y)).save(B+'png/preview-variants.png')
