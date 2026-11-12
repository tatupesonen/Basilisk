# Independent transliteration of PackedEncode and XmlEncode from Ghidra's
# marshal.cc. Its output is the block of expected vectors in testmarshal.rs:
#
#     python3 gen_marshal_vectors.py
#
# It follows the C++ line by line (the threshold ladder of writeInteger, the
# tag state machine of XmlEncode) rather than the Rust, so that agreement
# between the two is evidence that the Rust matches Ghidra.
ATTR = dict(XMLcontent=1, align=2, bigendian=3, constructor=4, destructor=5, extrapop=6, format=7, id=9, index=10, metatype=12, model=13, name=14, space=20, val=24, value=25)
ELEM = dict(data=1, input=2, off=3, output=4, symbol=6, target=7, addr=11)
class Packed:
    def __init__(s): s.o = bytearray()
    def hdr(s, h, i):
        if i > 0x1f:
            s.o += bytes([(h | 0x20 | (i >> 7)) & 0xff, (i & 0x7f) | 0x80])
        else: s.o.append(h | i)
    def integer(s, tb, val):
        if val == 0: l, sa = 0, -1
        elif val < 0x800000000:
            if val < 0x200000:
                if val < 0x80: l, sa = 1, 0
                elif val < 0x4000: l, sa = 2, 7
                else: l, sa = 3, 14
            elif val < 0x10000000: l, sa = 4, 21
            else: l, sa = 5, 28
        elif val < 0x2000000000000:
            if val < 0x40000000000: l, sa = 6, 35
            else: l, sa = 7, 42
        else:
            if val < 0x100000000000000: l, sa = 8, 49
            elif val < 0x8000000000000000: l, sa = 9, 56
            else: l, sa = 10, 63
        s.o.append(tb | l)
        while sa >= 0:
            s.o.append(((val >> sa) & 0x7f) | 0x80); sa -= 7
    def open(s, e): s.hdr(0x40, ELEM[e])
    def close(s, e): s.hdr(0x80, ELEM[e])
    def bool(s, a, v): s.hdr(0xc0, ATTR[a]); s.o.append(0x11 if v else 0x10)
    def signed(s, a, v):
        s.hdr(0xc0, ATTR[a])
        if v < 0: s.integer(0x30, -v)
        else: s.integer(0x20, v)
    def unsigned(s, a, v): s.hdr(0xc0, ATTR[a]); s.integer(0x40, v)
    def string(s, a, v):
        b = v.encode(); s.hdr(0xc0, ATTR[a]); s.integer(0x70, len(b)); s.o += b
    def space(s, a, name, idx): s.hdr(0xc0, ATTR[a]); s.integer(0x50, idx)
    def result(s): return bytes(s.o)
def esc(v):
    return v.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&apos;')
class Xml:
    START, CONTENT, STOP = 0, 1, 2
    def __init__(s): s.o = ''; s.st = s.STOP; s.depth = 0
    def nl(s):
        n = min(s.depth * 2 + 1, 25); s.o += ("\n" + " " * 24)[:n]
    def open(s, e):
        if s.st == s.START: s.o += '>'
        else: s.st = s.START
        s.nl(); s.o += '<' + e; s.depth += 1
    def close(s, e):
        s.depth -= 1
        if s.st == s.START: s.o += '/>'; s.st = s.STOP; return
        if s.st != s.CONTENT: s.nl()
        else: s.st = s.STOP
        s.o += '</' + e + '>'
    def val(s, a, text):
        if a == 'XMLcontent':
            if s.st == s.START: s.o += '>'
            s.o += text; s.st = s.CONTENT
        else: s.o += ' ' + a + '="' + text + '"'
    def bool(s, a, v): s.val(a, 'true' if v else 'false')
    def signed(s, a, v): s.val(a, str(v))
    def unsigned(s, a, v): s.val(a, '0x%x' % v)
    def string(s, a, v): s.val(a, esc(v))
    def space(s, a, name, idx): s.val(a, esc(name))
    def result(s): return s.o.encode()
def signed(e):
    e.open('addr'); e.signed('align', 3); e.signed('bigendian', -0x100); e.signed('constructor', 0x1fffff)
    e.signed('destructor', -0xabcdefa); e.signed('extrapop', 0x300000000); e.signed('format', -0x30101010101)
    e.signed('id', 0x123456789011); e.signed('index', -0xf0f0f0f0f0f0f0); e.signed('metatype', 0x7fffffffffffffff); e.close('addr')
def unsigned(e):
    e.open('addr'); e.unsigned('align', 3); e.unsigned('bigendian', 0x100); e.unsigned('constructor', 0x1fffff)
    e.unsigned('destructor', 0xabcdefa); e.unsigned('extrapop', 0x300000000); e.unsigned('format', 0x30101010101)
    e.unsigned('id', 0x123456789011); e.unsigned('index', 0xf0f0f0f0f0f0f0); e.unsigned('metatype', 0x7fffffffffffffff)
    e.unsigned('model', 0x8000000000000000); e.close('addr')
def mixed(e):
    e.open('addr'); e.signed('align', 456); e.string('extrapop', 'unknown'); e.close('addr')
LONG = ("one to three four five six seven eight nine ten eleven twelve thirteen "
        "fourteen fifteen sixteen seventeen eighteen nineteen twenty twenty one "
        "blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah")
def attributes(e):
    e.open('data'); e.bool('align', True); e.bool('bigendian', False); e.space('space', 'ram', 3)
    e.string('val', ''); e.string('value', 'hello'); e.string('constructor', "<<\u20ac>>&\"bl a  h'\\bleh\n\t")
    e.string('destructor', LONG); e.close('data')
def hierarchy(e):
    e.open('data'); e.bool('XMLcontent', True); e.open('input'); e.open('output'); e.signed('id', 0x1000)
    e.open('data'); e.open('data'); e.open('off'); e.close('off'); e.open('off'); e.string('id', 'blahblah'); e.close('off')
    e.open('off'); e.close('off'); e.close('data'); e.close('data'); e.open('symbol'); e.unsigned('id', 17)
    e.open('target'); e.close('target'); e.close('symbol'); e.close('output'); e.close('input')
    for _ in range(6): e.open('input'); e.close('input')
    e.close('data')
def rs_bytes(b):
    return ', '.join('0x%02x' % x for x in b)
for name, fn in [('SIGNED', signed), ('UNSIGNED', unsigned), ('MIXED', mixed), ('ATTRIBUTES', attributes), ('HIERARCHY', hierarchy)]:
    p = Packed(); fn(p); x = Xml(); fn(x)
    print('const %s_PACKED: &[u8] = &[%s];' % (name, rs_bytes(p.result())))
    print('const %s_XML: &str = %s;' % (name, '"' + x.result().decode().replace('\\','\\\\').replace('"','\\"').replace('\n','\\n').replace('\t','\\t') + '"'))
