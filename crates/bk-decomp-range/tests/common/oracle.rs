//! Reading the oracle table (`tests/data/README.md`) and computing each
//! row's results with `bk-decomp-range`, written in the table's own format,
//! so that a row is checked by comparing two strings.

use std::fmt::Write as _;
use std::io::Read as _;

use bk_decomp_range::{CircleRange, Combined, Translated};
use bk_pcode::OpCode;

/// The table, decompressed.
pub(crate) fn gunzip(bytes: &[u8]) -> String {
    let mut s = String::new();
    flate2::read::GzDecoder::new(bytes).read_to_string(&mut s).unwrap();
    s
}

/// A table row split into its tag, its inputs, the results the C++ gave,
/// and its marks (` #ub=…`, ` #uninit`).
#[derive(Debug)]
pub(crate) struct Row<'a> {
    pub(crate) tag: &'a str,
    pub(crate) inputs: Vec<&'a str>,
    pub(crate) results: &'a str,
    pub(crate) marks: Vec<&'a str>,
}

pub(crate) fn split(line: &str) -> Row<'_> {
    let (body, marks) = match line.find(" #") {
        Some(i) => (&line[..i], line[i + 2..].split(" #").collect()),
        None => (line, Vec::new()),
    };
    let (lhs, results) = body.split_once(" =").unwrap();
    let mut fields = lhs.split(' ');
    let tag = fields.next().unwrap();
    Row {
        tag,
        inputs: fields.collect(),
        results: results.strip_prefix(' ').unwrap_or(results),
        marks,
    }
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

fn int<T: std::str::FromStr>(s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    s.parse().unwrap()
}

/// The receiver of every push-forward in the oracle (`receiver()`).
pub(crate) fn receiver() -> CircleRange {
    CircleRange::from_parts(0x5a, 0xa5, 0xff, 3, true)
}

/// A range token: `l,r,m,s` with a leading `!` when empty.
pub(crate) fn range(s: &str) -> CircleRange {
    let (empty, s) = match s.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let f: Vec<&str> = s.split(',').collect();
    CircleRange::from_parts(hex(f[0]), hex(f[1]), hex(f[2]), int(f[3]), empty)
}

fn op(s: &str) -> OpCode {
    OpCode::from_u8(int(s)).unwrap()
}

/// Appends a range token.
pub(crate) fn put(out: &mut String, r: &CircleRange) {
    if r.is_empty() {
        out.push('!');
    }
    write!(out, "{:x},{:x},{:x},{}", r.min(), r.end(), r.mask(), r.step()).unwrap();
}

fn flag(out: &mut String, b: bool) {
    out.push(if b { '1' } else { '0' });
}

fn combined(c: Combined) -> u8 {
    match c {
        Combined::Done => 0,
        Combined::TwoPieces => 2,
    }
}

fn translated(out: &mut String, t: Translated) {
    match t {
        Translated::Comparison { op, constant, slot } => {
            write!(out, "0:{}:{constant:x}:{slot}", op as u8).unwrap();
        }
        Translated::Always => out.push('1'),
        Translated::NotPossible => out.push('2'),
        Translated::Never => out.push('3'),
    }
}

/// The byte size whose mask is the range's (the oracle's `sizeOf`).
fn size_of(r: &CircleRange) -> u32 {
    if r.is_empty() {
        return 8;
    }
    (1..=8).find(|&s| bk_core::bits::calc_mask(s) == r.mask()).unwrap_or(8)
}

/// The second inputs of an `F` row: `shiftInputs`, or for the step-bound
/// rows (24 results) only the shifts up to 128 and the range that is not
/// single.
pub(crate) fn second_inputs(row: &Row<'_>) -> Vec<CircleRange> {
    let mut inputs = shift_inputs();
    if row.results.split(' ').count() == 24 {
        inputs.drain(23..29);
    }
    inputs
}

/// The second inputs of the shift-like push-forwards (`shiftInputs`).
fn shift_inputs() -> Vec<CircleRange> {
    let vals: [u64; 29] = [
        0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 48, 56, 63, 64, 65, 127, 128, 0x2000_0000, 0x7fff_ffff,
        0x8000_0000, 0xffff_ffff, 0x1_0000_0000, u64::MAX,
    ];
    let mut v: Vec<CircleRange> = vals.iter().map(|&x| CircleRange::single(x, 8)).collect();
    v.push(CircleRange::new(1, 3, 8, 1));
    v
}

const CONSTS: [u64; 28] = [
    0,
    1,
    2,
    3,
    4,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    65,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x7fff,
    0x8000,
    0xffff,
    0x1234,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX,
];

const PULL_UNARY: [OpCode; 6] = [
    OpCode::BoolNegate,
    OpCode::Copy,
    OpCode::Int2Comp,
    OpCode::IntNegate,
    OpCode::IntZExt,
    OpCode::IntSExt,
];
const PUSH_UNARY: [OpCode; 8] = [
    OpCode::Cast,
    OpCode::Copy,
    OpCode::IntZExt,
    OpCode::IntSExt,
    OpCode::Int2Comp,
    OpCode::IntNegate,
    OpCode::BoolNegate,
    OpCode::FloatNan,
];
const BOOL_OUT: [OpCode; 18] = [
    OpCode::IntEqual,
    OpCode::IntNotEqual,
    OpCode::IntSLess,
    OpCode::IntSLessEqual,
    OpCode::IntLess,
    OpCode::IntLessEqual,
    OpCode::IntCarry,
    OpCode::IntSCarry,
    OpCode::IntSBorrow,
    OpCode::BoolXor,
    OpCode::BoolAnd,
    OpCode::BoolOr,
    OpCode::FloatEqual,
    OpCode::FloatNotEqual,
    OpCode::FloatLess,
    OpCode::FloatLessEqual,
    OpCode::PtrSub,
    OpCode::IntXor,
];

/// Basilisk's results for a row, in the table's format.
pub(crate) fn compute(row: &Row<'_>) -> String {
    let mut o = String::new();
    let i = &row.inputs;
    match row.tag {
        "Q" => {
            let r = range(i[0]);
            let bitmap = row.results.rsplit(' ').next().unwrap().len() == 64;
            queries(&mut o, &r, bitmap);
        }
        "S" => {
            let r = range(i[0]);
            for s in [1, 2, 4, 8, 16] {
                for rem in [0, 1, 3] {
                    let mut c = r;
                    c.set_stride(s, rem);
                    if !o.is_empty() {
                        o.push(' ');
                    }
                    put(&mut o, &c);
                }
            }
        }
        "P" => pair(&mut o, &range(i[0]), &range(i[1])),
        "M" => {
            let (a, b) = (range(i[0]), range(i[1]));
            for m in [-1, 0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256] {
                let mut c = a;
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.minimal_container(&b, m));
                o.push(':');
                put(&mut o, &c);
            }
        }
        "N" => {
            let mut c = CircleRange::new(0x11, 0x33, 2, 2);
            flag(&mut o, c.set_nz_mask(hex(i[0]), int(i[1])));
            o.push(':');
            put(&mut o, &c);
        }
        "UP" => {
            let (r, inn, out) = (range(i[0]), int(i[1]), int(i[2]));
            for op in PULL_UNARY {
                let mut c = r;
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.pull_back_unary(op, inn, out));
                o.push(':');
                put(&mut o, &c);
            }
            let mut c = r;
            o.push(' ');
            flag(&mut o, c.pull_back_unary(OpCode::IntAdd, inn, out));
        }
        "UF" => {
            let (r, inn, out) = (range(i[0]), int(i[1]), int(i[2]));
            for op in PUSH_UNARY {
                let mut c = receiver();
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.push_forward_unary(op, &r, inn, out));
                o.push(':');
                put(&mut o, &c);
            }
            let mut c = receiver();
            o.push(' ');
            flag(&mut o, c.push_forward_unary(OpCode::PopCount, &r, inn, out));
        }
        "B" => {
            let (r, opc, slot, inn, out) = (range(i[0]), op(i[1]), int(i[2]), int(i[3]), int(i[4]));
            for v in CONSTS {
                let mut c = r;
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.pull_back_binary(opc, v, slot, inn, out));
                o.push(':');
                put(&mut o, &c);
            }
        }
        "F" => {
            let (r, opc, inn, out, max) = (range(i[0]), op(i[1]), int(i[2]), int(i[3]), int(i[4]));
            for b in second_inputs(row) {
                let mut c = receiver();
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.push_forward_binary(opc, &r, &b, inn, out, max));
                o.push(':');
                put(&mut o, &c);
            }
        }
        "K" => {
            let (a, b) = (range(i[0]), range(i[1]));
            for opc in BOOL_OUT {
                let mut c = receiver();
                if !o.is_empty() {
                    o.push(' ');
                }
                flag(&mut o, c.push_forward_binary(opc, &a, &b, size_of(&a), 1, 32));
                o.push(':');
                put(&mut o, &c);
            }
        }
        "T" => {
            let (a, b, c3) = (range(i[0]), range(i[1]), range(i[2]));
            let size = size_of(&a);
            let mut c = receiver();
            flag(&mut o, c.push_forward_trinary(OpCode::PtrAdd, [&a, &b, &c3], size, size, 32));
            o.push(':');
            put(&mut o, &c);
            o.push(' ');
            let mut c = receiver();
            flag(&mut o, c.push_forward_trinary(OpCode::IntAdd, [&a, &b, &c3], size, size, 32));
        }
        other => panic!("unknown row tag {other:?}"),
    }
    o
}

fn queries(o: &mut String, r: &CircleRange, bitmap: bool) {
    write!(o, "{:x} {} {:x} ", r.count(), r.max_info(), r.max()).unwrap();
    flag(o, r.is_single());
    flag(o, r.is_full());
    let mut v = r.min();
    let more = r.next(&mut v);
    write!(o, " {v:x},").unwrap();
    flag(o, more);
    o.push(' ');
    translated(o, r.translate_2op());
    let mut inv = *r;
    write!(o, " {},", inv.invert()).unwrap();
    put(o, &inv);
    write!(o, " {r} ").unwrap();
    if bitmap {
        for i in (0..256u64).step_by(4) {
            let mut nib = 0;
            for j in 0..4 {
                if r.contains_value(i + j) {
                    nib |= 8 >> j;
                }
            }
            o.push(char::from_digit(nib, 16).unwrap());
        }
    } else {
        let probes = [
            r.min(),
            r.end(),
            r.min().wrapping_sub(1),
            r.end().wrapping_sub(1),
            r.min().wrapping_add(1),
            0,
            (r.mask() >> 1).wrapping_add(1),
            r.mask(),
        ];
        for p in probes {
            flag(o, r.contains_value(p));
        }
    }
}

fn pair(o: &mut String, a: &CircleRange, b: &CircleRange) {
    let mut c = *a;
    write!(o, "{}:", combined(c.intersect(b))).unwrap();
    put(o, &c);
    let mut c = *a;
    write!(o, " {}:", combined(c.circle_union(b))).unwrap();
    put(o, &c);
    o.push(' ');
    flag(o, a.contains(b));
    flag(o, a == b);
    o.push(' ');
    let mut c = *a;
    flag(o, c.minimal_container(b, 32));
    o.push(':');
    put(o, &c);
    o.push(' ');
    let mut c = *a;
    c.widen(b, true);
    put(o, &c);
    o.push(' ');
    let mut c = *a;
    c.widen(b, false);
    put(o, &c);
    let size = size_of(a);
    for opc in [OpCode::IntAdd, OpCode::IntMult] {
        let mut c = receiver();
        o.push(' ');
        flag(o, c.push_forward_binary(opc, a, b, size, size, 32));
        o.push(':');
        put(o, &c);
    }
}
