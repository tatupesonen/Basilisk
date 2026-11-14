//! Arbitrary bytes read as three circle ranges (any field values), sizes,
//! an operation, a constant and a step bound, then every `CircleRange`
//! method of `bk-decomp-range`. The process must not panic, divide by zero
//! or hang.

#![no_main]

use bk_decomp_range::CircleRange;
use bk_pcode::OpCode;
use libfuzzer_sys::fuzz_target;

/// Takes the next `N` bytes, zero-padded past the end.
fn take<const N: usize>(data: &mut &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = data.len().min(N);
    out[..n].copy_from_slice(&data[..n]);
    *data = &data[n..];
    out
}

fn u64_of(data: &mut &[u8]) -> u64 {
    u64::from_le_bytes(take::<8>(data))
}

fn i32_of(data: &mut &[u8]) -> i32 {
    i32::from_le_bytes(take::<4>(data))
}

fn range_of(data: &mut &[u8]) -> CircleRange {
    let (l, r, m) = (u64_of(data), u64_of(data), u64_of(data));
    let step = i32_of(data);
    let [empty] = take::<1>(data);
    CircleRange::from_parts(l, r, m, step, empty & 1 == 1)
}

fuzz_target!(|bytes: &[u8]| {
    let mut data = bytes;
    let a = range_of(&mut data);
    let b = range_of(&mut data);
    let c3 = range_of(&mut data);
    let [op, s1, s2, flags] = take::<4>(&mut data);
    let val = u64_of(&mut data);
    let max_step = i32_of(&mut data);
    let op = OpCode::from_u8(op).unwrap_or(OpCode::Copy);
    let (s1, s2) = (u32::from(s1), u32::from(s2));

    let _ = (a.count(), a.max_info(), a.max(), a.is_full(), a.is_single(), a.translate_2op());
    let _ = a.to_string();
    let mut v = val;
    let _ = a.next(&mut v);
    let _ = (a.contains_value(val), a.contains(&b), a == b);
    let mut x = a;
    let _ = x.intersect(&b);
    let mut x = a;
    let _ = x.circle_union(&b);
    let mut x = a;
    let _ = x.minimal_container(&b, max_step);
    let mut x = a;
    let _ = x.invert();
    let mut x = a;
    x.set_stride(b.step(), val);
    let mut x = a;
    x.widen(&b, flags & 1 == 1);
    let mut x = a;
    let _ = x.set_nz_mask(val, s1);
    let mut x = a;
    let _ = x.pull_back_unary(op, s1, s2);
    let mut x = a;
    let _ = x.pull_back_binary(op, val, u32::from(flags >> 1 & 1), s1, s2);
    let mut x = c3;
    let _ = x.push_forward_unary(op, &a, s1, s2);
    let mut x = c3;
    let _ = x.push_forward_binary(op, &a, &b, s1, s2, max_step);
    let mut x = c3;
    let _ = x.push_forward_trinary(op, [&a, &b, &c3], s1, s2, max_step);
});
