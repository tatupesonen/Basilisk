//! Soundness properties of `CircleRange`, checked by enumerating the
//! elements of 1- and 2-byte ranges (`docs/features/decomp-range.md` 6.3),
//! and robustness on arbitrary field values. 4,096 cases each.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use std::collections::BTreeSet;

use bk_core::bits::calc_mask;
use bk_decomp_range::{CircleRange, Combined};
use bk_pcode::behavior::{evaluate_binary, evaluate_unary};
use bk_pcode::{FloatFormats, OpCode};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 4096,
        // The documented Ghidra defects are excluded with `prop_assume!`.
        max_global_rejects: 1 << 20,
        ..ProptestConfig::default()
    }
}

/// A well-formed range of `size` bytes (1 or 2): step 1, 2, 4 or 8, bounds
/// congruent modulo the step; full, empty and single on purpose. Ranges of
/// 2 bytes are kept to at most 300 elements unless full, so that
/// enumeration stays cheap.
fn range_of(size: u32) -> impl Strategy<Value = CircleRange> {
    let mask = calc_mask(size);
    (
        0usize..10,
        prop::sample::select(vec![1i32, 1, 2, 4, 8]),
        any::<u64>(),
        0u64..300,
    )
        .prop_map(move |(kind, step, seed, len)| {
            let s = step as u64;
            let left = ((seed & mask) & !(s - 1)) | ((seed >> 32) % s);
            let left = left & mask;
            match kind {
                0 => CircleRange::empty(),
                // Full, normalised as Ghidra's methods leave a full range
                // (`minimalContainer` mishandles one whose left bound is
                // not its phase; no method produces such a range).
                1 => CircleRange::new(left % s, left % s, size, step),
                2 => CircleRange::new(left, left + s, size, step),
                _ => {
                    let len = if size == 1 { len % (256 / s) } else { len };
                    CircleRange::new(left, left + len * s, size, step)
                }
            }
        })
}

fn small_range() -> impl Strategy<Value = CircleRange> {
    prop_oneof![range_of(1), range_of(2)]
}

/// The elements of a well-formed range.
fn elements(r: &CircleRange) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    if r.is_empty() {
        return set;
    }
    let mut v = r.min();
    let mut steps = 0u32;
    loop {
        set.insert(v);
        steps += 1;
        assert!(steps <= 1 << 17, "{r} ({r:?}) does not close");
        if !r.next(&mut v) {
            break;
        }
    }
    set
}

/// Whether `getMaxInfo` is below the largest information content of an
/// element (bits of the magnitude, a value with the top bit set counted as
/// negative).
fn understated(r: &CircleRange) -> bool {
    let half = r.mask() ^ (r.mask() >> 1);
    let info = |v: u64| {
        let m = if v & half == 0 { v } else { !v & r.mask() };
        64 - m.leading_zeros() as i32 + i32::from(v == half)
    };
    elements(r).into_iter().map(info).max().unwrap_or(0) > r.max_info()
}

/// The bounds of a range read as signed values of `size` bytes.
fn signed(r: &CircleRange, size: u32) -> (i64, i64) {
    let sa = 64 - 8 * size;
    (
        (r.min().cast_signed() << sa) >> sa,
        (r.end().cast_signed() << sa) >> sa,
    )
}

/// The phase of a range: its left bound modulo its step.
fn phase(r: &CircleRange) -> u64 {
    r.min() % u64::from(r.step().unsigned_abs().max(1))
}

fn size_of(r: &CircleRange) -> u32 {
    if r.mask() == 0xff { 1 } else { 2 }
}

/// Ghidra's result for an intersection of ranges of different sizes where it
/// differs from the set intersection, or `None` where it does not.
///
/// Ranges of different sizes are a real input: the jump-table recovery
/// intersects a switch variable's range with guard ranges taken through
/// copies, extensions and truncations of it (`GuardRecord::quasiCopy` and
/// `valueMatch`, jumptable.cc:1158–1163), and `intersect` handles a mask
/// difference on purpose: it cuts the wider range down to the narrower
/// domain (`newDomain`) and gives the result the narrower mask
/// (rangeutil.cc:582–594, 661). Values are compared as values, so the
/// result is the set intersection, with one Ghidra defect: a wide range
/// that starts above the narrow domain and ends at its phase inside it
/// (`[ff41,0)` in two bytes) has no value there, but the cut gives
/// `[rem, rem)`, which `newDomain` then reads as everything
/// (rangeutil.cc:151–166). The intersection is then the narrow range's
/// values of that phase. A wide range of the smaller step that wraps is
/// already excluded by the caller.
fn mixed_size_result(a: &CircleRange, b: &CircleRange) -> Option<BTreeSet<u64>> {
    if a.mask() == b.mask() || a.is_empty() || b.is_empty() {
        return None;
    }
    let (wide, narrow) = if a.mask() > b.mask() { (a, b) } else { (b, a) };
    let new_step = u64::from(a.step().max(b.step()).unsigned_abs());
    let rem = wide.min() % new_step;
    let empty_cut = wide.min() > narrow.mask() && wide.end() <= narrow.mask() && wide.end() == rem;
    empty_cut.then(|| {
        elements(narrow)
            .into_iter()
            .filter(|x| x % new_step == rem)
            .collect()
    })
}

proptest! {
    #![proptest_config(config())]

    /// A successful intersection is the set intersection.
    #[test]
    fn intersect_is_exact_when_it_succeeds(a in small_range(), b in small_range()) {
        // Ghidra defect: with equal steps the phases are never compared, so
        // odd ∩ even comes out as one of them (`intersect`, rangeutil.cc:580).
        prop_assume!(a.step() != b.step() || a.is_empty() || b.is_empty() || phase(&a) == phase(&b));
        let mut c = a;
        if c.intersect(&b) == Combined::Done {
            let want: BTreeSet<u64> = elements(&a).intersection(&elements(&b)).copied().collect();
            // Ghidra defect: moving the range of smaller step onto the larger
            // step's phase (`newStride`) can round a range that holds no such
            // value to `[x, x)`, which then reads as everything.
            // It also compares the order of the bounds before and after
            // rounding them up, which changes when a bound rounds past the
            // top of the domain or the range wraps; that reads as "empty"
            // (rangeutil.cc:111–128).
            let (smaller, larger) = if a.step() < b.step() { (a, b) } else { (b, a) };
            let big = larger.step() as u64;
            let past_top = |x: u64| x.div_ceil(big) * big > smaller.mask();
            prop_assume!(!(a.step() != b.step()
                && (want.is_empty() || smaller.min() > smaller.end() || past_top(smaller.min()) || past_top(smaller.end()))));
            let want = mixed_size_result(&a, &b).unwrap_or(want);
            prop_assert_eq!(elements(&c), want, "{} ∩ {} = {}", a, b, c);
        } else {
            prop_assert_eq!(c, a, "a failed intersection left the receiver changed");
        }
    }

    /// A successful union is the set union.
    #[test]
    fn union_is_exact_when_it_succeeds(a in range_of(1), b in range_of(1)) {
        let mut c = a;
        if c.circle_union(&b) == Combined::Done {
            let want: BTreeSet<u64> = elements(&a).union(&elements(&b)).copied().collect();
            prop_assert_eq!(elements(&c), want, "{} ∪ {} = {}", a, b, c);
        } else {
            prop_assert_eq!(c, a, "a failed union left the receiver changed");
        }
    }

    /// The minimal container holds both ranges, and says "everything"
    /// exactly when it is full.
    #[test]
    fn minimal_container_contains_both(a in range_of(1), b in range_of(1)) {
        prop_assume!(!a.is_empty() && !b.is_empty());
        // Ghidra defect: a full range, `[left, left)`, becomes an empty
        // interval once its right bound is moved back by `step - 1`, so the
        // container of a full range and another is the other one
        // (`minimalContainer`, rangeutil.cc:478–495).
        prop_assume!(a.min() != a.end() && b.min() != b.end());
        // Ghidra defect: `right - step + 1` is not masked, so a range whose
        // end is below `step - 1` gives a right bound outside the domain
        // (rangeutil.cc:478–479).
        prop_assume!(a.end() + 1 >= a.step() as u64 && b.end() + 1 >= b.step() as u64);
        let mut c = a;
        let full = c.minimal_container(&b, 32);
        let got = elements(&c);
        prop_assert!(elements(&a).is_subset(&got) && elements(&b).is_subset(&got), "{} {} -> {}", a, b, c);
        prop_assert_eq!(full, got.len() == 256 && c.step() == 1);
    }

    /// `contains(x)` agrees with the elements.
    #[test]
    fn contains_value_agrees_with_enumeration(r in range_of(1)) {
        let set = elements(&r);
        for v in 0..256u64 {
            prop_assert_eq!(r.contains_value(v), set.contains(&v), "{} {}", r, v);
        }
    }

    /// `contains(range)` is never wrong when it says yes.
    #[test]
    fn contains_range_is_sound(a in range_of(1), b in range_of(1)) {
        // Ghidra defect: a full receiver claims everything without looking
        // at the phase (`contains`, rangeutil.cc:314).
        prop_assume!(!(a.min() == a.end() && a.step() > 1));
        if a.contains(&b) {
            prop_assert!(elements(&b).is_subset(&elements(&a)), "{} claims {}", a, b);
        }
    }

    /// A successful unary push-forward contains the image of every element.
    #[test]
    fn push_forward_unary_is_sound(
        r in small_range(),
        op in prop::sample::select(vec![OpCode::Copy, OpCode::IntZExt, OpCode::IntSExt, OpCode::Int2Comp, OpCode::IntNegate]),
        out in prop::sample::select(vec![1u32, 2, 4, 8]),
    ) {
        let inn = size_of(&r);
        let out = if matches!(op, OpCode::IntZExt | OpCode::IntSExt) { out.max(inn) } else { inn };
        let mut c = CircleRange::empty();
        if c.push_forward_unary(op, &r, inn, out) {
            for e in elements(&r) {
                let v = evaluate_unary(op, out, inn, e, &FloatFormats::DEFAULT).unwrap();
                prop_assert!(c.contains_value(v), "{:?} {} -> {} misses {:x}", op, r, c, v);
            }
        }
    }

    /// A successful binary push-forward contains the image of every pair.
    #[test]
    fn push_forward_binary_is_sound(
        a in small_range(),
        b in range_of(1),
        op in prop::sample::select(vec![OpCode::IntAdd, OpCode::IntMult, OpCode::IntLeft, OpCode::IntRight, OpCode::IntSRight, OpCode::SubPiece, OpCode::IntLess]),
    ) {
        let inn = size_of(&a);
        // Shift amounts and SUBPIECE offsets within the operand.
        let b = match op {
            OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight => CircleRange::single(b.min() % (8 * u64::from(inn)), 1),
            OpCode::SubPiece => CircleRange::single(b.min() % u64::from(inn), 1),
            OpCode::IntAdd | OpCode::IntMult => {
                if inn == 1 { b } else { CircleRange::single(b.min(), 2) }
            }
            _ => b,
        };
        prop_assume!(elements(&b).len() <= 64);
        let out = match op {
            OpCode::IntLess => 1,
            OpCode::SubPiece => inn - b.min() as u32,
            _ => inn,
        };
        // Ghidra defect: INT_RIGHT of a wrapping or full range gives
        // `[0, mask >> sa)`, one short (rangeutil.cc:1313).
        prop_assume!(!(op == OpCode::IntRight && a.min() >= a.end()));
        // Ghidra defect: the same for INT_SRIGHT of a range that wraps in
        // the signed order: `[min, max)` with max the largest positive value,
        // which is left out (rangeutil.cc:1329–1335).
        prop_assume!(!(op == OpCode::IntSRight && signed(&a, inn).0 >= signed(&a, inn).1));
        // Ghidra defect: `getMaxInfo` reads a full stepped range by its
        // bounds alone, so INT_MULT and INT_LEFT treat it as a short range
        // and miss most of the image (rangeutil.cc:1241 and 1272).
        let full_stepped = |r: &CircleRange| r.min() == r.end() && r.step() > 1;
        prop_assume!(!(matches!(op, OpCode::IntMult | OpCode::IntLeft | OpCode::SubPiece) && (full_stepped(&a) || full_stepped(&b))));
        // (SUBPIECE: a full stepped range comes out as phase 0, rangeutil.cc:1289.)
        // Ghidra defect: INT_LEFT shifts both bounds without checking that
        // the range wraps; only `getMaxInfo` guards it, and that misses a
        // wrapping range that avoids the sign bit (rangeutil.cc:1269–1272).
        prop_assume!(!(op == OpCode::IntLeft && a.min() > a.end()));
        // Ghidra defect behind several of these: `getMaxInfo` looks only at
        // the bounds and at whether the sign-bit value is in the range, so a
        // stepped range that skips that value is understated, and INT_MULT
        // and INT_LEFT then miss the overflow (rangeutil.cc:280–297).
        prop_assume!(!(matches!(op, OpCode::IntMult | OpCode::IntLeft) && (understated(&a) || understated(&b))));
        // And the guard itself counts the bits of a negative value's
        // magnitude but not its sign bit, so a product that overflows the
        // signed range by one bit passes it: INT_MULT and INT_LEFT are only
        // sound where no element's product overflows (rangeutil.cc:1241,
        // 1272).
        if matches!(op, OpCode::IntMult | OpCode::IntLeft) {
            let bits = 8 * inn;
            let sext = |v: u64| (v.cast_signed() << (64 - bits)) >> (64 - bits);
            let lim = 1i128 << (bits - 1);
            let overflow = elements(&a).iter().any(|&x| {
                elements(&b).iter().any(|&y| {
                    let p = if op == OpCode::IntMult {
                        i128::from(sext(x)) * i128::from(sext(y))
                    } else {
                        i128::from(sext(x)) << y
                    };
                    p < -lim || p >= lim
                })
            });
            prop_assume!(!overflow);
        }
        let mut c = CircleRange::empty();
        if c.push_forward_binary(op, &a, &b, inn, out, 32) {
            for x in elements(&a) {
                for y in elements(&b) {
                    let v = evaluate_binary(op, out, inn, x, y, &FloatFormats::DEFAULT).unwrap();
                    prop_assert!(c.contains_value(v), "{:?} {} {} -> {} misses {:x}", op, a, b, c, v);
                }
            }
        }
    }

    /// A successful unary pull-back holds every input whose image is in
    /// the range, and nothing else for the exact operations.
    #[test]
    fn pull_back_unary_is_sound(
        narrow in range_of(1),
        wide in range_of(2),
        op in prop::sample::select(vec![OpCode::Copy, OpCode::Int2Comp, OpCode::IntNegate, OpCode::IntZExt, OpCode::IntSExt]),
    ) {
        // Inputs of 1 byte: the extensions pull a 2-byte range back to them.
        let ext = matches!(op, OpCode::IntZExt | OpCode::IntSExt);
        let r = if ext { wide } else { narrow };
        let (inn, out) = (1, size_of(&r));
        let mut c = r;
        if c.pull_back_unary(op, inn, out) {
            let pulled = elements(&c);
            for x in 0..256u64 {
                let image = evaluate_unary(op, out, inn, x, &FloatFormats::DEFAULT).unwrap();
                let wanted = r.contains_value(image);
                if wanted {
                    prop_assert!(pulled.contains(&x), "{:?} {} -> {} misses {:x}", op, r, c, x);
                } else if matches!(op, OpCode::Copy | OpCode::Int2Comp | OpCode::IntNegate) {
                    prop_assert!(!pulled.contains(&x), "{:?} {} -> {} has {:x}", op, r, c, x);
                }
            }
        }
    }

    /// A successful binary pull-back holds every input whose image is in the
    /// range; for addition, subtraction and the comparisons nothing else.
    #[test]
    fn pull_back_binary_is_sound(
        r in range_of(1),
        op in prop::sample::select(vec![OpCode::IntAdd, OpCode::IntSub, OpCode::IntRight, OpCode::IntSRight,
            OpCode::IntEqual, OpCode::IntNotEqual, OpCode::IntLess, OpCode::IntLessEqual,
            OpCode::IntSLess, OpCode::IntSLessEqual, OpCode::IntCarry]),
        val in 0u64..256,
        slot in 0u32..2,
    ) {
        let comparison = !matches!(op, OpCode::IntAdd | OpCode::IntSub | OpCode::IntRight | OpCode::IntSRight);
        let val = if matches!(op, OpCode::IntRight | OpCode::IntSRight) { val % 8 } else { val };
        let slot = if matches!(op, OpCode::IntRight | OpCode::IntSRight) { 0 } else { slot };
        // Ghidra defects: `c - x` (INT_SUB, slot 1) maps the bounds without
        // reversing them (rangeutil.cc:942–943); a comparison whose range
        // holds both outcomes pulls back to [0,2) in the input's mask, not
        // to everything (rangeutil.cc:820 and the six like it).
        prop_assume!(!(op == OpCode::IntSub && slot == 1));
        prop_assume!(!(comparison && r.contains_value(0) && r.contains_value(1)));
        let mut c = r;
        if c.pull_back_binary(op, val, slot, 1, 1) {
            let pulled = elements(&c);
            for x in 0..256u64 {
                let (in1, in2) = if slot == 0 { (x, val) } else { (val, x) };
                let image = evaluate_binary(op, 1, 1, in1, in2, &FloatFormats::DEFAULT).unwrap();
                let wanted = r.contains_value(image);
                if wanted {
                    prop_assert!(pulled.contains(&x), "{:?} {} c={:x} slot {} -> {} misses {:x}", op, r, val, slot, c, x);
                } else if !matches!(op, OpCode::IntRight | OpCode::IntSRight) {
                    prop_assert!(!pulled.contains(&x), "{:?} {} c={:x} slot {} -> {} has {:x}", op, r, val, slot, c, x);
                }
            }
        }
    }

    /// `Display` round-trips through a parser of Ghidra's `printRaw` form.
    #[test]
    fn display_round_trips(r in small_range()) {
        let text = r.to_string();
        let parsed = parse(&text, r.mask());
        prop_assert_eq!(parsed.to_string(), text.clone());
        if !r.is_empty() && !r.is_single() && r.min() != r.end() {
            prop_assert_eq!((parsed.min(), parsed.end(), parsed.step()), (r.min(), r.end(), r.step()), "{}", text);
        }
    }

    /// No method panics or loops, whatever the fields, sizes and operands.
    #[test]
    fn never_panics(
        f in prop::array::uniform5(any::<u64>()),
        g in prop::array::uniform5(any::<u64>()),
        steps in prop::array::uniform3(prop_oneof![any::<i32>(), -9i32..9]),
        sizes in prop::array::uniform2(prop_oneof![any::<u32>(), 0u32..10]),
        op in 0u8..80,
        val in any::<u64>(),
        max_step in prop_oneof![any::<i32>(), -2i32..64, Just(i32::MAX)],
    ) {
        let a = CircleRange::from_parts(f[0], f[1], f[2], steps[0], f[3] & 1 == 1);
        let b = CircleRange::from_parts(g[0], g[1], g[2], steps[1], g[3] & 1 == 1);
        let c3 = CircleRange::from_parts(f[4], g[4], f[2] | g[2], steps[2], false);
        exercise(&a, &b, &c3, op, val, sizes, max_step);
    }
}

/// Ranges of different sizes, as Ghidra intersects them
/// (`mixed_size_result`): the result takes the narrower domain and holds
/// the common values.
#[test]
fn intersect_of_different_sizes_takes_the_narrower_domain() {
    // A 1-byte receiver: [10,20) ∩ [18,130) of two bytes = [18,20).
    let mut c = CircleRange::new(0x10, 0x20, 1, 1);
    assert_eq!(
        c.intersect(&CircleRange::new(0x18, 0x130, 2, 1)),
        Combined::Done
    );
    assert_eq!(c, CircleRange::new(0x18, 0x20, 1, 1));
    // A 2-byte receiver: the result has the 1-byte mask.
    let mut c = CircleRange::new(0x18, 0x130, 2, 1);
    assert_eq!(
        c.intersect(&CircleRange::new(0x10, 0x20, 1, 1)),
        Combined::Done
    );
    assert_eq!(c, CircleRange::new(0x18, 0x20, 1, 1));
    // Nothing of [100,200) in two bytes fits in one byte.
    let mut c = CircleRange::new(0, 0x80, 1, 1);
    assert_eq!(
        c.intersect(&CircleRange::new(0x100, 0x200, 2, 1)),
        Combined::Done
    );
    assert!(c.is_empty());
}

/// The minimal case CI found (run 43661252298): the full 1-byte range and
/// `[ff41,0)` of two bytes have no common value, but Ghidra's `newDomain`
/// cuts the 2-byte range to `[0,0)` and reads that as everything
/// (rangeutil.cc:151–166), so the result is the full 1-byte range.
#[test]
fn intersect_reads_an_empty_cut_as_everything() {
    let a = CircleRange::new(0, 0, 1, 1);
    let b = CircleRange::from_parts(0xff41, 0, 0xffff, 1, false);
    let mut c = a;
    assert_eq!(c.intersect(&b), Combined::Done);
    assert_eq!(c, CircleRange::new(0, 0, 1, 1));
    assert!(c.is_full());
    // The same cut with the 2-byte range as the receiver.
    let mut c = b;
    assert_eq!(
        c.intersect(&CircleRange::new(0x10, 0x20, 1, 1)),
        Combined::Done
    );
    assert_eq!(c, CircleRange::new(0x10, 0x20, 1, 1));
}

/// Calls every method once on arbitrary inputs.
fn exercise(
    a: &CircleRange,
    b: &CircleRange,
    c3: &CircleRange,
    op: u8,
    val: u64,
    sizes: [u32; 2],
    max_step: i32,
) {
    let opc = OpCode::from_u8(op).unwrap_or(OpCode::Copy);
    let _ = (
        a.count(),
        a.max_info(),
        a.max(),
        a.is_full(),
        a.is_single(),
        a.translate_2op(),
        a.to_string(),
    );
    let mut v = val;
    let _ = a.next(&mut v);
    let _ = (a.contains_value(val), a.contains(b), a == b);
    let mut x = *a;
    let _ = x.intersect(b);
    let mut x = *a;
    let _ = x.circle_union(b);
    let mut x = *a;
    let _ = x.minimal_container(b, max_step);
    let mut x = *a;
    let _ = x.invert();
    let mut x = *a;
    x.set_stride(b.step(), val);
    let mut x = *a;
    x.widen(b, val & 1 == 0);
    let mut x = *a;
    let _ = x.set_nz_mask(val, sizes[0]);
    let mut x = *a;
    let _ = x.pull_back_unary(opc, sizes[0], sizes[1]);
    let mut x = *a;
    let _ = x.pull_back_binary(opc, val, (val >> 1) as u32 & 1, sizes[0], sizes[1]);
    let mut x = *c3;
    let _ = x.push_forward_unary(opc, a, sizes[0], sizes[1]);
    let mut x = *c3;
    let _ = x.push_forward_binary(opc, a, b, sizes[0], sizes[1], max_step);
    let mut x = *c3;
    let _ = x.push_forward_trinary(OpCode::PtrAdd, [a, b, c3], sizes[0], sizes[1], max_step);
}

/// Parses `printRaw` output in a domain with the given mask.
fn parse(text: &str, mask: u64) -> CircleRange {
    let size = if mask == 0xff { 1 } else { 2 };
    if text == "(empty)" {
        return CircleRange::empty();
    }
    if let Some(rest) = text.strip_prefix("(full") {
        let step = rest
            .strip_prefix(',')
            .map_or(1, |s| s.trim_end_matches(')').parse().unwrap());
        return CircleRange::new(0, 0, size, step);
    }
    let inner = text.strip_prefix('[').unwrap();
    if let Some(single) = inner.strip_suffix(']') {
        return CircleRange::single(u64::from_str_radix(single, 16).unwrap(), size);
    }
    let fields: Vec<&str> = inner.strip_suffix(')').unwrap().split(',').collect();
    let step = fields.get(2).map_or(1, |s| s.parse().unwrap());
    CircleRange::new(
        u64::from_str_radix(fields[0], 16).unwrap(),
        u64::from_str_radix(fields[1], 16).unwrap(),
        size,
        step,
    )
}

#[test]
fn the_struct_is_small() {
    assert!(std::mem::size_of::<CircleRange>() <= 32);
}
