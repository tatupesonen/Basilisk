//! The brute-force model of Ghidra's `unittests/testcirclerange.cc`
//! (`CircleRangeTest`): a range as the explicit list of its elements,
//! pushed through or pulled back with the op behaviours one element at a
//! time, and re-described as start/stop/step by `getStartStopStep`.

use bk_core::bits::calc_mask;
use bk_decomp_range::CircleRange;
use bk_pcode::behavior::{
    evaluate_binary, evaluate_unary, recover_input_binary, recover_input_unary,
};
use bk_pcode::{FloatFormats, OpCode};

/// The largest number of elements the model enumerates.
const LIMIT: usize = 1 << 20;

/// The elements of a range, as Ghidra's test holds them.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    pub(crate) elements: Vec<u64>,
    pub(crate) mask: u64,
    pub(crate) bytes: u32,
}

impl Model {
    /// An empty set of `bytes`-byte values.
    pub(crate) fn with_bytes(bytes: u32) -> Self {
        Self {
            elements: Vec::new(),
            mask: calc_mask(bytes),
            bytes,
        }
    }

    /// Every element of `range`, from its minimum by `getNext`
    /// (`CircleRangeTest(const CircleRange &)`).
    pub(crate) fn of(range: &CircleRange) -> Self {
        let mask = range.mask();
        let mut elements = Vec::new();
        if !range.is_empty() {
            let mut v = range.min();
            loop {
                elements.push(v);
                assert!(
                    elements.len() <= LIMIT,
                    "range {range} has too many elements to enumerate"
                );
                if !range.next(&mut v) {
                    break;
                }
            }
        }
        let temp = mask.wrapping_add(1);
        let bytes = if temp == 0 { 8 } else { temp.ilog2() / 8 };
        Self {
            elements,
            mask,
            bytes,
        }
    }

    /// `set_intersect`.
    pub(crate) fn intersect(&mut self, other: &Self) {
        let mut a = self.elements.clone();
        let mut b = other.elements.clone();
        a.sort_unstable();
        b.sort_unstable();
        self.elements = a
            .iter()
            .copied()
            .filter(|x| b.binary_search(x).is_ok())
            .collect();
        self.elements.dedup();
    }

    /// `set_union`.
    pub(crate) fn union(&mut self, other: &Self) {
        self.elements.extend_from_slice(&other.elements);
        self.elements.sort_unstable();
        self.elements.dedup();
    }

    /// `pushUnary`.
    pub(crate) fn push_unary(&mut self, op: OpCode, out_size: u32) {
        for e in &mut self.elements {
            *e = evaluate_unary(op, out_size, self.bytes, *e, &FloatFormats::DEFAULT).unwrap();
        }
        if out_size != self.bytes {
            self.bytes = out_size;
            self.mask = calc_mask(out_size);
        }
    }

    /// `pushBinary`: every pair of elements.
    pub(crate) fn push_binary(&mut self, op: OpCode, out_size: u32, in1: &Self, in2: &Self) {
        self.elements.clear();
        for &a in &in1.elements {
            for &b in &in2.elements {
                let v =
                    evaluate_binary(op, out_size, in1.bytes, a, b, &FloatFormats::DEFAULT).unwrap();
                self.elements.push(v);
            }
        }
        if out_size != self.bytes {
            self.bytes = out_size;
            self.mask = calc_mask(out_size);
        }
    }

    /// `pullbackUnary`: an element no input produces is dropped.
    pub(crate) fn pull_back_unary(&mut self, op: OpCode, in_size: u32) {
        let bytes = self.bytes;
        self.elements = self
            .elements
            .iter()
            .filter_map(|&e| recover_input_unary(op, bytes, e, in_size).ok())
            .collect();
        if in_size != self.bytes {
            self.bytes = in_size;
            self.mask = calc_mask(in_size);
        }
    }

    /// `pullbackBinary`.
    pub(crate) fn pull_back_binary(&mut self, op: OpCode, slot: u32, val: u64) {
        let bytes = self.bytes;
        self.elements = self
            .elements
            .iter()
            .filter_map(|&e| recover_input_binary(op, slot, bytes, e, bytes, val).ok())
            .collect();
    }

    /// `getStartStopStep`: the start, stop and step of the one range
    /// holding exactly these elements, or `None` when there is none. Sorts
    /// and deduplicates the elements, as Ghidra's does.
    pub(crate) fn start_stop_step(&mut self) -> Option<(u64, u64, i32)> {
        if self.elements.is_empty() {
            return Some((0, 0, 1));
        }
        self.elements.sort_unstable();
        self.elements.dedup();
        let els = &self.elements;
        let mask = self.mask;
        if *els.last().unwrap() > mask {
            return None;
        }
        if els.len() == 1 {
            return Some((els[0], els[0].wrapping_add(1) & mask, 1));
        }
        if els.len() == 2 {
            let diff = els[0].wrapping_sub(els[1]) & mask;
            if matches!(diff, 1 | 2 | 4 | 8) {
                let start = els[1];
                return Some((start, start.wrapping_add(diff + diff) & mask, diff as i32));
            }
        }
        let mut bigpos = 0usize;
        let (mut biggest1, mut biggest2) = (0u64, 0u64);
        for i in 1..els.len() {
            let diff = els[i].wrapping_sub(els[i - 1]);
            if diff >= biggest1 {
                if diff > biggest1 {
                    biggest2 = biggest1;
                    biggest1 = diff;
                    bigpos = i;
                }
            } else if diff > biggest2 {
                biggest2 = diff;
            }
        }
        if biggest1 == 0 {
            return None;
        }
        if biggest2 == 0 {
            let step = biggest1 as i32;
            let stop = els
                .last()
                .unwrap()
                .wrapping_add(i64::from(step).cast_unsigned())
                & mask;
            return Some((els[0], stop, step));
        }
        let (mut count1, mut count3) = (0, 0);
        for i in 1..els.len() {
            let diff = els[i].wrapping_sub(els[i - 1]);
            if diff == biggest1 {
                count1 += 1;
            } else if diff != biggest2 {
                count3 += 1;
            }
        }
        if count3 > 0 || count1 > 1 {
            return None;
        }
        let step = biggest2 as i32;
        let wide = i64::from(step).cast_unsigned();
        let tmp = els.last().unwrap().wrapping_add(wide);
        if tmp <= mask {
            return None;
        }
        if tmp.wrapping_sub(mask.wrapping_add(1)) != els[0] {
            return None;
        }
        Some((els[bigpos], els[bigpos - 1].wrapping_add(wide), step))
    }

    /// `testEqual`: whether `range` and its validity agree with the model.
    pub(crate) fn agrees(&mut self, valid: bool, range: &CircleRange) -> bool {
        if self.elements.is_empty() {
            return range.is_empty();
        }
        if range.is_empty() {
            return false;
        }
        let described = self.start_stop_step();
        if described.is_some() != valid {
            return false;
        }
        match described {
            None => true,
            Some((start, stop, step)) => {
                start == range.min() && stop == range.end() && step == range.step()
            }
        }
    }
}
