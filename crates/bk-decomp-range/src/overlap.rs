//! How two intervals on the circle lie relative to each other (Ghidra
//! `CircleRange::encodeRangeOverlaps` and the table `arrange`).

/// The order in which the four bounds of `[l, r)` and `[l2, r2)` are met
/// going round the circle, starting at `l2` unless `l2` lies in `[l, r)`.
/// Ghidra encodes these as the letters `a`–`g`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overlap {
    /// `a`: `l r l2 r2` — disjoint, the second after the first.
    A,
    /// `b`: `l l2 r r2` — the second starts inside the first.
    B,
    /// `c`: `l l2 r2 r` — the second inside the first.
    C,
    /// `d`: `l2 l r r2` — the first inside the second.
    D,
    /// `e`: `l2 l r2 r` — the first starts inside the second.
    E,
    /// `f`: `l2 r2 l r` — disjoint, the first after the second.
    F,
    /// `g`: `l r2 l2 r` — together they cover the circle, or the
    /// combination is impossible.
    G,
}

/// Ghidra's `arrange` string, indexed by the six comparisons.
const ARRANGE: &[u8; 64] = b"gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

/// Classifies `[l1, r1)` against `[l2, r2)` (Ghidra
/// `encodeRangeOverlaps`): six comparisons packed into an index into
/// `arrange`.
#[inline]
pub(crate) fn encode(l1: u64, r1: u64, l2: u64, r2: u64) -> Overlap {
    let index = usize::from(l1 <= r1) << 5
        | usize::from(l1 <= l2) << 4
        | usize::from(l1 <= r2) << 3
        | usize::from(r1 <= l2) << 2
        | usize::from(r1 <= r2) << 1
        | usize::from(l2 <= r2);
    // The index is below 64 by construction; `arrange` holds only `a`–`g`.
    match ARRANGE.get(index) {
        Some(b'a') => Overlap::A,
        Some(b'b') => Overlap::B,
        Some(b'c') => Overlap::C,
        Some(b'd') => Overlap::D,
        Some(b'e') => Overlap::E,
        Some(b'f') => Overlap::F,
        _ => Overlap::G,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrange_is_ghidras_string() {
        assert_eq!(ARRANGE.len(), 64);
        assert!(ARRANGE.iter().all(|c| (b'a'..=b'g').contains(c)));
        assert_eq!(
            core::str::from_utf8(ARRANGE).unwrap(),
            "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda"
        );
    }

    #[test]
    fn the_six_orders() {
        assert_eq!(encode(10, 20, 30, 40), Overlap::A);
        assert_eq!(encode(10, 30, 20, 40), Overlap::B);
        assert_eq!(encode(10, 40, 20, 30), Overlap::C);
        assert_eq!(encode(20, 30, 10, 40), Overlap::D);
        assert_eq!(encode(20, 40, 10, 30), Overlap::E);
        assert_eq!(encode(30, 40, 10, 20), Overlap::F);
        assert_eq!(encode(30, 20, 10, 40), Overlap::G);
    }
}
