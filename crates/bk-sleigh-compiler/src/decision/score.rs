//! The entropy score of a candidate field (`DecisionNode::getScore`,
//! inventory 10 c.8), computed as x86-64 Linux computes it (spec 4.3,
//! ADR-032): IEEE `f64` operations each rounded on its own, in Ghidra's
//! order, with glibc's `log`.

use super::log::log;

/// The score of a field whose fully specified patterns fall into bins with
/// the given counts (indexed by the field's value), out of `total` such
/// patterns, at a node holding `list_len` patterns. −1 when no pattern is
/// fully specified or one bin holds every pattern of the node.
pub(crate) fn score(counts: &[u32], total: u32, list_len: usize) -> f64 {
    if total == 0 {
        return -1.0;
    }
    let total = f64::from(total);
    let mut sc = 0.0_f64;
    for &count in counts {
        if count == 0 {
            continue;
        }
        if count as usize >= list_len {
            return -1.0;
        }
        let p = f64::from(count) / total;
        // Never fuse: x86-64 rounds the product before the subtraction.
        let product = p * log(p);
        sc -= product;
    }
    sc / log(2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `TI_MSP430` tie of `docs/research/sla-host-dependence.md`
    /// section 2: bins (2,2,1) of a 3-bit field against (2,1,2) of a 2-bit
    /// field, 5 of 7 patterns. Unfused, both sums round to the same value,
    /// so the field scanned first (the 2-bit one) is kept; fused, the 2-bit
    /// field's score is 2 ulp lower and the 3-bit field would win.
    #[test]
    fn the_msp430_tie_is_decided_by_unfused_arithmetic() {
        let three_bit = score(&[2, 2, 0, 0, 1, 0, 0, 0], 5, 7);
        let two_bit = score(&[2, 1, 2, 0], 5, 7);
        assert_eq!(three_bit.to_bits(), 0x3ff8_59d1_4626_7a17);
        assert_eq!(two_bit.to_bits(), three_bit.to_bits());
        // The fused computation of the same field differs.
        let fused = [2.0_f64, 1.0, 2.0].iter().fold(0.0_f64, |sc, c| {
            let p = c / 5.0;
            (-p).mul_add(log(p), sc)
        }) / log(2.0);
        assert_eq!(fused.to_bits(), 0x3ff8_59d1_4626_7a15);
        assert_eq!(
            three_bit.partial_cmp(&two_bit),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn degenerate_fields_score_minus_one() {
        assert_eq!(score(&[0, 0], 0, 3).to_bits(), (-1.0_f64).to_bits());
        assert_eq!(score(&[3, 0], 3, 3).to_bits(), (-1.0_f64).to_bits());
        assert_eq!(score(&[1, 1], 2, 2).to_bits(), 1.0_f64.to_bits());
    }
}
