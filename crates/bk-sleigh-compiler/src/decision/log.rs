//! The natural logarithm the decision-tree score uses: a `log` bit-equal to
//! glibc's (the variant for CPUs with fused multiply-add, glibc 2.28 and
//! later) on every argument, so that the compiler's output does not depend
//! on the host's C library (spec 4.3, ADR-032).
//!
//! Port of Szabolcs Nagy's `log` from Arm's optimized-routines
//! (`math/log.c`, revision 20859d3fd9e797dde592c489c8ef7d383f778620,
//! Copyright (c) 2018-2026, Arm Limited, SPDX-License-Identifier: MIT OR
//! Apache-2.0 WITH LLVM-exception), the code glibc ships as
//! `sysdeps/ieee754/dbl-64/e_log.c`. Configuration: 128 subintervals,
//! polynomial orders 6 and 12, the fast-FMA path.
//!
//! **Contraction.** glibc is compiled as GNU C, where GCC's default is
//! `-ffp-contract=fast`: in the FMA build every product whose only uses
//! are additions or subtractions becomes a fused multiply-add, across
//! statements. A port that fuses only the explicit `fma (z, invc, -1.0)`
//! differs from glibc on 1,134 of the 16,383 lines of the table (as musl
//! does, which compiles the same source without contraction). This port
//! writes out each fusion GCC performs as `libm::fma` (correctly rounded on
//! every platform) and rounds every other operation on its own (Rust
//! never contracts). Checked against glibc's results for every `k/n` with
//! `1 <= k < n <= 16384` (`log_table_test.rs`).
//!
//! Only finite positive normal arguments reach the score; the special
//! cases (zero, negative, subnormal, infinity, NaN) are handled as glibc
//! does, without its error reporting.

use libm::fma;

use super::log_data::{LN2HI, LN2LO, POLY, POLY1, TAB};

/// Offset of the reduced argument's range, `[OFF, 2 * OFF)`.
const OFF: u64 = 0x3fe6_0000_0000_0000;
/// log2 of the number of subintervals.
const TABLE_BITS: u32 = 7;

/// glibc's `log(x)`.
#[expect(
    clippy::many_single_char_names,
    reason = "the names of the upstream source"
)]
pub(crate) fn log(x: f64) -> f64 {
    let mut ix = x.to_bits();
    let top = (ix >> 48) as u32;
    let lo_bound = (1.0_f64 - f64::from_bits(0x3fb0_0000_0000_0000)).to_bits(); // 1 - 0x1p-4
    let hi_bound = (1.0_f64 + f64::from_bits(0x3fb0_9000_0000_0000)).to_bits(); // 1 + 0x1.09p-4
    if ix.wrapping_sub(lo_bound) < hi_bound.wrapping_sub(lo_bound) {
        return near_one(x, ix);
    }
    if top.wrapping_sub(0x0010) >= 0x7ff0 - 0x0010 {
        if ix.wrapping_mul(2) == 0 {
            return f64::NEG_INFINITY;
        }
        if ix == f64::INFINITY.to_bits() {
            return x;
        }
        if (top & 0x8000) != 0 || (top & 0x7ff0) == 0x7ff0 {
            return f64::NAN;
        }
        // Subnormal: normalise.
        ix = (x * f64::from_bits(0x4330_0000_0000_0000)).to_bits(); // x * 0x1p52
        ix = ix.wrapping_sub(52_u64 << 52);
    }
    let tmp = ix.wrapping_sub(OFF);
    let i = ((tmp >> (52 - TABLE_BITS)) % (1 << TABLE_BITS)) as usize;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfff_u64 << 52));
    let (invc, logc) = TAB.get(i).copied().unwrap_or((1.0, 0.0));
    let z = f64::from_bits(iz);

    let r = fma(z, invc, -1.0);
    let kd = k as f64;
    let w = fma(kd, LN2HI, logc);
    let hi = w + r;
    let lo = fma(kd, LN2LO, w - hi + r);
    let r2 = r * r;
    let [a0, a1, a2, a3, a4] = POLY;
    let p = fma(r2, fma(r, a4, a3), fma(r, a2, a1));
    fma(r * r2, p, fma(r2, a0, lo)) + hi
}

/// The branch for arguments within about 1/16 of 1.
fn near_one(x: f64, ix: u64) -> f64 {
    if ix == 1.0_f64.to_bits() {
        return 0.0;
    }
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10] = POLY1;
    let r = x - 1.0;
    let r2 = r * r;
    let r3 = r * r2;
    let inner = fma(r3, b10, fma(r2, b9, fma(r, b8, b7)));
    let middle = fma(r3, inner, fma(r2, b6, fma(r, b5, b4)));
    let poly = fma(r3, middle, fma(r2, b3, fma(r, b2, b1)));
    // Split r into a high part of 26 bits and the rest, to compute
    // -r*r/2 with extra precision. (r * 0x1p27 is exact, so fusing it into
    // the additions changes nothing.)
    let w = r * f64::from_bits(0x41a0_0000_0000_0000); // r * 0x1p27
    let rhi = r + w - w;
    let rlo = r - rhi;
    let rr = rhi * rhi;
    let hi = fma(rr, b0, r);
    let lo = fma(rr, b0, r - hi);
    let lo = fma(b0 * rlo, rhi + r, lo);
    let y = fma(r3, poly, lo);
    y + hi
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_values() {
        assert_eq!(log(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log(0.0), f64::NEG_INFINITY);
        assert!(log(-1.0).is_nan());
        assert!(log(f64::NAN).is_nan());
        assert_eq!(log(f64::INFINITY), f64::INFINITY);
        // log(2) as glibc gives it (first line of the checked-in table).
        assert_eq!(log(2.0).to_bits(), 0x3fe6_2e42_fefa_39ef);
        assert!((log(f64::MIN_POSITIVE / 4.0) - (-1024.0 * std::f64::consts::LN_2)).abs() < 1e-9);
    }
}
