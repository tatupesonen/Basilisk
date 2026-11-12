//! [`Wide`]: the operand type of the wide evaluation path.
//!
//! Ghidra's Java behaviours work on `BigInteger` when an operand is wider than
//! 8 bytes (vector registers, 80- and 128-bit floats). basilisk uses a fixed
//! 512-bit unsigned integer instead: it covers the widest register any Ghidra
//! processor module computes with (the 64-byte AVX-512 `ZMM` registers), it is
//! `Copy`, and evaluating an operation on it never allocates.
//!
//! The arithmetic is the `primitive-types` crate's `U512`; this module adds what p-code
//! needs on top: byte-size masks, sign handling by byte size, and conversion
//! to and from bytes and `num_bigint` integers.

use core::cmp::Ordering;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use num_bigint::{BigInt, BigUint, Sign};
use primitive_types::U512;

/// A 512-bit unsigned integer: a p-code value of up to 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Wide(U512);

impl Wide {
    /// The largest operand size in bytes a `Wide` can hold.
    pub const BYTES: u32 = 64;
    /// The number of bits in a `Wide`.
    pub const BITS: u32 = 512;
    /// Zero.
    pub const ZERO: Wide = Wide(U512([0; 8]));
    /// One.
    pub const ONE: Wide = Wide::from_u64(1);
    /// The value with all 512 bits set.
    pub const MAX: Wide = Wide(U512([u64::MAX; 8]));

    /// Widens a `u64`.
    pub const fn from_u64(value: u64) -> Wide {
        Wide::from_u128(value as u128)
    }

    /// Widens a `u128`.
    pub const fn from_u128(value: u128) -> Wide {
        Wide(U512([value as u64, (value >> 64) as u64, 0, 0, 0, 0, 0, 0]))
    }

    /// Reads a little-endian value; `None` if it has a non-zero byte beyond
    /// the 64th.
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Wide> {
        let (low, excess) = bytes.split_at_checked(64).unwrap_or((bytes, &[]));
        excess
            .iter()
            .all(|&byte| byte == 0)
            .then(|| Wide(U512::from_little_endian(low)))
    }

    /// Reads a big-endian value; `None` if it has a non-zero byte beyond the
    /// 64 least significant.
    pub fn from_be_bytes(bytes: &[u8]) -> Option<Wide> {
        let split = bytes.len().saturating_sub(64);
        let (excess, low) = bytes.split_at_checked(split).unwrap_or((&[], bytes));
        excess
            .iter()
            .all(|&byte| byte == 0)
            .then(|| Wide(U512::from_big_endian(low)))
    }

    /// The value as 64 little-endian bytes.
    pub fn to_le_bytes(self) -> [u8; 64] {
        self.0.to_little_endian()
    }

    /// Writes the low `out.len()` bytes of the value, least significant
    /// first. Bytes beyond the 64th are written as zero.
    pub fn write_le_bytes(self, out: &mut [u8]) {
        let bytes = self.to_le_bytes();
        let mut source = bytes.iter();
        for byte in out {
            *byte = source.next().copied().unwrap_or(0);
        }
    }

    /// Writes the low `out.len()` bytes of the value, most significant first.
    /// Bytes beyond the 64th are written as zero.
    pub fn write_be_bytes(self, out: &mut [u8]) {
        let bytes = self.to_le_bytes();
        let mut source = bytes.iter();
        for byte in out.iter_mut().rev() {
            *byte = source.next().copied().unwrap_or(0);
        }
    }

    /// The low 64 bits.
    pub const fn low_u64(self) -> u64 {
        self.0.low_u64()
    }

    /// The low 128 bits.
    pub const fn low_u128(self) -> u128 {
        self.0.low_u128()
    }

    /// The value as a `u64`, if it fits.
    pub fn to_u64(self) -> Option<u64> {
        (self.bit_len() <= 64).then(|| self.low_u64())
    }

    /// Whether the value is zero.
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    /// Bit `index` (0 is the least significant); `false` beyond bit 511.
    pub fn bit(self, index: u32) -> bool {
        index < Wide::BITS && self.0.bit(index as usize)
    }

    /// The number of bits needed to represent the value (0 for zero), Java's
    /// `BigInteger.bitLength`.
    pub fn bit_len(self) -> u32 {
        Wide::BITS - self.0.leading_zeros()
    }

    /// The number of one bits.
    pub fn count_ones(self) -> u32 {
        self.0.0.iter().map(|limb| limb.count_ones()).sum()
    }

    /// The mask that keeps the low `size` bytes; all ones for 64 bytes or
    /// more.
    pub fn mask(size: u32) -> Wide {
        if size >= Wide::BYTES {
            Wide::MAX
        } else {
            Wide::MAX >> (Wide::BITS - size * 8)
        }
    }

    /// The low `size` bytes of the value.
    #[must_use]
    pub fn truncate(self, size: u32) -> Wide {
        self & Wide::mask(size)
    }

    /// Whether the sign bit of the value, taken as a `size`-byte integer, is
    /// set. `false` for a size of 0 or above 64.
    pub fn is_negative(self, size: u32) -> bool {
        size != 0 && self.bit(size.saturating_mul(8) - 1)
    }

    /// The value, taken as a `size`-byte twos-complement integer, extended
    /// to all 512 bits.
    #[must_use]
    pub fn sign_extend(self, size: u32) -> Wide {
        let low = self.truncate(size);
        if low.is_negative(size) {
            low | !Wide::mask(size)
        } else {
            low
        }
    }

    /// Addition modulo 2^512.
    #[must_use]
    pub fn wrapping_add(self, rhs: Wide) -> Wide {
        Wide(self.0.overflowing_add(rhs.0).0)
    }

    /// Subtraction modulo 2^512.
    #[must_use]
    pub fn wrapping_sub(self, rhs: Wide) -> Wide {
        Wide(self.0.overflowing_sub(rhs.0).0)
    }

    /// Multiplication modulo 2^512.
    #[must_use]
    pub fn wrapping_mul(self, rhs: Wide) -> Wide {
        Wide(self.0.overflowing_mul(rhs.0).0)
    }

    /// Negation modulo 2^512.
    #[must_use]
    pub fn wrapping_neg(self) -> Wide {
        Wide(self.0.overflowing_neg().0)
    }

    /// Unsigned quotient; `None` when `rhs` is zero.
    pub fn checked_div(self, rhs: Wide) -> Option<Wide> {
        self.0.checked_div(rhs.0).map(Wide)
    }

    /// Unsigned remainder; `None` when `rhs` is zero.
    pub fn checked_rem(self, rhs: Wide) -> Option<Wide> {
        self.0.checked_rem(rhs.0).map(Wide)
    }

    /// The value as an arbitrary-precision unsigned integer.
    pub fn to_biguint(self) -> BigUint {
        BigUint::from_bytes_le(&self.to_le_bytes())
    }

    /// The low 512 bits of an arbitrary-precision unsigned integer.
    pub fn from_biguint(value: &BigUint) -> Wide {
        let mut limbs = [0u64; 8];
        for (to, from) in limbs.iter_mut().zip(value.iter_u64_digits()) {
            *to = from;
        }
        Wide(U512(limbs))
    }

    /// The low 512 bits of the twos-complement form of an arbitrary-precision
    /// signed integer, which is how Java's emulator stores a `BigInteger`
    /// result into a varnode.
    pub fn from_bigint(value: &BigInt) -> Wide {
        let magnitude = Wide::from_biguint(value.magnitude());
        if value.sign() == Sign::Minus {
            magnitude.wrapping_neg()
        } else {
            magnitude
        }
    }

    /// The value, taken as a `size`-byte twos-complement integer, as an
    /// arbitrary-precision signed integer.
    pub fn to_bigint_signed(self, size: u32) -> BigInt {
        let low = self.truncate(size);
        if low.is_negative(size) {
            BigInt::from_biguint(
                Sign::Minus,
                low.sign_extend(size).wrapping_neg().to_biguint(),
            )
        } else {
            BigInt::from(low.to_biguint())
        }
    }
}

impl Default for Wide {
    fn default() -> Wide {
        Wide::ZERO
    }
}

impl From<u64> for Wide {
    fn from(value: u64) -> Wide {
        Wide::from_u64(value)
    }
}

impl From<u128> for Wide {
    fn from(value: u128) -> Wide {
        Wide::from_u128(value)
    }
}

impl PartialOrd for Wide {
    fn partial_cmp(&self, other: &Wide) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Wide {
    fn cmp(&self, other: &Wide) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl BitAnd for Wide {
    type Output = Wide;

    fn bitand(self, rhs: Wide) -> Wide {
        Wide(self.0 & rhs.0)
    }
}

impl BitOr for Wide {
    type Output = Wide;

    fn bitor(self, rhs: Wide) -> Wide {
        Wide(self.0 | rhs.0)
    }
}

impl BitXor for Wide {
    type Output = Wide;

    fn bitxor(self, rhs: Wide) -> Wide {
        Wide(self.0 ^ rhs.0)
    }
}

impl Shl<u32> for Wide {
    type Output = Wide;

    /// Logical left shift; zero when `bits` is 512 or more.
    fn shl(self, bits: u32) -> Wide {
        Wide(self.0 << bits)
    }
}

impl Shr<u32> for Wide {
    type Output = Wide;

    /// Logical right shift; zero when `bits` is 512 or more.
    fn shr(self, bits: u32) -> Wide {
        Wide(self.0 >> bits)
    }
}

impl Not for Wide {
    type Output = Wide;

    fn not(self) -> Wide {
        Wide(!self.0)
    }
}

impl fmt::Debug for Wide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wide(0x{self:x})")
    }
}

impl fmt::Display for Wide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for Wide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_low_parts() {
        assert_eq!(Wide::ZERO.low_u64(), 0);
        assert_eq!(Wide::ONE.low_u64(), 1);
        assert_eq!(Wide::from_u64(u64::MAX).low_u128(), u128::from(u64::MAX));
        assert_eq!(Wide::from_u128(u128::MAX).low_u128(), u128::MAX);
        assert_eq!(Wide::from_u128(u128::MAX).low_u64(), u64::MAX);
        assert_eq!(Wide::from(7u64), Wide::from(7u128));
        assert_eq!(Wide::from_u64(5).to_u64(), Some(5));
        assert_eq!(Wide::from_u128(1 << 64).to_u64(), None);
        assert_eq!(Wide::MAX.count_ones(), 512);
        assert_eq!(Wide::MAX.bit_len(), 512);
        assert_eq!(Wide::ZERO.bit_len(), 0);
        assert_eq!(Wide::from_u64(0x80).bit_len(), 8);
        assert!(Wide::ZERO.is_zero());
        assert!(!Wide::ONE.is_zero());
    }

    #[test]
    fn bytes_round_trip() {
        let bytes: Vec<u8> = (1..=20).collect();
        let le = Wide::from_le_bytes(&bytes).unwrap();
        let mut out = [0u8; 20];
        le.write_le_bytes(&mut out);
        assert_eq!(out.as_slice(), bytes.as_slice());
        let be = Wide::from_be_bytes(&bytes).unwrap();
        be.write_be_bytes(&mut out);
        assert_eq!(out.as_slice(), bytes.as_slice());
        assert_eq!(le.low_u64(), 0x0807_0605_0403_0201);
        assert_eq!(be.low_u64(), 0x0d0e_0f10_1112_1314);

        // Truncating and zero-padding writes.
        let mut short = [0u8; 2];
        le.write_le_bytes(&mut short);
        assert_eq!(short, [1, 2]);
        be.write_be_bytes(&mut short);
        assert_eq!(short, [19, 20]);
        let mut long = [0xaau8; 70];
        Wide::MAX.write_le_bytes(&mut long);
        assert!(long[..64].iter().all(|&b| b == 0xff) && long[64..].iter().all(|&b| b == 0));
        Wide::MAX.write_be_bytes(&mut long);
        assert!(long[6..].iter().all(|&b| b == 0xff) && long[..6].iter().all(|&b| b == 0));

        // More than 64 bytes only when the excess is zero.
        let mut big = [0u8; 65];
        assert_eq!(Wide::from_le_bytes(&big), Some(Wide::ZERO));
        big[64] = 1;
        assert_eq!(Wide::from_le_bytes(&big), None);
        assert_eq!(Wide::from_be_bytes(&big), Some(Wide::ONE));
        assert_eq!(Wide::from_le_bytes(&[]), Some(Wide::ZERO));
    }

    #[test]
    fn masks_and_signs() {
        assert_eq!(Wide::mask(0), Wide::ZERO);
        assert_eq!(Wide::mask(1), Wide::from_u64(0xff));
        assert_eq!(Wide::mask(16), Wide::from_u128(u128::MAX));
        assert_eq!(Wide::mask(64), Wide::MAX);
        assert_eq!(Wide::mask(1000), Wide::MAX);
        assert_eq!(Wide::mask(63).bit_len(), 504);
        assert_eq!(Wide::MAX.truncate(2), Wide::from_u64(0xffff));

        assert!(Wide::from_u64(0x80).is_negative(1));
        assert!(!Wide::from_u64(0x80).is_negative(2));
        assert!(!Wide::MAX.is_negative(0));
        assert!(Wide::MAX.is_negative(64));
        assert!(!Wide::MAX.is_negative(65));
        assert!(!Wide::MAX.is_negative(u32::MAX));

        assert_eq!(
            Wide::from_u64(0x80).sign_extend(1),
            Wide::MAX.wrapping_sub(Wide::from(0x7fu64))
        );
        assert_eq!(Wide::from_u64(0x17f).sign_extend(1), Wide::from_u64(0x7f));
        assert_eq!(Wide::from_u64(5).sign_extend(0), Wide::ZERO);
        assert_eq!(Wide::MAX.sign_extend(64), Wide::MAX);
    }

    #[test]
    fn arithmetic_wraps() {
        assert_eq!(Wide::MAX.wrapping_add(Wide::ONE), Wide::ZERO);
        assert_eq!(Wide::ZERO.wrapping_sub(Wide::ONE), Wide::MAX);
        assert_eq!(Wide::ONE.wrapping_neg(), Wide::MAX);
        assert_eq!(Wide::MAX.wrapping_mul(Wide::MAX), Wide::ONE);
        let a = Wide::from_u128(u128::MAX);
        assert_eq!(
            a.wrapping_mul(a),
            Wide::ONE
                .shl(256)
                .wrapping_sub(Wide::ONE.shl(129))
                .wrapping_add(Wide::ONE)
        );
        assert_eq!(
            Wide::from_u64(17).checked_div(Wide::from_u64(5)),
            Some(Wide::from_u64(3))
        );
        assert_eq!(
            Wide::from_u64(17).checked_rem(Wide::from_u64(5)),
            Some(Wide::from_u64(2))
        );
        assert_eq!(Wide::ONE.checked_div(Wide::ZERO), None);
        assert_eq!(Wide::ONE.checked_rem(Wide::ZERO), None);
        assert_eq!(Wide::MAX.checked_div(Wide::MAX), Some(Wide::ONE));
    }

    #[test]
    fn shifts_are_unbounded() {
        assert_eq!(Wide::ONE.shl(511).bit_len(), 512);
        assert_eq!(Wide::ONE.shl(512), Wide::ZERO);
        assert_eq!(Wide::MAX.shl(u32::MAX), Wide::ZERO);
        assert_eq!(Wide::MAX.shr(511), Wide::ONE);
        assert_eq!(Wide::MAX.shr(512), Wide::ZERO);
        assert_eq!(Wide::MAX.shr(u32::MAX), Wide::ZERO);
        assert!(Wide::ONE.shl(200).bit(200));
        assert!(!Wide::ONE.shl(200).bit(199));
        assert!(!Wide::MAX.bit(512));
    }

    #[test]
    fn ordering_is_numeric() {
        assert!(Wide::ONE.shl(64) > Wide::from_u64(u64::MAX));
        assert!(Wide::ZERO < Wide::ONE);
        assert_eq!(Wide::MAX.cmp(&Wide::MAX), Ordering::Equal);
    }

    #[test]
    fn bigint_conversions() {
        let value = Wide::ONE.shl(300).wrapping_add(Wide::from_u64(12345));
        assert_eq!(Wide::from_biguint(&value.to_biguint()), value);
        assert_eq!(
            Wide::from_biguint(&(BigUint::from(1u8) << 600u32)),
            Wide::ZERO
        );
        assert_eq!(Wide::from_bigint(&BigInt::from(-1)), Wide::MAX);
        assert_eq!(
            Wide::from_bigint(&BigInt::from(-2)).truncate(2),
            Wide::from_u64(0xfffe)
        );
        assert_eq!(Wide::from_bigint(&BigInt::from(77)), Wide::from_u64(77));
        assert_eq!(Wide::from_u64(0xff).to_bigint_signed(1), BigInt::from(-1));
        assert_eq!(Wide::from_u64(0xff).to_bigint_signed(2), BigInt::from(255));
        assert_eq!(Wide::from_u64(0x80).to_bigint_signed(1), BigInt::from(-128));
        assert_eq!(Wide::MAX.to_bigint_signed(64), BigInt::from(-1));
        assert_eq!(Wide::MAX.to_bigint_signed(0), BigInt::from(0));
    }

    #[test]
    fn formatting() {
        assert_eq!(format!("{:x}", Wide::from_u64(0xbeef)), "beef");
        assert_eq!(format!("{}", Wide::from_u64(1234)), "1234");
        assert_eq!(format!("{:?}", Wide::from_u64(255)), "Wide(0xff)");
    }
}
