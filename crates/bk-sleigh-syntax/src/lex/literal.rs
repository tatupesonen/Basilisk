//! Integer literals: arbitrary width, with the radix they were written in.
//!
//! Ghidra's Java front end reads literals into `RadixBigInteger`, a
//! `BigInteger` that remembers its radix; the compiler later rejects values
//! that do not fit where they are used. [`IntValue`] keeps the exact value
//! (inline when it fits in 64 bits, which is always the case in practice)
//! and [`Radix`] keeps how it was written.

use std::fmt;

use num_bigint::BigUint;

/// The radix an integer literal was written in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Radix {
    /// `0b1010`.
    Binary,
    /// `10`, or `0n10` in a semantic section.
    Decimal,
    /// `0x1F`.
    Hex,
}

impl Radix {
    /// The numeric base: 2, 10 or 16.
    pub const fn base(self) -> u32 {
        match self {
            Self::Binary => 2,
            Self::Decimal => 10,
            Self::Hex => 16,
        }
    }
}

/// Longest digit string accepted for one literal. Longer literals are
/// rejected so that decimal conversion stays bounded.
pub const MAX_DIGITS: usize = 4096;

/// Why a digit string is not an integer literal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IntError {
    /// No digits at all.
    Empty,
    /// A character that is not a digit of the radix.
    BadDigit,
    /// More than [`MAX_DIGITS`] digits.
    TooLong,
}

/// A non-negative integer of any width.
///
/// Values up to 64 bits are stored inline; wider ones (which no shipped
/// specification contains) are a boxed `num_bigint::BigUint`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IntValue(Repr);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Repr {
    /// The value fits in 64 bits.
    Small(u64),
    /// The value needs more than 64 bits.
    Big(Box<BigUint>),
}

impl IntValue {
    /// The value zero.
    pub const ZERO: Self = Self(Repr::Small(0));

    /// A value that fits in 64 bits.
    pub const fn from_u64(value: u64) -> Self {
        Self(Repr::Small(value))
    }

    /// The value, if it fits in 64 bits.
    pub const fn to_u64(&self) -> Option<u64> {
        match &self.0 {
            Repr::Small(v) => Some(*v),
            Repr::Big(_) => None,
        }
    }

    /// The low 64 bits (what Java's `BigInteger.longValue` returns).
    pub fn low_u64(&self) -> u64 {
        match &self.0 {
            Repr::Small(v) => *v,
            Repr::Big(big) => big.iter_u64_digits().next().unwrap_or(0),
        }
    }

    /// Number of significant bits; zero has none.
    pub fn bit_len(&self) -> u64 {
        match &self.0 {
            Repr::Small(v) => u64::from(64 - v.leading_zeros()),
            Repr::Big(big) => big.bits(),
        }
    }

    /// The exact value as a big integer.
    pub fn to_biguint(&self) -> BigUint {
        match &self.0 {
            Repr::Small(v) => BigUint::from(*v),
            Repr::Big(big) => (**big).clone(),
        }
    }

    /// Parses `digits` (no prefix) in `radix`.
    pub fn parse(digits: &str, radix: Radix) -> Result<Self, IntError> {
        if digits.is_empty() {
            return Err(IntError::Empty);
        }
        if digits.len() > MAX_DIGITS {
            return Err(IntError::TooLong);
        }
        let base = radix.base();
        // Fast path, taken by every literal in practice: accumulate in a u64.
        let mut small: u64 = 0;
        let mut fits = true;
        for &byte in digits.as_bytes() {
            let digit = char::from(byte).to_digit(base).ok_or(IntError::BadDigit)?;
            if fits {
                match small
                    .checked_mul(u64::from(base))
                    .and_then(|v| v.checked_add(u64::from(digit)))
                {
                    Some(v) => small = v,
                    None => fits = false,
                }
            }
        }
        if fits {
            return Ok(Self::from_u64(small));
        }
        let big = BigUint::parse_bytes(digits.as_bytes(), base).ok_or(IntError::BadDigit)?;
        Ok(Self(Repr::Big(Box::new(big))))
    }

    /// Writes the value in `radix`, without a prefix.
    pub fn to_string_radix(&self, radix: Radix) -> String {
        match (&self.0, radix) {
            (Repr::Small(v), Radix::Decimal) => v.to_string(),
            (Repr::Small(v), Radix::Hex) => format!("{v:x}"),
            (Repr::Small(v), Radix::Binary) => format!("{v:b}"),
            (Repr::Big(big), _) => big.to_str_radix(radix.base()),
        }
    }
}

impl From<u64> for IntValue {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl fmt::Display for IntValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_radix(Radix::Decimal))
    }
}

impl fmt::Debug for IntValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_values_in_each_radix() {
        assert_eq!(
            IntValue::parse("0", Radix::Decimal).unwrap().to_u64(),
            Some(0)
        );
        assert_eq!(
            IntValue::parse("42", Radix::Decimal).unwrap().to_u64(),
            Some(42)
        );
        assert_eq!(
            IntValue::parse("fF", Radix::Hex).unwrap().to_u64(),
            Some(255)
        );
        assert_eq!(
            IntValue::parse("1010", Radix::Binary).unwrap().to_u64(),
            Some(10)
        );
        assert_eq!(
            IntValue::parse("18446744073709551615", Radix::Decimal)
                .unwrap()
                .to_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            IntValue::parse("ffffffffffffffff", Radix::Hex)
                .unwrap()
                .to_u64(),
            Some(u64::MAX)
        );
    }

    #[test]
    fn values_wider_than_64_bits_are_exact() {
        let v = IntValue::parse("18446744073709551616", Radix::Decimal).unwrap();
        assert_eq!(v.to_u64(), None);
        assert_eq!(v.low_u64(), 0);
        assert_eq!(v.bit_len(), 65);
        assert_eq!(v.to_biguint(), BigUint::from(1u8) << 64);
        assert_eq!(v.to_string(), "18446744073709551616");
        assert_eq!(v.to_string_radix(Radix::Hex), "10000000000000000");

        let h = IntValue::parse("123456789abcdef0fedcba9876543210", Radix::Hex).unwrap();
        assert_eq!(h.bit_len(), 125);
        assert_eq!(h.low_u64(), 0xfedc_ba98_7654_3210);
        assert_eq!(
            h.to_string_radix(Radix::Hex),
            "123456789abcdef0fedcba9876543210"
        );
        assert_eq!(h.to_string(), "24197857203266734881846307747534221840");
        assert_eq!(IntValue::parse(&h.to_string(), Radix::Decimal).unwrap(), h);

        let b = IntValue::parse(&format!("1{}", "0".repeat(70)), Radix::Binary).unwrap();
        assert_eq!(b.bit_len(), 71);
        assert_eq!(
            b.to_string_radix(Radix::Binary),
            format!("1{}", "0".repeat(70))
        );
    }

    #[test]
    fn leading_zeros_do_not_make_a_value_big() {
        let v = IntValue::parse(&format!("{}1", "0".repeat(40)), Radix::Hex).unwrap();
        assert_eq!(v.to_u64(), Some(1));
        assert_eq!(IntValue::ZERO.bit_len(), 0);
        assert_eq!(IntValue::from(5).bit_len(), 3);
    }

    #[test]
    fn malformed_digit_strings_are_rejected() {
        assert_eq!(IntValue::parse("", Radix::Decimal), Err(IntError::Empty));
        assert_eq!(
            IntValue::parse("12a", Radix::Decimal),
            Err(IntError::BadDigit)
        );
        assert_eq!(IntValue::parse("2", Radix::Binary), Err(IntError::BadDigit));
        assert_eq!(IntValue::parse("g", Radix::Hex), Err(IntError::BadDigit));
        assert_eq!(
            IntValue::parse(&"1".repeat(MAX_DIGITS + 1), Radix::Decimal),
            Err(IntError::TooLong)
        );
        assert!(IntValue::parse(&"9".repeat(MAX_DIGITS), Radix::Decimal).is_ok());
    }
}
