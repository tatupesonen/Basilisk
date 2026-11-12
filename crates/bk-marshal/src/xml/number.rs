//! Integer and boolean text forms, as Ghidra's C++ reads them.
//!
//! `XmlDecode` reads integers with `istringstream >> value` after clearing
//! the stream's base flags, which behaves like C's `strtoull` with base 0:
//! leading white space is skipped, an optional sign is taken, `0x` selects
//! hexadecimal, a leading `0` octal, anything else decimal, and conversion
//! stops at the first character that does not fit. Ghidra never checks the
//! stream state afterwards, so text without digits reads as 0 and a value
//! that does not fit saturates. No crate reproduces these rules (Rust's
//! `from_str_radix` and the `lexical` family reject what C accepts), so they
//! are written out here; `bk-core` uses the same functions for the numbers
//! inside join-piece attributes and address strings.

/// The base an integer is read in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Radix {
    /// Chosen by prefix: `0x` hexadecimal, `0` octal, otherwise decimal.
    Auto,
    /// Decimal only (`istream >> dec`).
    Decimal,
    /// Hexadecimal, with an optional `0x` prefix (`istream >> hex`).
    Hex,
}

/// The pieces of an integer found at the start of a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scanned {
    /// A `-` sign was present.
    pub negative: bool,
    /// The digits' value; meaningless if `overflow` is set.
    pub magnitude: u64,
    /// The digits denote a value above `u64::MAX`.
    pub overflow: bool,
    /// At least one digit was found.
    pub has_digits: bool,
    /// Bytes consumed, including leading white space, sign and prefix; 0 when
    /// no digit was found (C's `endptr == nptr`).
    pub consumed: usize,
}

impl Scanned {
    /// The value as C++ stores it into an unsigned 64-bit integer.
    pub fn as_u64(&self) -> u64 {
        if !self.has_digits {
            0
        } else if self.overflow {
            u64::MAX
        } else if self.negative {
            self.magnitude.wrapping_neg()
        } else {
            self.magnitude
        }
    }

    /// The value as C++ stores it into a signed 64-bit integer.
    pub fn as_i64(&self) -> i64 {
        if !self.has_digits {
            0
        } else if self.negative {
            if self.overflow || self.magnitude > i64::MIN.unsigned_abs() {
                i64::MIN
            } else {
                0i64.wrapping_sub_unsigned(self.magnitude)
            }
        } else if self.overflow {
            i64::MAX
        } else {
            i64::try_from(self.magnitude).unwrap_or(i64::MAX)
        }
    }

    /// The value as C++ stores it into an unsigned 32-bit integer.
    pub fn as_u32(&self) -> u32 {
        if !self.has_digits {
            return 0;
        }
        match u32::try_from(self.magnitude) {
            Ok(value) if !self.overflow => {
                if self.negative {
                    value.wrapping_neg()
                } else {
                    value
                }
            }
            _ => u32::MAX,
        }
    }
}

fn digit_value(byte: u8, base: u64) -> Option<u64> {
    let value = match byte {
        b'0'..=b'9' => u64::from(byte - b'0'),
        b'a'..=b'f' => u64::from(byte - b'a') + 10,
        b'A'..=b'F' => u64::from(byte - b'A') + 10,
        _ => return None,
    };
    (value < base).then_some(value)
}

/// Scans the integer at the start of `text`.
pub fn scan(text: &str, radix: Radix) -> Scanned {
    let bytes = text.as_bytes();
    let at = |index: usize| bytes.get(index).copied();
    let mut pos = 0;
    // C's isspace in the "C" locale.
    while matches!(at(pos), Some(b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')) {
        pos += 1;
    }
    let negative = at(pos) == Some(b'-');
    if matches!(at(pos), Some(b'+' | b'-')) {
        pos += 1;
    }
    let has_hex_prefix = at(pos) == Some(b'0')
        && matches!(at(pos + 1), Some(b'x' | b'X'))
        && at(pos + 2).is_some_and(|byte| digit_value(byte, 16).is_some());
    let base: u64 = match radix {
        Radix::Hex => 16,
        Radix::Auto if has_hex_prefix => 16,
        Radix::Auto if at(pos) == Some(b'0') => 8,
        Radix::Auto | Radix::Decimal => 10,
    };
    if base == 16 && has_hex_prefix {
        pos += 2;
    }
    let mut scanned = Scanned {
        negative,
        magnitude: 0,
        overflow: false,
        has_digits: false,
        consumed: 0,
    };
    while let Some(digit) = at(pos).and_then(|byte| digit_value(byte, base)) {
        scanned.has_digits = true;
        match scanned
            .magnitude
            .checked_mul(base)
            .and_then(|value| value.checked_add(digit))
        {
            Some(value) => scanned.magnitude = value,
            None => scanned.overflow = true,
        }
        pos += 1;
    }
    if scanned.has_digits {
        scanned.consumed = pos;
    }
    scanned
}

/// Reads an unsigned integer the way `XmlDecode::readUnsignedInteger` does.
pub fn parse_u64(text: &str) -> u64 {
    scan(text, Radix::Auto).as_u64()
}

/// Reads a signed integer the way `XmlDecode::readSignedInteger` does.
pub fn parse_i64(text: &str) -> i64 {
    scan(text, Radix::Auto).as_i64()
}

/// Reads an unsigned 32-bit integer with base detection.
pub fn parse_u32(text: &str) -> u32 {
    scan(text, Radix::Auto).as_u32()
}

/// Reads a boolean the way Ghidra's `xml_readbool` does: true if the text
/// starts with `t`, `1` or `y`.
pub fn parse_bool(text: &str) -> bool {
    matches!(text.as_bytes().first(), Some(b't' | b'1' | b'y'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_forms() {
        let cases: &[(&str, u64)] = &[
            ("0", 0),
            ("7", 7),
            ("123", 123),
            ("0x1f", 0x1f),
            ("0X1F", 0x1f),
            ("0xABCdef", 0x00ab_cdef),
            ("010", 8),
            ("0777", 0o777),
            ("08", 0),
            ("  42", 42),
            ("\t\n\r\x0b\x0c 42", 42),
            ("+42", 42),
            ("42abc", 42),
            ("42 ", 42),
            ("0x", 0),
            ("0xg", 0),
            ("", 0),
            ("abc", 0),
            ("-", 0),
            ("- 1", 0),
            ("-1", u64::MAX),
            ("-0x10", 0x10u64.wrapping_neg()),
            ("18446744073709551615", u64::MAX),
            ("18446744073709551616", u64::MAX),
            ("-18446744073709551616", u64::MAX),
            ("0xffffffffffffffff", u64::MAX),
            ("0x1ffffffffffffffff", u64::MAX),
            ("01777777777777777777777", u64::MAX),
            ("1e5", 1),
            ("1.5", 1),
            ("0b11", 0),
        ];
        for &(text, expected) in cases {
            assert_eq!(parse_u64(text), expected, "{text:?}");
        }
    }

    #[test]
    fn signed_forms() {
        let cases: &[(&str, i64)] = &[
            ("0", 0),
            ("3", 3),
            ("-256", -256),
            ("-0x100", -256),
            ("+0x100", 256),
            ("-010", -8),
            ("9223372036854775807", i64::MAX),
            ("9223372036854775808", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("-9223372036854775809", i64::MIN),
            ("0x7fffffffffffffff", i64::MAX),
            ("0xffffffffffffffff", i64::MAX),
            ("99999999999999999999999", i64::MAX),
            ("-99999999999999999999999", i64::MIN),
            ("unknown", 0),
            ("", 0),
            (" -5x", -5),
        ];
        for &(text, expected) in cases {
            assert_eq!(parse_i64(text), expected, "{text:?}");
        }
    }

    #[test]
    fn narrow_and_fixed_radix_forms() {
        assert_eq!(parse_u32("4"), 4);
        assert_eq!(parse_u32("0x10"), 16);
        assert_eq!(parse_u32("4294967295"), u32::MAX);
        assert_eq!(parse_u32("4294967296"), u32::MAX);
        assert_eq!(parse_u32("99999999999999999999999"), u32::MAX);
        assert_eq!(parse_u32("-1"), u32::MAX);
        assert_eq!(parse_u32("-2"), u32::MAX - 1);
        assert_eq!(parse_u32("x"), 0);
        assert_eq!(scan("012", Radix::Decimal).as_u32(), 12);
        assert_eq!(scan("0x12", Radix::Decimal).as_u32(), 0);
        assert_eq!(scan("ff", Radix::Hex).as_u64(), 0xff);
        assert_eq!(scan("0xff", Radix::Hex).as_u64(), 0xff);
        assert_eq!(scan("12", Radix::Hex).as_u64(), 0x12);
        assert_eq!(scan("zz", Radix::Hex).as_u64(), 0);
    }

    #[test]
    fn consumed_counts_follow_strtoul() {
        assert_eq!(scan("0x10:4", Radix::Auto).consumed, 4);
        assert_eq!(scan("  12+3", Radix::Auto).consumed, 4);
        assert_eq!(scan("abc", Radix::Auto).consumed, 0);
        assert_eq!(scan("  -", Radix::Auto).consumed, 0);
        // "0x" without a hex digit is the octal number 0 followed by "x".
        assert_eq!(scan("0xz", Radix::Auto).consumed, 1);
        assert_eq!(scan("-7", Radix::Auto).consumed, 2);
        assert!(scan("-7", Radix::Auto).negative);
        assert!(!scan("", Radix::Auto).has_digits);
    }

    #[test]
    fn booleans() {
        for text in ["true", "t", "1", "yes", "y", "10", "tfalse"] {
            assert!(parse_bool(text), "{text:?}");
        }
        for text in ["", "false", "0", "no", "True", "TRUE", "Y", " true", "2"] {
            assert!(!parse_bool(text), "{text:?}");
        }
    }
}
