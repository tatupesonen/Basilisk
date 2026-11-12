//! Decoding of attribute values, matching Ghidra's `SpecXmlUtils`.

/// Parses digits the way Java's `new BigInteger(text, radix).longValue()`
/// does: an optional single sign, then one or more digits, the result
/// reduced to its low 64 bits.
fn parse_wrapping(text: &str, radix: u32) -> Option<u64> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, text.get(1..)?),
        b'+' => (false, text.get(1..)?),
        _ => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for c in digits.chars() {
        let digit = c.to_digit(radix)?;
        value = value
            .wrapping_mul(u64::from(radix))
            .wrapping_add(u64::from(digit));
    }
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// Decodes an integer as `SpecXmlUtils.decodeLong` does: `0x` introduces
/// hexadecimal, any other leading `0` octal, anything else is decimal; the
/// value wraps to 64 bits. `None` where Ghidra throws
/// `NumberFormatException`.
pub(crate) fn decode_u64(text: &str) -> Option<u64> {
    if text == "0" {
        Some(0)
    } else if let Some(hex) = text.strip_prefix("0x") {
        parse_wrapping(hex, 16)
    } else if let Some(octal) = text.strip_prefix('0') {
        parse_wrapping(octal, 8)
    } else {
        parse_wrapping(text, 10)
    }
}

/// Decodes an integer as `SpecXmlUtils.decodeInt` does: like
/// [`decode_u64`], truncated to a signed 32-bit value.
pub(crate) fn decode_i32(text: &str) -> Option<i32> {
    decode_u64(text).map(|v| v as u32 as i32)
}

/// Decodes a boolean as `SpecXmlUtils.decodeNullableBoolean` does: only
/// the first character counts (`y`, `t`, `1` are true; `n`, `f`, `0` are
/// false); anything else is undecided.
pub(crate) fn decode_bool(text: &str) -> Option<bool> {
    match text.as_bytes().first()? {
        b'y' | b't' | b'1' => Some(true),
        b'n' | b'f' | b'0' => Some(false),
        _ => None,
    }
}

/// Whether `text` is one of the six spellings the schema's `boolean_type`
/// allows.
pub(crate) fn is_schema_boolean(text: &str) -> bool {
    matches!(text, "true" | "false" | "yes" | "no" | "1" | "0")
}

/// `String.split(separator)`: pieces between separators, with trailing
/// empty pieces dropped (so an empty string yields one empty piece and a
/// lone separator none).
pub(crate) fn java_split(text: &str, separator: char) -> impl Iterator<Item = &str> {
    let pieces = if text.is_empty() {
        text
    } else {
        text.trim_end_matches(separator)
    };
    let none = !text.is_empty() && pieces.is_empty();
    pieces.split(separator).filter(move |_| !none)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("0", Some(0))]
    #[case("7", Some(7))]
    #[case("32", Some(32))]
    #[case("0x20", Some(32))]
    #[case("0xFF", Some(255))]
    #[case("010", Some(8))]
    #[case("00", Some(0))]
    #[case("-5", Some(-5))]
    #[case("+5", Some(5))]
    #[case("0x-1", Some(-1))]
    #[case("0xffffffff", Some(-1))]
    #[case("4294967297", Some(1))]
    #[case("", None)]
    #[case("08", None)]
    #[case("0X10", None)]
    #[case(" 5", None)]
    #[case("5 ", None)]
    #[case("-", None)]
    #[case("0x", None)]
    #[case("1.5", None)]
    #[case("--5", None)]
    fn decodes_int_like_spec_xml_utils(#[case] text: &str, #[case] expected: Option<i32>) {
        assert_eq!(decode_i32(text), expected);
    }

    #[rstest]
    #[case("0xffffffffffffffff", Some(u64::MAX))]
    #[case("0x10000000000000001", Some(1))]
    #[case("-1", Some(u64::MAX))]
    #[case("18446744073709551615", Some(u64::MAX))]
    #[case("0777", Some(0o777))]
    fn decodes_long_wrapping_to_64_bits(#[case] text: &str, #[case] expected: Option<u64>) {
        assert_eq!(decode_u64(text), expected);
    }

    #[rstest]
    #[case("true", Some(true))]
    #[case("yes", Some(true))]
    #[case("1", Some(true))]
    #[case("y", Some(true))]
    #[case("false", Some(false))]
    #[case("no", Some(false))]
    #[case("0", Some(false))]
    #[case("nope", Some(false))]
    #[case("", None)]
    #[case("True", None)]
    #[case("maybe", None)]
    fn decodes_bool_by_first_character(#[case] text: &str, #[case] expected: Option<bool>) {
        assert_eq!(decode_bool(text), expected);
    }

    #[test]
    fn schema_booleans_are_exactly_six() {
        for ok in ["true", "false", "yes", "no", "1", "0"] {
            assert!(is_schema_boolean(ok));
        }
        for bad in ["True", "y", "n", "", "2"] {
            assert!(!is_schema_boolean(bad));
        }
    }

    #[rstest]
    #[case("", ',', &[""])]
    #[case(",", ',', &[])]
    #[case("8,10", ',', &["8", "10"])]
    #[case("8,,10", ',', &["8", "", "10"])]
    #[case(",8", ',', &["", "8"])]
    #[case("8,", ',', &["8"])]
    #[case("8,,", ',', &["8"])]
    fn splits_like_java(#[case] text: &str, #[case] separator: char, #[case] expected: &[&str]) {
        assert_eq!(java_split(text, separator).collect::<Vec<_>>(), expected);
    }
}
