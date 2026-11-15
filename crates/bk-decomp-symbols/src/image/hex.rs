//! Ghidra's hex-content loops (loadimage_xml.cc:111–135, the same code in
//! stringmanage.cc:242–266; spec 4.15, ADR-045).
//!
//! Ghidra skips white space, takes two characters, and continues while both
//! are positive as signed `char`s — so it stops at the end of the text, at a
//! NUL and at any byte of 0x80 or more — mapping each with `c <= '9' → c -
//! '0'`, `c <= 'F' → c + 10 - 'A'`, else `c + 10 - 'a'` and storing
//! `(c1 * 16 + c2) & 0xff`, without validation. With unsigned `char` the end
//! of text reads as 255 and the loop never ends; Basilisk computes the
//! signed-`char` result for every input and always stops. An odd final
//! character is dropped.

use std::fmt::Write as _;

/// C's `isspace` in the C locale.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn digit(c: u8) -> u8 {
    if c <= b'9' {
        c.wrapping_sub(b'0')
    } else if c <= b'F' {
        c.wrapping_add(10).wrapping_sub(b'A')
    } else {
        c.wrapping_add(10).wrapping_sub(b'a')
    }
}

/// Appends the bytes Ghidra reads from hex content to `out`.
pub fn hex_bytes_into(text: &str, out: &mut Vec<u8>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    let positive = |c: Option<&u8>| c.copied().filter(|&b| (1..0x80).contains(&b));
    loop {
        while bytes.get(i).is_some_and(|&b| is_space(b)) {
            i += 1;
        }
        let (Some(c1), Some(c2)) = (positive(bytes.get(i)), positive(bytes.get(i + 1))) else {
            break;
        };
        i += 2;
        out.push(digit(c1).wrapping_mul(16).wrapping_add(digit(c2)));
    }
}

/// The bytes Ghidra reads from hex content.
pub fn hex_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    hex_bytes_into(text, &mut out);
    out
}

/// Ghidra's hex content as written: a newline, two lower-case digits per
/// byte, a newline (followed by `indent`) after every 20th byte, and a
/// final newline.
pub fn write_hex_lines(bytes: &[u8], indent: &str) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + bytes.len() / 10 + 2);
    s.push('\n');
    for (i, b) in bytes.iter().enumerate() {
        let _ = write!(s, "{b:02x}");
        if i % 20 == 19 {
            s.push('\n');
            s.push_str(indent);
        }
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_signed_char_rule() {
        let cases: &[(&str, &[u8])] = &[
            ("", &[]),
            ("  \n", &[]),
            ("0a1B", &[0x0a, 0x1b]),
            (" 0a \n 1b ", &[0x0a, 0x1b]),
            // White space inside a pair is a digit: ' ' - '0' wraps to 0xf0;
            // then "a" alone is dropped.
            ("0 a", &[0xf0]),
            // Letters past 'f': 'z' + 10 - 'a' = 0x23; 0x23 * 16 + 0x23 = 0x253.
            ("zz", &[0x53]),
            ("0a\u{0}1b", &[0x0a]),
            ("0a\u{80}1b", &[0x0a]),
            ("0a1", &[0x0a]),
            ("FF", &[0xff]),
        ];
        for (text, want) in cases {
            assert_eq!(hex_bytes(text), *want, "{text:?}");
        }
        assert_eq!(write_hex_lines(&[1, 2], "  "), "\n0102\n");
        let twenty: Vec<u8> = (0..21).collect();
        let text = write_hex_lines(&twenty, "  ");
        assert!(text.contains("13\n  14\n"), "{text:?}");
        assert_eq!(hex_bytes(&text), twenty);
    }
}
