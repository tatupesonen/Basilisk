//! Reading and writing the oracle's line formats: one record per line,
//! fields separated by one tab, a header naming the format and its version,
//! and a final `T` record. Every number has exactly one spelling (decimal
//! without leading zeros or sign, `0x` and lower-case hexadecimal without
//! leading zeros), so writing a parsed file gives back the same bytes.

use std::fmt;

/// Why an oracle file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{format} line {line}: {kind}")]
pub struct ParseError {
    /// The format being read (`bkgraph`, `bkstruct`, …).
    pub format: &'static str,
    /// The 1-based line, or 0 for a property of the whole file.
    pub line: usize,
    /// What was wrong.
    pub kind: ParseErrorKind,
}

/// The ways an oracle file can be malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The input is larger than the reader accepts.
    #[error("input of {size} bytes is larger than the limit of {limit}")]
    TooLarge {
        /// Bytes given.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The input does not end with a line break, so it is truncated.
    #[error("the last line has no line break (truncated?)")]
    Truncated,
    /// The input ended where a record was expected.
    #[error("input ends where {expected} was expected")]
    UnexpectedEnd {
        /// What was expected.
        expected: &'static str,
    },
    /// A record of the wrong kind.
    #[error("expected {expected}, found `{found}`")]
    UnexpectedRecord {
        /// What was expected.
        expected: &'static str,
        /// The start of the line found.
        found: String,
    },
    /// A record with the wrong number of fields.
    #[error("{record} record has {found} fields, expected {expected}")]
    FieldCount {
        /// The record's tag.
        record: &'static str,
        /// Fields expected, tag included.
        expected: usize,
        /// Fields found.
        found: usize,
    },
    /// A field that is not in its one accepted spelling.
    #[error("bad {field}: `{value}`")]
    BadField {
        /// Which field.
        field: &'static str,
        /// The start of its text.
        value: String,
    },
    /// A header naming another version of the format.
    #[error("unsupported version `{version}`")]
    UnsupportedVersion {
        /// The version found.
        version: String,
    },
    /// Records that contradict each other.
    #[error("{reason}")]
    Inconsistent {
        /// What contradicts what.
        reason: String,
    },
    /// Text after the final `T` record.
    #[error("text after the final T record")]
    TrailingText,
    /// More items than the reader accepts.
    #[error("more than {limit} {what}")]
    TooMany {
        /// What there are too many of.
        what: &'static str,
        /// The limit.
        limit: usize,
    },
}

/// The largest oracle file any reader accepts, in bytes.
pub const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;

/// The most characters of offending text an error repeats.
const SHOWN: usize = 60;

/// The start of `text`, for messages.
pub(crate) fn shown(text: &str) -> String {
    text.chars().take(SHOWN).collect()
}

/// The lines of one file, read front to back.
#[derive(Debug)]
pub(crate) struct Lines<'a> {
    format: &'static str,
    all: Vec<&'a str>,
    next: usize,
}

impl<'a> Lines<'a> {
    /// Split `text` into lines. The text must end with a line break.
    pub(crate) fn new(format: &'static str, text: &'a str) -> Result<Self, ParseError> {
        if text.len() > MAX_FILE_BYTES {
            return Err(ParseError {
                format,
                line: 0,
                kind: ParseErrorKind::TooLarge {
                    size: text.len(),
                    limit: MAX_FILE_BYTES,
                },
            });
        }
        let Some(body) = text.strip_suffix('\n') else {
            let line = text.split('\n').count();
            return Err(ParseError {
                format,
                line,
                kind: if text.is_empty() {
                    ParseErrorKind::UnexpectedEnd {
                        expected: "a header",
                    }
                } else {
                    ParseErrorKind::Truncated
                },
            });
        };
        Ok(Self {
            format,
            all: body.split('\n').collect(),
            next: 0,
        })
    }

    /// An error at line `line` (1-based).
    pub(crate) fn error_at(&self, line: usize, kind: ParseErrorKind) -> ParseError {
        ParseError {
            format: self.format,
            line,
            kind,
        }
    }

    /// The next line, or an error naming what was expected.
    pub(crate) fn next_line(&mut self, expected: &'static str) -> Result<Record<'a>, ParseError> {
        let Some(&line) = self.all.get(self.next) else {
            return Err(self.error_at(self.next + 1, ParseErrorKind::UnexpectedEnd { expected }));
        };
        self.next += 1;
        Ok(Record {
            format: self.format,
            number: self.next,
            text: line,
            fields: line.split('\t').collect(),
        })
    }

    /// The tag of the next line without consuming it.
    pub(crate) fn peek_tag(&self) -> Option<&'a str> {
        self.all
            .get(self.next)
            .map(|line| line.split('\t').next().unwrap_or(""))
    }

    /// Require the final `T` record and nothing after it.
    pub(crate) fn finish(mut self) -> Result<(), ParseError> {
        let record = self.next_line("the final T record")?;
        record.expect("T", 1, "the final T record")?;
        if self.next < self.all.len() {
            return Err(self.error_at(self.next + 1, ParseErrorKind::TrailingText));
        }
        Ok(())
    }
}

/// One line split into its fields.
#[derive(Debug, Clone)]
pub(crate) struct Record<'a> {
    format: &'static str,
    /// The 1-based line number.
    pub(crate) number: usize,
    /// The whole line.
    pub(crate) text: &'a str,
    /// Its tab-separated fields; the first is the tag.
    pub(crate) fields: Vec<&'a str>,
}

impl<'a> Record<'a> {
    /// The record's tag (its first field).
    pub(crate) fn tag(&self) -> &'a str {
        self.fields.first().copied().unwrap_or("")
    }

    /// An error on this line.
    pub(crate) fn error(&self, kind: ParseErrorKind) -> ParseError {
        ParseError {
            format: self.format,
            line: self.number,
            kind,
        }
    }

    /// Require tag `tag` and exactly `count` fields (the tag included).
    pub(crate) fn expect(
        &self,
        tag: &'static str,
        count: usize,
        what: &'static str,
    ) -> Result<(), ParseError> {
        if self.tag() != tag {
            return Err(self.error(ParseErrorKind::UnexpectedRecord {
                expected: what,
                found: shown(self.text),
            }));
        }
        if self.fields.len() != count {
            return Err(self.error(ParseErrorKind::FieldCount {
                record: tag,
                expected: count,
                found: self.fields.len(),
            }));
        }
        Ok(())
    }

    /// Field `i` (0 is the tag); callers check the count first.
    pub(crate) fn field(&self, i: usize) -> &'a str {
        self.fields.get(i).copied().unwrap_or("")
    }

    /// A bad-field error for field `i`.
    pub(crate) fn bad(&self, field: &'static str, value: &str) -> ParseError {
        self.error(ParseErrorKind::BadField {
            field,
            value: shown(value),
        })
    }

    /// Field `i` as a decimal `u32`.
    pub(crate) fn u32_at(&self, i: usize, name: &'static str) -> Result<u32, ParseError> {
        let text = self.field(i);
        parse_u32(text).ok_or_else(|| self.bad(name, text))
    }

    /// Field `i` as a decimal `i32`.
    pub(crate) fn i32_at(&self, i: usize, name: &'static str) -> Result<i32, ParseError> {
        let text = self.field(i);
        parse_i32(text).ok_or_else(|| self.bad(name, text))
    }

    /// Field `i` as `0x…` hexadecimal `u32`.
    pub(crate) fn hex32_at(&self, i: usize, name: &'static str) -> Result<u32, ParseError> {
        let text = self.field(i);
        parse_hex_u64(text)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| self.bad(name, text))
    }
}

/// A decimal `u32` in its one spelling.
pub(crate) fn parse_u32(text: &str) -> Option<u32> {
    canonical_digits(text).then(|| text.parse().ok()).flatten()
}

/// A decimal `i32` in its one spelling (`-` before a non-zero magnitude).
pub(crate) fn parse_i32(text: &str) -> Option<i32> {
    match text.strip_prefix('-') {
        Some(rest) if rest != "0" && canonical_digits(rest) => text.parse().ok(),
        Some(_) => None,
        None => canonical_digits(text).then(|| text.parse().ok()).flatten(),
    }
}

/// Digits only, no leading zero unless the number is 0.
fn canonical_digits(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 20
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

/// `0x` and lower-case hexadecimal digits without leading zeros.
pub(crate) fn parse_hex_u64(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x")?;
    let ok = !digits.is_empty()
        && digits.len() <= 16
        && digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && (digits == "0" || !digits.starts_with('0'));
    if !ok {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// The comma-separated items of a list field; `-` is the empty list.
pub(crate) fn list_items(field: &str) -> Option<Vec<&str>> {
    if field == "-" {
        return Some(Vec::new());
    }
    let items: Vec<&str> = field.split(',').collect();
    items.iter().all(|item| !item.is_empty()).then_some(items)
}

/// Write `items` as a list field (`-` when empty).
pub(crate) fn write_list<T: fmt::Display>(out: &mut String, items: &[T]) {
    if items.is_empty() {
        out.push('-');
        return;
    }
    for (i, item) in items.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        push_display(out, item);
    }
}

/// Append a value's text.
pub(crate) fn push_display<T: fmt::Display + ?Sized>(out: &mut String, value: &T) {
    use fmt::Write as _;
    // Writing to a String cannot fail.
    let _ = write!(out, "{value}");
}

/// A value as `0x…` lower-case hexadecimal.
pub(crate) fn hex(value: u64) -> String {
    format!("{value:#x}")
}

/// Undo the extension's escaping of a text field (`\\`, `\t`, `\n`, `\r`, `\0`).
pub(crate) fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            '\\' => '\\',
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            '0' => '\0',
            _ => return None,
        });
    }
    Some(out)
}

/// Escape a text field as the extension does.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            _ => out.push(c),
        }
    }
    out
}

/// The outcome of a command, as the `H` record of `bkcfg` and `bkstruct` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    /// `ok\t-`
    Ok,
    /// `error\t<message>`
    Error(String),
}

/// Read the `H\t<format>\t1\tok|error\t<message>` header.
pub(crate) fn read_status_header(
    lines: &mut Lines<'_>,
    format: &'static str,
) -> Result<Status, ParseError> {
    let record = lines.next_line("a header")?;
    if record.tag() != "H" || record.field(1) != format {
        return Err(record.error(ParseErrorKind::UnexpectedRecord {
            expected: "the header",
            found: shown(record.text),
        }));
    }
    record.expect("H", 5, "the header")?;
    if record.field(2) != "1" {
        return Err(record.error(ParseErrorKind::UnsupportedVersion {
            version: shown(record.field(2)),
        }));
    }
    match (record.field(3), record.field(4)) {
        ("ok", "-") => Ok(Status::Ok),
        ("error", message) => unescape(message)
            .filter(|m| !m.is_empty() && m != "-")
            .map(Status::Error)
            .ok_or_else(|| record.bad("error message", message)),
        (status, _) => Err(record.bad("status", status)),
    }
}

/// Write the `H` record of a status format.
pub(crate) fn write_status_header(out: &mut String, format: &str, status: &Status) {
    out.push_str("H\t");
    out.push_str(format);
    out.push_str("\t1\t");
    match status {
        Status::Ok => out.push_str("ok\t-"),
        Status::Error(message) => {
            out.push_str("error\t");
            out.push_str(&escape(message));
        }
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_have_one_spelling() {
        assert_eq!(parse_u32("0"), Some(0));
        assert_eq!(parse_u32("17"), Some(17));
        for bad in ["", "01", "+1", "-1", " 1", "1a", "4294967296"] {
            assert_eq!(parse_u32(bad), None, "{bad:?}");
        }
        assert_eq!(parse_i32("-1"), Some(-1));
        assert_eq!(parse_i32("-0"), None);
        assert_eq!(parse_i32("-01"), None);
        assert_eq!(parse_hex_u64("0x0"), Some(0));
        assert_eq!(parse_hex_u64("0x1f"), Some(31));
        for bad in ["0x", "0x01", "0X1", "0x1F", "1f", "0x10000000000000000"] {
            assert_eq!(parse_hex_u64(bad), None, "{bad:?}");
        }
        assert_eq!(hex(31), "0x1f");
        assert_eq!(hex(0), "0x0");
    }

    #[test]
    fn escaping_round_trips() {
        let text = "a\\b\tc\nd\re\0f";
        assert_eq!(unescape(&escape(text)).as_deref(), Some(text));
        assert_eq!(unescape("bad\\q"), None);
        assert_eq!(unescape("bad\\"), None);
    }

    #[test]
    fn lists() {
        assert_eq!(list_items("-"), Some(vec![]));
        assert_eq!(list_items("a,b"), Some(vec!["a", "b"]));
        assert_eq!(list_items("a,,b"), None);
        assert_eq!(list_items(""), None);
        let mut s = String::new();
        write_list::<u32>(&mut s, &[]);
        write_list(&mut s, &[1, 2]);
        assert_eq!(s, "-1,2");
    }

    #[test]
    fn truncated_input_is_reported() {
        let error = Lines::new("bkgraph", "H\tbkgraph").unwrap_err();
        assert_eq!(error.kind, ParseErrorKind::Truncated);
        let error = Lines::new("bkgraph", "").unwrap_err();
        assert!(matches!(error.kind, ParseErrorKind::UnexpectedEnd { .. }));
    }
}
