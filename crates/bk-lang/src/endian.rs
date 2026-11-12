//! Byte order (Ghidra: `ghidra.program.model.lang.Endian`).

use std::{fmt, str::FromStr};

/// The byte order of a language's data or instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Endian {
    /// Most significant byte first.
    Big,
    /// Least significant byte first.
    Little,
}

impl Endian {
    /// The name spec files use: `big` or `little`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Big => "big",
            Self::Little => "little",
        }
    }

    /// The short name used in language ids: `BE` or `LE`.
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Big => "BE",
            Self::Little => "LE",
        }
    }

    /// The name shown to users: `Big` or `Little`.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Big => "Big",
            Self::Little => "Little",
        }
    }

    /// Whether this is big endian.
    #[must_use]
    pub const fn is_big(self) -> bool {
        matches!(self, Self::Big)
    }

    /// Parses any form Ghidra's `Endian.toEndian` accepts: the long or the
    /// short name, in any letter case.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Big, Self::Little].into_iter().find(|e| {
            text.eq_ignore_ascii_case(e.name()) || text.eq_ignore_ascii_case(e.short_name())
        })
    }

    /// Parses the long name only, in any letter case, as Ghidra's `.ldefs`
    /// reader does (`Endian.valueOf(text.toUpperCase())`).
    #[must_use]
    pub fn parse_long_name(text: &str) -> Option<Self> {
        [Self::Big, Self::Little]
            .into_iter()
            .find(|e| text.eq_ignore_ascii_case(e.name()))
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The text is not a byte-order name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no such endian: {0}")]
pub struct ParseEndianError(pub String);

impl FromStr for Endian {
    type Err = ParseEndianError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| ParseEndianError(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("big", Some(Endian::Big))]
    #[case("BIG", Some(Endian::Big))]
    #[case("be", Some(Endian::Big))]
    #[case("BE", Some(Endian::Big))]
    #[case("little", Some(Endian::Little))]
    #[case("Little", Some(Endian::Little))]
    #[case("LE", Some(Endian::Little))]
    #[case("le", Some(Endian::Little))]
    #[case("", None)]
    #[case("middle", None)]
    #[case(" big", None)]
    fn parses_the_forms_ghidra_accepts(#[case] text: &str, #[case] expected: Option<Endian>) {
        assert_eq!(Endian::parse(text), expected);
        assert_eq!(text.parse::<Endian>().ok(), expected);
    }

    #[test]
    fn long_name_parse_rejects_short_names() {
        assert_eq!(Endian::parse_long_name("BIG"), Some(Endian::Big));
        assert_eq!(Endian::parse_long_name("little"), Some(Endian::Little));
        assert_eq!(Endian::parse_long_name("LE"), None);
    }

    #[test]
    fn names() {
        assert_eq!(Endian::Big.to_string(), "big");
        assert_eq!(Endian::Little.to_string(), "little");
        assert_eq!(Endian::Big.short_name(), "BE");
        assert_eq!(Endian::Little.short_name(), "LE");
        assert_eq!(Endian::Big.display_name(), "Big");
        assert_eq!(Endian::Little.display_name(), "Little");
        assert!(Endian::Big.is_big());
        assert!(!Endian::Little.is_big());
        assert_eq!(
            "x".parse::<Endian>().unwrap_err().to_string(),
            "no such endian: x"
        );
    }
}
