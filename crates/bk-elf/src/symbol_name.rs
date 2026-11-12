//! Ghidra's handling of ELF symbol names: escaping characters a symbol name
//! may not contain, version suffixes, and compiler-generated `.cold` parts.

use std::borrow::Cow;

use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

/// Code points that are in an allowed Unicode category but are invisible or
/// otherwise unwanted in a symbol name (Ghidra's `EXTRA_INVALID_CODEPOINTS`).
const EXTRA_INVALID: [char; 6] = [
    '\u{2800}', // braille blank
    '\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}', // hangul fillers
    '\u{fffc}', // object replacement character
];

/// True when `c` may not appear in a symbol name (Ghidra's
/// `SymbolUtilities.isInvalidCodePoint`): invisible, unprintable and
/// whitespace characters, by Unicode general category.
///
/// The categories come from the `unicode-properties` crate; Ghidra asks the
/// Java runtime, so a code point assigned in a Unicode version newer than
/// one side's tables can be classified differently.
pub fn is_invalid_symbol_char(c: char) -> bool {
    matches!(
        c.general_category(),
        GeneralCategory::SpaceSeparator
            | GeneralCategory::SpacingMark
            | GeneralCategory::Control
            | GeneralCategory::EnclosingMark
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::NonspacingMark
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Surrogate
            | GeneralCategory::Unassigned
    ) || EXTRA_INVALID.contains(&c)
}

/// Makes a symbol name acceptable (Ghidra's
/// `ElfSymbolNameUtils.replaceInvalidChars`), in the style of `readelf`:
/// a control character becomes `^` and the letter 64 above it (`^@` to
/// `^_`), DEL becomes `^?`, a space becomes `_`, and any other character
/// that is not allowed is dropped. A name without such characters is
/// returned borrowed.
pub fn replace_invalid_chars(name: &str) -> Cow<'_, str> {
    let Some(first_bad) = name.find(is_invalid_symbol_char) else {
        return Cow::Borrowed(name);
    };
    let (clean, rest) = name.split_at(first_bad);
    let mut out = String::with_capacity(name.len() + 4);
    out.push_str(clean);
    for c in rest.chars() {
        if !is_invalid_symbol_char(c) {
            out.push(c);
        } else if c < ' ' {
            out.push('^');
            out.push(char::from(b'@' + c as u8));
        } else if c == '\u{7f}' {
            out.push_str("^?");
        } else if c == ' ' {
            out.push('_');
        }
    }
    Cow::Owned(out)
}

/// True when `name` is that of a function part the compiler split off as
/// unlikely to run: it ends in `.cold` or `.cold.<digits>` and has something
/// before that (Ghidra's `ElfSymbol.isColdSymbolName`, the pattern
/// `.+\.cold((\.[0-9]+)?)`).
pub fn is_cold_symbol_name(name: &str) -> bool {
    let stem = match name.rsplit_once('.') {
        // An empty digit run does not match `\.[0-9]+`; "x.cold." is not cold.
        Some((head, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            head
        }
        _ => name,
    };
    stem.strip_suffix(".cold")
        .is_some_and(|before| !before.is_empty())
}

/// A symbol name split at its version suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionedName<'a> {
    /// The name before the first `@`.
    pub name: &'a str,
    /// The version after `@` or `@@`.
    pub version: &'a str,
    /// True when the separator is `@@`: this is the default version of the
    /// symbol.
    pub is_default: bool,
}

/// Splits `<sym>@<version>` or `<sym>@@<version>` at the first `@`; `None`
/// when the name has no `@`.
///
/// Ghidra's loader treats any symbol name containing `@` as versioned
/// (`ElfProgramBuilder.processVersionedExternal`, and "do not make versioned
/// symbols primary"); this is that test, with the parts.
pub fn split_version(name: &str) -> Option<VersionedName<'_>> {
    let (base, rest) = name.split_once('@')?;
    let (version, is_default) = match rest.strip_prefix('@') {
        Some(version) => (version, true),
        None => (rest, false),
    };
    Some(VersionedName {
        name: base,
        version,
        is_default,
    })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("main", "main")]
    #[case("_ZN3fooC1Ev", "_ZN3fooC1Ev")]
    #[case("a b", "a_b")]
    #[case("tab\there", "tab^Ihere")]
    #[case("nul\0", "nul^@")]
    #[case("\u{1f}x", "^_x")]
    #[case("del\u{7f}", "del^?")]
    #[case("nb\u{a0}sp", "nbsp")] // no-break space: a space separator that is not ' '
    #[case("zero\u{200b}width", "zerowidth")] // format character
    #[case("e\u{301}", "e")] // combining mark
    #[case("x\u{e000}y", "xy")] // private use
    #[case("braille\u{2800}", "braille")]
    #[case("ünïcödé_ok$.@", "ünïcödé_ok$.@")]
    #[case("", "")]
    fn replaces_invalid_characters(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(replace_invalid_chars(input), expected);
    }

    #[test]
    fn valid_names_are_borrowed() {
        assert!(matches!(
            replace_invalid_chars("memcpy@@GLIBC_2.14"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(replace_invalid_chars("a b"), Cow::Owned(_)));
    }

    #[test]
    fn invalid_character_classes() {
        for c in [
            ' ', '\t', '\n', '\0', '\u{7f}', '\u{85}', '\u{a0}', '\u{2028}', '\u{2029}',
            '\u{feff}', '\u{fffc}', '\u{3164}',
        ] {
            assert!(is_invalid_symbol_char(c), "{c:?}");
        }
        for c in [
            'a', 'Z', '0', '_', '$', '.', '@', '-', '(', 'é', '漢', '€', '+', '«',
        ] {
            assert!(!is_invalid_symbol_char(c), "{c:?}");
        }
    }

    #[rstest]
    #[case("foo.cold", true)]
    #[case("foo.cold.0", true)]
    #[case("foo.cold.123", true)]
    #[case("a.b.cold", true)]
    #[case(".cold", false)] // nothing before it
    #[case("cold", false)]
    #[case("foo.cold.", false)]
    #[case("foo.cold.1a", false)]
    #[case("foo.cold.1.2", false)]
    #[case("foo.coldx", false)]
    #[case("foo.constprop.0", false)]
    #[case("x.cold.cold", true)]
    #[case("", false)]
    fn cold_names(#[case] name: &str, #[case] expected: bool) {
        assert_eq!(is_cold_symbol_name(name), expected, "{name}");
    }

    #[test]
    fn version_suffixes() {
        assert_eq!(
            split_version("memcpy@GLIBC_2.2.5"),
            Some(VersionedName {
                name: "memcpy",
                version: "GLIBC_2.2.5",
                is_default: false
            })
        );
        assert_eq!(
            split_version("memcpy@@GLIBC_2.14"),
            Some(VersionedName {
                name: "memcpy",
                version: "GLIBC_2.14",
                is_default: true
            })
        );
        assert_eq!(split_version("plain"), None);
        assert_eq!(
            split_version("@v"),
            Some(VersionedName {
                name: "",
                version: "v",
                is_default: false
            })
        );
        assert_eq!(
            split_version("a@"),
            Some(VersionedName {
                name: "a",
                version: "",
                is_default: false
            })
        );
    }
}
