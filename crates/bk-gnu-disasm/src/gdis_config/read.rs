//! Reading `.gdis` files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use roxmltree::{Document, Node};

use super::{ContextOption, ContextOptions, GdisConfig};

/// An error reading a `.gdis` file, or applying one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The file is not well-formed XML (or has a DTD, which is refused as
    /// Ghidra's secure parser refuses it).
    #[error("not a .gdis file: {0}")]
    Xml(#[from] roxmltree::Error),
    /// Neither `<global>` nor `<context_register>` is present.
    #[error("no <context_register> or <global> element in the .gdis file")]
    Empty,
    /// `<context_register>` names no register.
    #[error("<context_register> names no register")]
    EmptyContextRegister,
    /// `<context_register>` is present but `<options>` is not.
    #[error("<context_register> without <options>")]
    MissingOptions,
    /// An `<option>` without a `value` attribute.
    #[error("<option> at line {line} has no value attribute")]
    MissingValue {
        /// Line in the file.
        line: u32,
    },
    /// A `value` that `Long.decode` would reject.
    #[error("<option> at line {line}: {text:?} is not a number")]
    BadValue {
        /// Line in the file.
        line: u32,
        /// The attribute's text.
        text: String,
    },
    /// The register-value lookup does not know the context register.
    #[error("the language has no context register {register:?}")]
    UnknownContextRegister {
        /// The register named in the file.
        register: String,
    },
}

/// Reads a `.gdis` file.
pub fn read_file(path: &Path) -> Result<GdisConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    parse(&text)
}

/// Parses the text of a `.gdis` file. The root element's name is not
/// checked, as Ghidra does not check it.
pub fn parse(text: &str) -> Result<GdisConfig, ConfigError> {
    let doc = Document::parse(text)?;
    let root = doc.root_element();
    let global_element = child(root, "global");
    let global = global_element
        .and_then(|g| g.attribute("optstring"))
        .map(str::to_owned);
    let Some(context_register) = child(root, "context_register") else {
        return if global_element.is_some() {
            Ok(GdisConfig {
                global,
                context: None,
            })
        } else {
            Err(ConfigError::Empty)
        };
    };
    // Ghidra takes the value of the element's first content node; the name
    // is trimmed here, which Ghidra's register lookup would need anyway.
    let register = context_register
        .first_child()
        .and_then(|n| n.text())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or(ConfigError::EmptyContextRegister)?
        .to_owned();
    let options_element = child(root, "options").ok_or(ConfigError::MissingOptions)?;
    let mut options = BTreeMap::new();
    for option in options_element
        .children()
        .filter(|n| n.has_tag_name("option"))
    {
        let line = doc.text_pos_at(option.range().start).row;
        let text = option
            .attribute("value")
            .ok_or(ConfigError::MissingValue { line })?;
        let value = decode_long(text).ok_or_else(|| ConfigError::BadValue {
            line,
            text: text.to_owned(),
        })?;
        // As with Java's HashMap, a repeated value replaces the earlier one.
        options.insert(
            value,
            ContextOption {
                optstring: option.attribute("optstring").map(str::to_owned),
                display_prefix: option.attribute("display_prefix").map(str::to_owned),
            },
        );
    }
    Ok(GdisConfig {
        global,
        context: Some(ContextOptions { register, options }),
    })
}

/// The first child element of that name (JDOM's `getChild`).
fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|n| n.has_tag_name(name))
}

/// Java's `Long.decode`: an optional sign, then `0x`, `0X` or `#` for
/// hexadecimal, a leading `0` for octal, or decimal; the result must fit a
/// signed 64-bit integer.
pub(crate) fn decode_long(text: &str) -> Option<i64> {
    let (negative, rest) = match text.as_bytes().first()? {
        b'-' => (true, text.get(1..)?),
        b'+' => (false, text.get(1..)?),
        _ => (false, text),
    };
    let (radix, digits) =
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, hex)
        } else if let Some(hex) = rest.strip_prefix('#') {
            (16, hex)
        } else if rest.len() > 1
            && let Some(octal) = rest.strip_prefix('0')
        {
            (8, octal)
        } else {
            (10, rest)
        };
    // Long.decode rejects a second sign after the prefix, which
    // from_str_radix would accept.
    if digits.is_empty() || digits.starts_with(['-', '+']) {
        return None;
    }
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    if negative {
        0i64.checked_sub_unsigned(magnitude)
    } else {
        i64::try_from(magnitude).ok()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("0", Some(0))]
    #[case("0x0", Some(0))]
    #[case("0x1", Some(1))]
    #[case("0X1f", Some(31))]
    #[case("#ff", Some(255))]
    #[case("010", Some(8))]
    #[case("-0x10", Some(-16))]
    #[case("+12", Some(12))]
    #[case("9223372036854775807", Some(i64::MAX))]
    #[case("-0x8000000000000000", Some(i64::MIN))]
    #[case("0x8000000000000000", None)]
    #[case("", None)]
    #[case("-", None)]
    #[case("0x", None)]
    #[case("0x-1", None)]
    #[case("08", None)]
    #[case("1.0", None)]
    #[case(" 1", None)]
    fn values_decode_like_java_long_decode(#[case] text: &str, #[case] expected: Option<i64>) {
        assert_eq!(decode_long(text), expected);
    }
}
