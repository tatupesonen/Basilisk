//! Reading a `<decompilertest>` file into a [`DataTest`].
//!
//! The rules follow Ghidra's reader (`FunctionTestCollection::restoreXml`,
//! `FunctionTestProperty::restoreXml`, `LoadImageXml::open`) with one
//! difference: where Ghidra computes garbage from malformed input (a
//! non-hexadecimal digit in a byte chunk, a count that is not a number),
//! this parser returns an error naming the place.

use std::path::{Path, PathBuf};

use roxmltree::{Document, Node};

use super::model::{BinaryImage, ByteChunk, DataTest, ImageSymbol, StringMatch};

/// Why a data-test file could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DataTestError {
    /// The file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The text is not well-formed XML.
    #[error("not well-formed XML: {0}")]
    Xml(#[from] roxmltree::Error),
    /// The root element is neither `<decompilertest>` nor the old form.
    #[error("root element is <{found}>, expected <decompilertest>")]
    UnexpectedRoot {
        /// The root element's name.
        found: String,
    },
    /// The root element is `<binaryimage>`: the old test form, with script
    /// and checks in a comment, which Ghidra no longer runs either.
    #[error("old-format test (root element <binaryimage>) is not supported")]
    OldFormat,
    /// An element that does not belong where it is.
    #[error("line {line}: unknown element <{name}> in <{parent}>")]
    UnknownElement {
        /// Line of the element's start tag.
        line: u32,
        /// The enclosing element.
        parent: &'static str,
        /// The element's name.
        name: String,
    },
    /// A required attribute is absent.
    #[error("line {line}: <{element}> has no `{attribute}` attribute")]
    MissingAttribute {
        /// Line of the element's start tag.
        line: u32,
        /// The element.
        element: &'static str,
        /// The attribute it lacks.
        attribute: &'static str,
    },
    /// An attribute that should be a number is not one.
    #[error("line {line}: <{element}> attribute `{attribute}` is not a number: {value:?}")]
    BadNumber {
        /// Line of the element's start tag.
        line: u32,
        /// The element.
        element: &'static str,
        /// The attribute.
        attribute: &'static str,
        /// Its value.
        value: String,
        /// Why it does not parse.
        source: std::num::ParseIntError,
    },
    /// The content of a `<bytechunk>` is not pairs of hexadecimal digits.
    #[error("line {line}: <bytechunk> content is not hexadecimal byte pairs (at {found:?})")]
    BadBytes {
        /// Line of the element's start tag.
        line: u32,
        /// The offending text, shortened.
        found: String,
    },
    /// A second `<binaryimage>` in one test.
    #[error("line {line}: more than one <binaryimage>")]
    DuplicateImage {
        /// Line of the second image's start tag.
        line: u32,
    },
    /// The test has no `<script>`.
    #[error("no <script> element")]
    MissingScript,
    /// The test has no `<stringmatch>`.
    #[error("no <stringmatch> element")]
    MissingStringMatch,
    /// The test has no `<binaryimage>`.
    #[error("no <binaryimage> element")]
    MissingImage,
}

/// Read and parse one data-test file.
pub fn read_data_test(path: &Path) -> Result<DataTest, DataTestError> {
    let text = std::fs::read_to_string(path).map_err(|source| DataTestError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse_data_test(&text)
}

/// Parse the text of a `<decompilertest>` document.
pub fn parse_data_test(xml: &str) -> Result<DataTest, DataTestError> {
    let document = Document::parse(xml)?;
    let root = document.root_element();
    match root.tag_name().name() {
        "decompilertest" => {}
        "binaryimage" => return Err(DataTestError::OldFormat),
        other => {
            return Err(DataTestError::UnexpectedRoot {
                found: other.to_owned(),
            });
        }
    }

    let mut image = None;
    let mut script = Vec::new();
    let mut saw_script = false;
    let mut matches = Vec::new();
    for child in root.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "script" => {
                saw_script = true;
                script.extend(child.children().filter(Node::is_element).map(command));
            }
            "stringmatch" => matches.push(string_match(child)?),
            "binaryimage" => {
                if image.is_some() {
                    return Err(DataTestError::DuplicateImage {
                        line: line_of(child),
                    });
                }
                image = Some(binary_image(child)?);
            }
            other => {
                return Err(DataTestError::UnknownElement {
                    line: line_of(child),
                    parent: "decompilertest",
                    name: other.to_owned(),
                });
            }
        }
    }

    if !saw_script {
        return Err(DataTestError::MissingScript);
    }
    if matches.is_empty() {
        return Err(DataTestError::MissingStringMatch);
    }
    let image = image.ok_or(DataTestError::MissingImage)?;
    Ok(DataTest {
        image,
        script,
        matches,
    })
}

/// The line an element starts on, for error messages.
fn line_of(node: Node<'_, '_>) -> u32 {
    node.document().text_pos_at(node.range().start).row
}

/// The character data directly inside an element, which is what Ghidra's
/// `Element::getContent` holds. Character data of nested elements is not
/// included.
fn content(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|text| text.text())
        .collect()
}

/// One script command: the element's content with carriage returns removed
/// and line breaks turned into spaces (`stripNewlines`).
fn command(node: Node<'_, '_>) -> String {
    content(node)
        .chars()
        .filter(|&c| c != '\r')
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect()
}

fn attribute<'a>(
    node: Node<'a, '_>,
    element: &'static str,
    name: &'static str,
) -> Result<&'a str, DataTestError> {
    node.attribute(name)
        .ok_or_else(|| DataTestError::MissingAttribute {
            line: line_of(node),
            element,
            attribute: name,
        })
}

/// An unsigned attribute in C notation: `0x` hexadecimal, leading-`0` octal
/// or decimal, which is how Ghidra's XML decoder reads integers.
fn unsigned(
    node: Node<'_, '_>,
    element: &'static str,
    name: &'static str,
) -> Result<u64, DataTestError> {
    let value = attribute(node, element, name)?;
    let text = value.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else if text.len() > 1 && text.starts_with('0') {
        u64::from_str_radix(text, 8)
    } else {
        text.parse()
    };
    parsed.map_err(|source| DataTestError::BadNumber {
        line: line_of(node),
        element,
        attribute: name,
        value: value.to_owned(),
        source,
    })
}

/// A decimal count attribute of `<stringmatch>`.
fn count(node: Node<'_, '_>, name: &'static str) -> Result<u32, DataTestError> {
    let value = attribute(node, "stringmatch", name)?;
    value
        .trim()
        .parse()
        .map_err(|source| DataTestError::BadNumber {
            line: line_of(node),
            element: "stringmatch",
            attribute: name,
            value: value.to_owned(),
            source,
        })
}

fn string_match(node: Node<'_, '_>) -> Result<StringMatch, DataTestError> {
    Ok(StringMatch {
        name: attribute(node, "stringmatch", "name")?.to_owned(),
        min: count(node, "min")?,
        max: count(node, "max")?,
        lines: pattern_lines(&content(node)),
    })
}

/// Split a pattern into its per-line regular expressions exactly as
/// `FunctionTestProperty::restoreXml` does: blanks and tabs before each line
/// are dropped, the text up to the next line break is one expression, and
/// the pattern ends at the first line that has nothing after its blanks. A
/// line break directly after another therefore yields an empty expression,
/// which matches any line.
fn pattern_lines(pattern: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut rest = pattern;
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }
        let Some((line, after)) = rest.split_once('\n') else {
            lines.push(rest.to_owned());
            break;
        };
        lines.push(line.to_owned());
        rest = after;
    }
    lines
}

fn binary_image(node: Node<'_, '_>) -> Result<BinaryImage, DataTestError> {
    let arch = attribute(node, "binaryimage", "arch")?.to_owned();
    let mut chunks = Vec::new();
    let mut symbols = Vec::new();
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "bytechunk" => chunks.push(ByteChunk {
                space: attribute(child, "bytechunk", "space")?.to_owned(),
                offset: unsigned(child, "bytechunk", "offset")?,
                readonly: child.attribute("readonly").is_some_and(xml_bool),
                bytes: hex_bytes(child)?,
            }),
            "symbol" => symbols.push(ImageSymbol {
                space: attribute(child, "symbol", "space")?.to_owned(),
                offset: unsigned(child, "symbol", "offset")?,
                name: attribute(child, "symbol", "name")?.to_owned(),
            }),
            other => {
                return Err(DataTestError::UnknownElement {
                    line: line_of(child),
                    parent: "binaryimage",
                    name: other.to_owned(),
                });
            }
        }
    }
    Ok(BinaryImage {
        arch,
        chunks,
        symbols,
    })
}

/// Ghidra's `xml_readbool`: true when the value starts with `t`, `1` or `y`.
fn xml_bool(value: &str) -> bool {
    matches!(value.as_bytes().first(), Some(b't' | b'1' | b'y'))
}

/// The bytes of a `<bytechunk>`: pairs of hexadecimal digits separated by
/// any amount of white space.
fn hex_bytes(node: Node<'_, '_>) -> Result<Vec<u8>, DataTestError> {
    let text = content(node);
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let mut digits = text.chars().filter(|c| !c.is_ascii_whitespace());
    while let Some(high) = digits.next() {
        let low = digits.next();
        let pair = low.and_then(|low| Some((high.to_digit(16)?, low.to_digit(16)?)));
        let Some((high, low)) = pair else {
            let found = std::iter::once(high)
                .chain(low)
                .chain(digits.by_ref().take(6))
                .collect();
            return Err(DataTestError::BadBytes {
                line: line_of(node),
                found,
            });
        };
        bytes.push((high * 16 + low) as u8);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
