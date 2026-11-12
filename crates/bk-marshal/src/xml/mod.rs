//! Reading and writing the XML form.
//!
//! Ghidra reads XML with its own parser (`xml.y`) into a small DOM
//! (`xml.hh`) and decodes from that with `XmlDecode`. Here the text is
//! tokenised by the `quick-xml` crate and assembled into [`Document`], an
//! arena DOM that applies Ghidra's rules for attribute values and for an
//! element's text content and keeps the parser's types out of the public API.
//! [`XmlDecoder`] walks a `Document`; [`XmlEncoder`] writes text identical to
//! Ghidra's `XmlEncode`.

mod decode;
mod dom;
mod encode;
pub mod number;
mod parse;

pub use decode::XmlDecoder;
pub use dom::{Document, ElementRef};
pub use encode::{XmlEncoder, xml_escape};

/// A failure to parse XML text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("XML error at {line}:{column}: {message}")]
pub struct XmlError {
    /// What is wrong.
    pub message: String,
    /// Line of the error, starting at 1.
    pub line: u32,
    /// Column of the error in bytes, starting at 1.
    pub column: u32,
}

impl XmlError {
    /// Builds an error for a byte offset in `source`.
    pub(crate) fn at(source: &str, offset: usize, message: impl Into<String>) -> Self {
        let offset = offset.min(source.len());
        let before = source.as_bytes().get(..offset).unwrap_or_default();
        let line = before.split(|&byte| byte == b'\n').count();
        let line_start = before
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |at| at + 1);
        Self {
            message: message.into(),
            line: u32::try_from(line).unwrap_or(u32::MAX),
            column: u32::try_from(offset - line_start + 1).unwrap_or(u32::MAX),
        }
    }
}
