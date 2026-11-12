//! The XML encoder (Ghidra `XmlEncode` in `marshal.cc`, `xml_escape` in
//! `xml.y`).
//!
//! The text produced is byte-for-byte what Ghidra writes, because expected
//! outputs elsewhere are compared as text.

use std::fmt::Write as _;

use crate::encoder::Encoder;
use crate::error::EncodeError;
use crate::ids::{ATTRIB_CONTENT, AttributeId, ElementId};
use crate::space::SpaceRef;

/// Appends `text` to `out` with `<`, `>`, `&`, `"` and `'` replaced by their
/// entity references (Ghidra `xml_escape`).
pub fn xml_escape(out: &mut String, text: &str) {
    let mut rest = text;
    while let Some(at) = rest.find(['<', '>', '&', '"', '\'']) {
        let (plain, tail) = rest.split_at(at);
        out.push_str(plain);
        let mut chars = tail.chars();
        out.push_str(match chars.next() {
            Some('<') => "&lt;",
            Some('>') => "&gt;",
            Some('&') => "&amp;",
            Some('"') => "&quot;",
            _ => "&apos;",
        });
        rest = chars.as_str();
    }
    out.push_str(rest);
}

/// How far the tag of the current element has been written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TagStatus {
    /// The tag has been opened; attributes can be written.
    Start,
    /// The opening tag and content have been written.
    Content,
    /// No tag is being written.
    Stop,
}

/// The longest indent Ghidra writes, in spaces.
const MAX_INDENT: usize = 24;

/// Writes a document as XML text (Ghidra `XmlEncode`).
#[derive(Debug, Clone)]
pub struct XmlEncoder {
    out: String,
    status: TagStatus,
    depth: usize,
    formatting: bool,
}

impl Default for XmlEncoder {
    fn default() -> Self {
        Self::new(true)
    }
}

impl XmlEncoder {
    /// Creates an encoder. With `formatting`, each tag starts on a new line,
    /// indented two spaces per level (Ghidra's `doFormat`, on by default).
    pub fn new(formatting: bool) -> Self {
        Self {
            out: String::new(),
            status: TagStatus::Stop,
            depth: 0,
            formatting,
        }
    }

    /// The text written so far.
    pub fn as_str(&self) -> &str {
        &self.out
    }

    /// Consumes the encoder and returns the text.
    pub fn into_string(self) -> String {
        self.out
    }

    /// Discards the text written so far and resets the encoder.
    pub fn clear(&mut self) {
        self.out.clear();
        self.status = TagStatus::Stop;
        self.depth = 0;
    }

    fn new_line(&mut self) {
        if !self.formatting {
            return;
        }
        self.out.push('\n');
        let indent = self.depth.saturating_mul(2).min(MAX_INDENT);
        self.out.extend(std::iter::repeat_n(' ', indent));
    }

    /// Starts an attribute, or the text content when `attribute` is
    /// `ATTRIB_CONTENT`. Returns `true` for content.
    fn begin_value(&mut self, attribute: AttributeId) -> bool {
        if attribute == ATTRIB_CONTENT {
            if self.status == TagStatus::Start {
                self.out.push('>');
            }
            self.status = TagStatus::Content;
            true
        } else {
            self.out.push(' ');
            self.out.push_str(attribute.name());
            self.out.push_str("=\"");
            false
        }
    }

    fn end_value(&mut self, is_content: bool) {
        if !is_content {
            self.out.push('"');
        }
    }
}

impl Encoder for XmlEncoder {
    fn open_element(&mut self, element: ElementId) {
        if self.status == TagStatus::Start {
            self.out.push('>');
        } else {
            self.status = TagStatus::Start;
        }
        self.new_line();
        self.out.push('<');
        self.out.push_str(element.name());
        self.depth += 1;
    }

    fn close_element(&mut self, element: ElementId) {
        self.depth = self.depth.saturating_sub(1);
        if self.status == TagStatus::Start {
            self.out.push_str("/>");
            self.status = TagStatus::Stop;
            return;
        }
        if self.status == TagStatus::Content {
            self.status = TagStatus::Stop;
        } else {
            self.new_line();
        }
        self.out.push_str("</");
        self.out.push_str(element.name());
        self.out.push('>');
    }

    fn write_bool(&mut self, attribute: AttributeId, value: bool) {
        let is_content = self.begin_value(attribute);
        self.out.push_str(if value { "true" } else { "false" });
        self.end_value(is_content);
    }

    fn write_signed(&mut self, attribute: AttributeId, value: i64) {
        let is_content = self.begin_value(attribute);
        // Writing to a String cannot fail.
        let _ = write!(self.out, "{value}");
        self.end_value(is_content);
    }

    fn write_unsigned(&mut self, attribute: AttributeId, value: u64) {
        let is_content = self.begin_value(attribute);
        let _ = write!(self.out, "0x{value:x}");
        self.end_value(is_content);
    }

    fn write_string(&mut self, attribute: AttributeId, value: &str) -> Result<(), EncodeError> {
        let is_content = self.begin_value(attribute);
        xml_escape(&mut self.out, value);
        self.end_value(is_content);
        Ok(())
    }

    fn write_string_indexed(
        &mut self,
        attribute: AttributeId,
        index: u32,
        value: &str,
    ) -> Result<(), EncodeError> {
        // The index is part of the attribute name, starting at 1.
        let _ = write!(
            self.out,
            " {}{}=\"",
            attribute.name(),
            index.wrapping_add(1)
        );
        xml_escape(&mut self.out, value);
        self.out.push('"');
        Ok(())
    }

    fn write_space(&mut self, attribute: AttributeId, space: &SpaceRef<'_>) {
        let is_content = self.begin_value(attribute);
        xml_escape(&mut self.out, space.name);
        self.end_value(is_content);
    }

    fn write_enum(&mut self, attribute: AttributeId, _value: u64, name: &str) {
        // Ghidra writes opcode and metatype names without escaping; they are
        // plain identifiers.
        let is_content = self.begin_value(attribute);
        self.out.push_str(name);
        self.end_value(is_content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{
        ATTRIB_ID, ATTRIB_NAME, ATTRIB_SPACE, ATTRIB_VAL, ELEM_DATA, ELEM_INPUT, ELEM_OFF,
        ELEM_OUTPUT,
    };
    use crate::space::PackedSpace;

    #[test]
    fn escape_matches_ghidra() {
        let mut out = String::new();
        xml_escape(&mut out, "a<b>c&d\"e'f \u{20ac}\n\t?@");
        assert_eq!(out, "a&lt;b&gt;c&amp;d&quot;e&apos;f \u{20ac}\n\t?@");
        let mut out = String::from("x");
        xml_escape(&mut out, "");
        assert_eq!(out, "x");
        let mut out = String::new();
        xml_escape(&mut out, "<<>>");
        assert_eq!(out, "&lt;&lt;&gt;&gt;");
    }

    #[test]
    fn formatted_output_matches_ghidra() {
        // Hand-traced through XmlEncode::openElement/closeElement/newLine.
        let mut enc = XmlEncoder::new(true);
        enc.open_element(ELEM_DATA);
        enc.write_signed(ATTRIB_ID, -5);
        enc.open_element(ELEM_INPUT);
        enc.write_unsigned(ATTRIB_VAL, 0x1f);
        enc.close_element(ELEM_INPUT);
        enc.open_element(ELEM_OUTPUT);
        enc.write_bool(ATTRIB_CONTENT, true);
        enc.close_element(ELEM_OUTPUT);
        enc.open_element(ELEM_OFF);
        enc.open_element(ELEM_OFF);
        enc.close_element(ELEM_OFF);
        enc.close_element(ELEM_OFF);
        enc.close_element(ELEM_DATA);
        assert_eq!(
            enc.as_str(),
            "\n<data id=\"-5\">\n  <input val=\"0x1f\"/>\n  <output>true</output>\n  <off>\n    <off/>\n  </off>\n</data>"
        );
    }

    #[test]
    fn unformatted_output_matches_ghidra() {
        let mut enc = XmlEncoder::new(false);
        enc.open_element(ELEM_DATA);
        enc.write_string(ATTRIB_NAME, "a<b").unwrap();
        enc.open_element(ELEM_INPUT);
        enc.close_element(ELEM_INPUT);
        enc.close_element(ELEM_DATA);
        assert_eq!(enc.into_string(), "<data name=\"a&lt;b\"><input/></data>");
    }

    #[test]
    fn content_forms() {
        let mut enc = XmlEncoder::new(false);
        enc.open_element(ELEM_DATA);
        enc.write_signed(ATTRIB_CONTENT, -12);
        enc.close_element(ELEM_DATA);
        enc.open_element(ELEM_DATA);
        enc.write_unsigned(ATTRIB_CONTENT, 255);
        enc.close_element(ELEM_DATA);
        enc.open_element(ELEM_DATA);
        enc.write_string(ATTRIB_CONTENT, "x & y").unwrap();
        enc.close_element(ELEM_DATA);
        enc.open_element(ELEM_DATA);
        enc.write_bool(ATTRIB_CONTENT, false);
        enc.close_element(ELEM_DATA);
        enc.open_element(ELEM_DATA);
        enc.write_space(
            ATTRIB_CONTENT,
            &SpaceRef {
                name: "ram",
                packed: PackedSpace::Index(3),
            },
        );
        enc.close_element(ELEM_DATA);
        enc.open_element(ELEM_DATA);
        enc.write_enum(ATTRIB_CONTENT, 1, "COPY");
        enc.close_element(ELEM_DATA);
        assert_eq!(
            enc.as_str(),
            "<data>-12</data><data>0xff</data><data>x &amp; y</data><data>false</data><data>ram</data><data>COPY</data>"
        );
    }

    #[test]
    fn content_then_child() {
        // After content, a child starts on a new line and the parent's close
        // tag is preceded by a new line (tag status is "stop" by then).
        let mut enc = XmlEncoder::default();
        enc.open_element(ELEM_DATA);
        enc.write_bool(ATTRIB_CONTENT, true);
        enc.open_element(ELEM_INPUT);
        enc.close_element(ELEM_INPUT);
        enc.close_element(ELEM_DATA);
        assert_eq!(enc.as_str(), "\n<data>true\n  <input/>\n</data>");
    }

    #[test]
    fn attribute_forms() {
        let mut enc = XmlEncoder::new(false);
        enc.open_element(ELEM_DATA);
        enc.write_bool(ATTRIB_NAME, true);
        enc.write_bool(ATTRIB_ID, false);
        enc.write_signed(ATTRIB_VAL, i64::MIN);
        enc.write_unsigned(ATTRIB_VAL, u64::MAX);
        enc.write_unsigned(ATTRIB_VAL, 0);
        enc.write_string(ATTRIB_NAME, "").unwrap();
        enc.write_space(
            ATTRIB_SPACE,
            &SpaceRef {
                name: "ram",
                packed: PackedSpace::Index(3),
            },
        );
        enc.write_string_indexed(ATTRIB_NAME, 0, "p<1").unwrap();
        enc.write_string_indexed(ATTRIB_NAME, 8, "p9").unwrap();
        enc.write_enum(ATTRIB_VAL, 1, "COPY");
        enc.close_element(ELEM_DATA);
        assert_eq!(
            enc.as_str(),
            "<data name=\"true\" id=\"false\" val=\"-9223372036854775808\" val=\"0xffffffffffffffff\" val=\"0x0\" name=\"\" space=\"ram\" name1=\"p&lt;1\" name9=\"p9\" val=\"COPY\"/>"
        );
    }

    #[test]
    fn indent_is_capped() {
        let mut enc = XmlEncoder::new(true);
        for _ in 0..14 {
            enc.open_element(ELEM_OFF);
        }
        let text = enc.as_str();
        // Depth 12 and deeper are indented 24 spaces.
        let last = text.rsplit('\n').next().unwrap();
        assert_eq!(last, format!("{}<off", " ".repeat(24)));
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines[12], format!("{}<off>", " ".repeat(22)));
        assert_eq!(lines[13], format!("{}<off>", " ".repeat(24)));
    }

    #[test]
    fn clear_resets_state() {
        let mut enc = XmlEncoder::new(true);
        enc.open_element(ELEM_DATA);
        enc.clear();
        enc.open_element(ELEM_DATA);
        enc.close_element(ELEM_DATA);
        assert_eq!(enc.as_str(), "\n<data/>");
        // Closing more than was opened does not panic.
        enc.close_element(ELEM_DATA);
        enc.close_element(ELEM_DATA);
    }
}
