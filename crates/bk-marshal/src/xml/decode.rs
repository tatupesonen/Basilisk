//! The XML decoder (Ghidra `XmlDecode` in `marshal.cc`).

use super::dom::{Document, ElementRef};
use super::number::{self, Radix};
use crate::MAX_ELEMENT_DEPTH;
use crate::decoder::Decoder;
use crate::error::DecodeError;
use crate::ids::{ATTRIB_CONTENT, AttrCode, AttributeId, ElemCode, ElementId, IdTable};
use crate::space::{SpaceId, SpaceResolver};

/// An open element and the next of its children to visit.
#[derive(Debug, Clone, Copy)]
struct Frame<'a> {
    element: ElementRef<'a>,
    next_child: Option<ElementRef<'a>>,
}

/// Where attribute iteration stands in the current element (Ghidra's
/// `attributeIndex`: -1, an index, or 1000).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cursor {
    /// No attribute visited yet.
    Before,
    /// The attribute at this index is current.
    At(usize),
    /// Iteration is over until rewound: an element was just closed.
    Done,
}

/// Decodes a parsed XML [`Document`] (Ghidra `XmlDecode`).
///
/// Unlike Ghidra's release build, [`Decoder::close_element`] always checks
/// that no child is left unread and that the id matches (Ghidra does so only
/// when built with `CPUI_DEBUG`), so that the XML and packed forms fail alike.
pub struct XmlDecoder<'a> {
    ids: &'a IdTable,
    spaces: &'a dyn SpaceResolver,
    root: Option<ElementRef<'a>>,
    stack: Vec<Frame<'a>>,
    cursor: Cursor,
}

impl std::fmt::Debug for XmlDecoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XmlDecoder")
            .field("depth", &self.stack.len())
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<'a> XmlDecoder<'a> {
    /// Creates a decoder positioned before the document's root element.
    ///
    /// `ids` maps element and attribute names to ids; `spaces` resolves the
    /// names in address-space attributes.
    pub fn new(
        document: &'a Document<'_>,
        ids: &'a IdTable,
        spaces: &'a dyn SpaceResolver,
    ) -> Self {
        Self::at(document.root(), ids, spaces)
    }

    /// Creates a decoder positioned before the given element, which it treats
    /// as the root (Ghidra's `XmlDecode` constructor taking an `Element`).
    pub fn at(root: ElementRef<'a>, ids: &'a IdTable, spaces: &'a dyn SpaceResolver) -> Self {
        Self {
            ids,
            spaces,
            root: Some(root),
            stack: Vec::new(),
            cursor: Cursor::Before,
        }
    }

    /// The element currently open (Ghidra `getCurrentXmlElement`).
    pub fn current_element(&self) -> Option<ElementRef<'a>> {
        self.stack.last().map(|frame| frame.element)
    }

    fn top(&self) -> Result<ElementRef<'a>, DecodeError> {
        self.current_element().ok_or(DecodeError::NoOpenElement)
    }

    /// Takes the next child of the current element (or the root) off the
    /// list of elements still to visit.
    fn take_next(&mut self) -> Option<ElementRef<'a>> {
        match self.stack.last_mut() {
            None => self.root.take(),
            Some(frame) => {
                let next = frame.next_child?;
                frame.next_child = next.next_sibling();
                Some(next)
            }
        }
    }

    fn push(&mut self, element: ElementRef<'a>) -> Result<(), DecodeError> {
        if self.stack.len() >= MAX_ELEMENT_DEPTH {
            return Err(DecodeError::TooDeep {
                limit: MAX_ELEMENT_DEPTH,
            });
        }
        self.stack.push(Frame {
            element,
            next_child: element.first_child(),
        });
        self.cursor = Cursor::Before;
        Ok(())
    }

    fn pop(&mut self, element: ElemCode) -> Result<(), DecodeError> {
        let top = self.top()?;
        let found = self.ids.element(top.name());
        if found != element {
            return Err(DecodeError::CloseMismatch {
                expected: element.get(),
                found: found.get(),
            });
        }
        self.stack.pop();
        self.cursor = Cursor::Done;
        Ok(())
    }

    fn current_value(&self) -> Result<&'a str, DecodeError> {
        let Cursor::At(index) = self.cursor else {
            return Err(DecodeError::NoCurrentAttribute);
        };
        let (_, value) = self
            .top()?
            .attribute_at(index)
            .ok_or(DecodeError::NoCurrentAttribute)?;
        Ok(value)
    }

    fn named_value(&self, attribute: AttributeId) -> Result<&'a str, DecodeError> {
        let element = self.top()?;
        if attribute == ATTRIB_CONTENT {
            return Ok(element.content());
        }
        element
            .attribute(attribute.name())
            .ok_or_else(|| DecodeError::AttributeMissing {
                name: attribute.name(),
            })
    }

    fn space_named(&self, name: &str) -> Result<SpaceId, DecodeError> {
        self.spaces
            .space_by_name(name)
            .ok_or_else(|| DecodeError::UnknownSpaceName(name.to_owned()))
    }
}

fn signed_or_string(text: &str, expect: &str, value: i64) -> i64 {
    if text == expect {
        value
    } else {
        number::parse_i64(text)
    }
}

fn enum_named(text: &str, by_name: &dyn Fn(&str) -> Option<i64>) -> Result<i64, DecodeError> {
    by_name(text).ok_or_else(|| DecodeError::UnknownEnumName(text.to_owned()))
}

impl<'a> Decoder<'a> for XmlDecoder<'a> {
    fn peek_element(&self) -> Option<ElemCode> {
        let next = match self.stack.last() {
            None => self.root,
            Some(frame) => frame.next_child,
        };
        next.map(|element| self.ids.element(element.name()))
    }

    fn open_element(&mut self) -> Result<Option<ElemCode>, DecodeError> {
        let Some(element) = self.take_next() else {
            return Ok(None);
        };
        self.push(element)?;
        Ok(Some(self.ids.element(element.name())))
    }

    fn open_element_expecting(&mut self, expected: ElementId) -> Result<ElemCode, DecodeError> {
        let element = self.take_next().ok_or_else(|| DecodeError::NoElement {
            expected: expected.name(),
        })?;
        if element.name() != expected.name() {
            return Err(DecodeError::ElementMismatch {
                expected: expected.name(),
                found: format!("<{}>", element.name()),
            });
        }
        self.push(element)?;
        Ok(expected.code())
    }

    fn close_element(&mut self, element: ElemCode) -> Result<(), DecodeError> {
        let frame = self.stack.last().ok_or(DecodeError::NoOpenElement)?;
        if frame.next_child.is_some() {
            return Err(DecodeError::UnreadChildren {
                element: format!("<{}>", frame.element.name()),
            });
        }
        self.pop(element)
    }

    fn close_element_skipping(&mut self, element: ElemCode) -> Result<(), DecodeError> {
        self.pop(element)
    }

    fn next_attribute(&mut self) -> Result<Option<AttrCode>, DecodeError> {
        let element = self.top()?;
        let next = match self.cursor {
            Cursor::Before => 0,
            Cursor::At(index) => index + 1,
            Cursor::Done => return Ok(None),
        };
        if let Some((name, _)) = element.attribute_at(next) {
            self.cursor = Cursor::At(next);
            Ok(Some(self.ids.attribute(name)))
        } else {
            self.cursor = Cursor::Done;
            Ok(None)
        }
    }

    fn indexed_attribute(&mut self, base: AttributeId) -> Result<AttrCode, DecodeError> {
        let unknown = self.ids.unknown_attribute();
        let Cursor::At(index) = self.cursor else {
            return Ok(unknown);
        };
        let Some((name, _)) = self.top()?.attribute_at(index) else {
            return Ok(unknown);
        };
        // In XML the index is part of the attribute name, starting at 1.
        let Some(suffix) = name.strip_prefix(base.name()) else {
            return Ok(unknown);
        };
        match number::scan(suffix, Radix::Decimal).as_u32() {
            0 => Err(DecodeError::BadIndexedAttribute { name: base.name() }),
            position => Ok(base.indexed(position - 1)),
        }
    }

    fn rewind_attributes(&mut self) {
        self.cursor = Cursor::Before;
    }

    fn read_bool(&mut self) -> Result<bool, DecodeError> {
        self.current_value().map(number::parse_bool)
    }

    fn read_bool_attr(&mut self, attribute: AttributeId) -> Result<bool, DecodeError> {
        self.named_value(attribute).map(number::parse_bool)
    }

    fn read_signed(&mut self) -> Result<i64, DecodeError> {
        self.current_value().map(number::parse_i64)
    }

    fn read_signed_attr(&mut self, attribute: AttributeId) -> Result<i64, DecodeError> {
        self.named_value(attribute).map(number::parse_i64)
    }

    fn read_signed_or_string(&mut self, expect: &str, value: i64) -> Result<i64, DecodeError> {
        self.current_value()
            .map(|text| signed_or_string(text, expect, value))
    }

    fn read_signed_or_string_attr(
        &mut self,
        attribute: AttributeId,
        expect: &str,
        value: i64,
    ) -> Result<i64, DecodeError> {
        self.named_value(attribute)
            .map(|text| signed_or_string(text, expect, value))
    }

    fn read_unsigned(&mut self) -> Result<u64, DecodeError> {
        self.current_value().map(number::parse_u64)
    }

    fn read_unsigned_attr(&mut self, attribute: AttributeId) -> Result<u64, DecodeError> {
        self.named_value(attribute).map(number::parse_u64)
    }

    fn read_string(&mut self) -> Result<&'a str, DecodeError> {
        self.current_value()
    }

    fn read_string_attr(&mut self, attribute: AttributeId) -> Result<&'a str, DecodeError> {
        self.named_value(attribute)
    }

    fn read_space(&mut self) -> Result<SpaceId, DecodeError> {
        let name = self.current_value()?;
        self.space_named(name)
    }

    fn read_space_attr(&mut self, attribute: AttributeId) -> Result<SpaceId, DecodeError> {
        let name = self.named_value(attribute)?;
        self.space_named(name)
    }

    fn read_enum(&mut self, by_name: &dyn Fn(&str) -> Option<i64>) -> Result<i64, DecodeError> {
        enum_named(self.current_value()?, by_name)
    }

    fn read_enum_attr(
        &mut self,
        attribute: AttributeId,
        by_name: &dyn Fn(&str) -> Option<i64>,
    ) -> Result<i64, DecodeError> {
        enum_named(self.named_value(attribute)?, by_name)
    }
}
