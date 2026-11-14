//! The pull interface the model decoder reads through, with its two
//! implementations: a direct cursor over the packed stream (the fast path)
//! and an adapter over any `bk_marshal::Decoder` (the XML form, and the
//! packed form through `bk-marshal` for cross-checking).

use bk_marshal::{Decoder, SpaceId, SpaceResolver};

use crate::error::{Fail, StreamError};
use crate::ids;

/// An address-space attribute as the document holds it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SpaceAttr<'a> {
    /// The packed form: the space's index.
    Index(u64),
    /// The XML form: the space's name.
    Name(&'a str),
}

/// An opcode attribute as the document holds it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum OpcodeAttr<'a> {
    /// The packed form: the opcode's number.
    Number(i64),
    /// The XML form: `get_opname`'s name.
    Name(&'a str),
}

/// A document of format-scope elements, read depth first. Attributes not
/// read are skipped by the next structural call.
pub(crate) trait Source<'a> {
    /// The id of the next child of the current element, if any.
    fn peek(&mut self) -> Result<Option<u32>, Fail>;
    /// Opens the next child, which must exist.
    fn open(&mut self) -> Result<u32, Fail>;
    /// Closes the current element; no child may remain.
    fn close(&mut self) -> Result<(), Fail>;
    /// The id of the next attribute of the current element, if any.
    fn next_attr(&mut self) -> Result<Option<u32>, Fail>;
    /// The current attribute as a boolean.
    fn bool(&mut self) -> Result<bool, Fail>;
    /// The current attribute as a signed integer.
    fn signed(&mut self) -> Result<i64, Fail>;
    /// The current attribute as an unsigned integer.
    fn unsigned(&mut self) -> Result<u64, Fail>;
    /// The current attribute as a string.
    fn string(&mut self) -> Result<&'a str, Fail>;
    /// The current attribute as an address space.
    fn space(&mut self) -> Result<SpaceAttr<'a>, Fail>;
    /// The current attribute as an opcode.
    fn opcode(&mut self) -> Result<OpcodeAttr<'a>, Fail>;
    /// The ids of the open elements, outermost first.
    fn stack(&self) -> &[u32];
    /// The current byte offset, for the packed form.
    fn offset(&self) -> Option<usize>;
    /// After the root element: the offset of any data that follows it.
    fn trailing(&self) -> Option<usize>;
}

/// The name of an element id, for messages.
pub(crate) fn element_text(id: u32) -> String {
    ids::element_name(id).map_or_else(|| format!("element id {id}"), |name| format!("<{name}>"))
}

/// Reads the inflated packed stream directly (`features/sla.md` 5.3).
#[derive(Debug)]
pub(crate) struct PackedCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    stack: Vec<u32>,
    max_depth: usize,
    /// The cursor is inside the current element's attribute list.
    in_attrs: bool,
    /// An attribute's header has been read and its value has not.
    pending: Option<u32>,
}

const HEADER_MASK: u8 = 0xc0;
const ELEMENT_START: u8 = 0x40;
const ELEMENT_END: u8 = 0x80;
const ATTRIBUTE: u8 = 0xc0;
const EXTEND: u8 = 0x20;
const TYPE_BOOL: u8 = 1;
const TYPE_POSITIVE: u8 = 2;
const TYPE_NEGATIVE: u8 = 3;
const TYPE_UNSIGNED: u8 = 4;
const TYPE_SPACE: u8 = 5;
const TYPE_SPECIAL: u8 = 6;
const TYPE_STRING: u8 = 7;

impl<'a> PackedCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8], max_depth: u32) -> Self {
        Self {
            bytes,
            pos: 0,
            stack: Vec::with_capacity(32),
            max_depth: max_depth as usize,
            in_attrs: false,
            pending: None,
        }
    }

    #[inline]
    fn byte(&mut self) -> Result<u8, Fail> {
        let byte = *self.bytes.get(self.pos).ok_or(StreamError::UnexpectedEof)?;
        self.pos += 1;
        Ok(byte)
    }

    #[inline]
    fn id(&mut self, header: u8) -> Result<u32, Fail> {
        let mut id = u32::from(header & 0x1f);
        if header & EXTEND != 0 {
            id = (id << 7) | u32::from(self.byte()? & 0x7f);
        }
        Ok(id)
    }

    #[inline]
    fn integer(&mut self, length: u8) -> Result<u64, Fail> {
        let end = self.pos + usize::from(length);
        let groups = self
            .bytes
            .get(self.pos..end)
            .ok_or(StreamError::UnexpectedEof)?;
        self.pos = end;
        Ok(groups
            .iter()
            .fold(0u64, |value, &byte| (value << 7) | u64::from(byte & 0x7f)))
    }

    fn skip_value(&mut self) -> Result<(), Fail> {
        let type_byte = self.byte()?;
        let length = type_byte & 0x0f;
        match type_byte >> 4 {
            TYPE_BOOL | TYPE_SPECIAL => Ok(()),
            TYPE_STRING => {
                let count = self.integer(length)?;
                self.advance(count)
            }
            _ => self.advance(u64::from(length)),
        }
    }

    fn advance(&mut self, count: u64) -> Result<(), Fail> {
        let target = usize::try_from(count)
            .ok()
            .and_then(|count| self.pos.checked_add(count))
            .filter(|&target| target <= self.bytes.len())
            .ok_or(StreamError::UnexpectedEof)?;
        self.pos = target;
        Ok(())
    }

    fn skip_attrs(&mut self) -> Result<(), Fail> {
        while self.in_attrs {
            self.next_attr()?;
        }
        Ok(())
    }

    /// Consumes the pending attribute's type byte.
    #[inline]
    fn value_type(&mut self) -> Result<(u32, u8), Fail> {
        let attribute = self
            .pending
            .take()
            .ok_or_else(|| Fail::invalid("no attribute to read"))?;
        Ok((attribute, self.byte()?))
    }

    fn wrong(&mut self, attribute: u32, expected: &'static str) -> Fail {
        // Leave the stream positioned after the value.
        self.pos = self.pos.saturating_sub(1);
        if self.skip_value().is_err() {
            self.pos = self.bytes.len();
        }
        Fail::Stream(StreamError::WrongType {
            attribute: ids::attribute_name(attribute).unwrap_or("?"),
            expected,
        })
    }
}

impl<'a> Source<'a> for PackedCursor<'a> {
    fn peek(&mut self) -> Result<Option<u32>, Fail> {
        self.skip_attrs()?;
        let Some(&header) = self.bytes.get(self.pos) else {
            return Ok(None);
        };
        if header & HEADER_MASK != ELEMENT_START {
            return Ok(None);
        }
        let mut id = u32::from(header & 0x1f);
        if header & EXTEND != 0 {
            let next = self.bytes.get(self.pos + 1).copied().unwrap_or(0);
            id = (id << 7) | u32::from(next & 0x7f);
        }
        Ok(Some(id))
    }

    fn open(&mut self) -> Result<u32, Fail> {
        self.skip_attrs()?;
        let header = self.byte()?;
        if header & HEADER_MASK != ELEMENT_START {
            self.pos -= 1;
            return Err(StreamError::Corrupt { byte: header }.into());
        }
        let id = self.id(header)?;
        if self.stack.len() >= self.max_depth {
            return Err(Fail::limit(
                "element nesting",
                self.max_depth as u64,
                self.stack.len() as u64 + 1,
            ));
        }
        self.stack.push(id);
        self.in_attrs = true;
        self.pending = None;
        Ok(id)
    }

    fn close(&mut self) -> Result<(), Fail> {
        self.skip_attrs()?;
        let expected = *self
            .stack
            .last()
            .ok_or_else(|| Fail::invalid("no element open"))?;
        let header = self.byte()?;
        match header & HEADER_MASK {
            ELEMENT_END => {}
            ELEMENT_START => {
                self.pos -= 1;
                let found = self.peek()?.unwrap_or(0);
                return Err(StreamError::UnexpectedChild {
                    found: element_text(found),
                }
                .into());
            }
            _ => {
                self.pos -= 1;
                return Err(StreamError::Corrupt { byte: header }.into());
            }
        }
        let found = self.id(header)?;
        if found != expected {
            return Err(StreamError::CloseMismatch { expected, found }.into());
        }
        self.stack.pop();
        Ok(())
    }

    #[inline]
    fn next_attr(&mut self) -> Result<Option<u32>, Fail> {
        if !self.in_attrs {
            return Ok(None);
        }
        if self.pending.take().is_some() {
            self.skip_value()?;
        }
        match self.bytes.get(self.pos) {
            Some(&header) if header & HEADER_MASK == ATTRIBUTE => {
                self.pos += 1;
                let id = self.id(header)?;
                self.pending = Some(id);
                Ok(Some(id))
            }
            _ => {
                self.in_attrs = false;
                Ok(None)
            }
        }
    }

    #[inline]
    fn bool(&mut self) -> Result<bool, Fail> {
        let (attribute, type_byte) = self.value_type()?;
        if type_byte >> 4 != TYPE_BOOL {
            return Err(self.wrong(attribute, "a boolean"));
        }
        Ok(type_byte & 0x0f != 0)
    }

    #[inline]
    fn signed(&mut self) -> Result<i64, Fail> {
        let (attribute, type_byte) = self.value_type()?;
        match type_byte >> 4 {
            TYPE_POSITIVE => Ok(self.integer(type_byte & 0x0f)?.cast_signed()),
            TYPE_NEGATIVE => Ok(self.integer(type_byte & 0x0f)?.cast_signed().wrapping_neg()),
            _ => Err(self.wrong(attribute, "a signed integer")),
        }
    }

    #[inline]
    fn unsigned(&mut self) -> Result<u64, Fail> {
        let (attribute, type_byte) = self.value_type()?;
        if type_byte >> 4 != TYPE_UNSIGNED {
            return Err(self.wrong(attribute, "an unsigned integer"));
        }
        self.integer(type_byte & 0x0f)
    }

    fn string(&mut self) -> Result<&'a str, Fail> {
        let (attribute, type_byte) = self.value_type()?;
        if type_byte >> 4 != TYPE_STRING {
            return Err(self.wrong(attribute, "a string"));
        }
        let length = self.integer(type_byte & 0x0f)?;
        let start = self.pos;
        self.advance(length)?;
        let bytes = self.bytes.get(start..self.pos).unwrap_or_default();
        std::str::from_utf8(bytes).map_err(|_| StreamError::InvalidUtf8.into())
    }

    fn space(&mut self) -> Result<SpaceAttr<'a>, Fail> {
        let (attribute, type_byte) = self.value_type()?;
        match type_byte >> 4 {
            TYPE_SPACE => Ok(SpaceAttr::Index(self.integer(type_byte & 0x0f)?)),
            TYPE_SPECIAL => Err(StreamError::UnknownSpace(format!(
                "special space code {}",
                type_byte & 0x0f
            ))
            .into()),
            _ => Err(self.wrong(attribute, "an address space")),
        }
    }

    fn opcode(&mut self) -> Result<OpcodeAttr<'a>, Fail> {
        self.signed().map(OpcodeAttr::Number)
    }

    fn stack(&self) -> &[u32] {
        &self.stack
    }

    fn offset(&self) -> Option<usize> {
        Some(self.pos)
    }

    fn trailing(&self) -> Option<usize> {
        (self.pos < self.bytes.len()).then_some(self.pos)
    }
}

/// A resolver that accepts every space index, so that `bk-marshal`'s packed
/// decoder hands raw indices to the model decoder, which checks them.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AnySpace;

impl SpaceResolver for AnySpace {
    fn space_by_name(&self, _name: &str) -> Option<SpaceId> {
        None
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        u32::try_from(index).ok().map(SpaceId::new)
    }

    fn space_count(&self) -> u64 {
        u64::MAX
    }

    fn stack_space(&self) -> Option<SpaceId> {
        None
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

/// Reads through a `bk_marshal` decoder.
#[derive(Debug)]
pub(crate) struct MarshalSource<D> {
    decoder: D,
    xml: bool,
    stack: Vec<u32>,
    max_depth: usize,
}

impl<D> MarshalSource<D> {
    /// `xml` says whether space and opcode attributes are names (XML) or
    /// numbers (packed).
    pub(crate) fn new(decoder: D, xml: bool, max_depth: u32) -> Self {
        Self {
            decoder,
            xml,
            stack: Vec::new(),
            max_depth: max_depth as usize,
        }
    }
}

impl<'a, D: Decoder<'a>> Source<'a> for MarshalSource<D> {
    fn peek(&mut self) -> Result<Option<u32>, Fail> {
        Ok(self.decoder.peek_element().map(bk_marshal::ElemCode::get))
    }

    fn open(&mut self) -> Result<u32, Fail> {
        if self.stack.len() >= self.max_depth {
            return Err(Fail::limit(
                "element nesting",
                self.max_depth as u64,
                self.stack.len() as u64 + 1,
            ));
        }
        let code = self
            .decoder
            .open_element()?
            .ok_or(StreamError::UnexpectedEof)?;
        self.stack.push(code.get());
        Ok(code.get())
    }

    fn close(&mut self) -> Result<(), Fail> {
        let id = *self
            .stack
            .last()
            .ok_or_else(|| Fail::invalid("no element open"))?;
        if let Some(found) = self.decoder.peek_element() {
            return Err(StreamError::UnexpectedChild {
                found: element_text(found.get()),
            }
            .into());
        }
        self.decoder.close_element(bk_marshal::ElemCode::new(id))?;
        self.stack.pop();
        Ok(())
    }

    fn next_attr(&mut self) -> Result<Option<u32>, Fail> {
        Ok(self
            .decoder
            .next_attribute()?
            .map(bk_marshal::AttrCode::get))
    }

    fn bool(&mut self) -> Result<bool, Fail> {
        Ok(self.decoder.read_bool()?)
    }

    fn signed(&mut self) -> Result<i64, Fail> {
        Ok(self.decoder.read_signed()?)
    }

    fn unsigned(&mut self) -> Result<u64, Fail> {
        Ok(self.decoder.read_unsigned()?)
    }

    fn string(&mut self) -> Result<&'a str, Fail> {
        Ok(self.decoder.read_string()?)
    }

    fn space(&mut self) -> Result<SpaceAttr<'a>, Fail> {
        if self.xml {
            Ok(SpaceAttr::Name(self.decoder.read_string()?))
        } else {
            Ok(SpaceAttr::Index(u64::from(
                self.decoder.read_space()?.index(),
            )))
        }
    }

    fn opcode(&mut self) -> Result<OpcodeAttr<'a>, Fail> {
        if self.xml {
            Ok(OpcodeAttr::Name(self.decoder.read_string()?))
        } else {
            Ok(OpcodeAttr::Number(self.decoder.read_signed()?))
        }
    }

    fn stack(&self) -> &[u32] {
        &self.stack
    }

    fn offset(&self) -> Option<usize> {
        None
    }

    fn trailing(&self) -> Option<usize> {
        self.decoder.peek_element().map(|_| 0)
    }
}
