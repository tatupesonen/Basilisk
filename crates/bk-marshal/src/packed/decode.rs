//! The packed decoder (Ghidra `PackedDecode`).
//!
//! Ghidra ingests a stream into a chain of 1,024-byte buffers and appends an
//! element-end byte as padding, so that looking at the byte after the last
//! record never runs off the data. This decoder works on one contiguous
//! slice, borrows strings from it, and gets the same effect by treating the
//! position one past the end as holding that padding byte: it can be looked
//! at but not consumed.

use super::format::{
    ATTRIBUTE, ELEMENT_END, ELEMENT_START, ELEMENTID_MASK, HEADER_MASK, HEADEREXTEND_MASK,
    LENGTHCODE_MASK, RAWDATA_BITSPERBYTE, RAWDATA_MASK, SPECIALSPACE_JOIN, SPECIALSPACE_STACK,
    TYPECODE_ADDRESSSPACE, TYPECODE_BOOLEAN, TYPECODE_SHIFT, TYPECODE_SIGNEDINT_NEGATIVE,
    TYPECODE_SIGNEDINT_POSITIVE, TYPECODE_SPECIALSPACE, TYPECODE_STRING, TYPECODE_UNSIGNEDINT,
};
use crate::MAX_ELEMENT_DEPTH;
use crate::decoder::Decoder;
use crate::error::{AttributeKind, DecodeError};
use crate::ids::{ATTRIB_UNKNOWN, AttrCode, AttributeId, ElemCode, ElementId};
use crate::space::{SpaceId, SpaceResolver};

/// Decodes a document in the packed form from a byte slice (Ghidra
/// `PackedDecode`).
pub struct PackedDecoder<'a> {
    bytes: &'a [u8],
    spaces: &'a dyn SpaceResolver,
    /// Start of the current element's attributes (Ghidra `startPos`).
    start: usize,
    /// The attribute `next_attribute` returned last, or the one it will
    /// return next (Ghidra `curPos`).
    cur: usize,
    /// End of the current element's attributes: its next child or its end
    /// record (Ghidra `endPos`).
    end: usize,
    /// The attribute at `cur` has been consumed (Ghidra `attributeRead`).
    attribute_read: bool,
    /// The attributes between `start` and `end` belong to the current
    /// element. False once a child has been closed.
    attributes_open: bool,
    depth: usize,
    /// Ids of the elements being skipped by `close_element_skipping`.
    skipping: Vec<u32>,
}

impl std::fmt::Debug for PackedDecoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackedDecoder")
            .field("len", &self.bytes.len())
            .field("position", &self.end)
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}

impl<'a> PackedDecoder<'a> {
    /// Creates a decoder positioned before the first element in `bytes`.
    /// `spaces` resolves the indices in address-space attributes.
    pub fn new(bytes: &'a [u8], spaces: &'a dyn SpaceResolver) -> Self {
        Self {
            bytes,
            spaces,
            start: 0,
            cur: 0,
            end: 0,
            attribute_read: true,
            attributes_open: false,
            depth: 0,
            skipping: Vec::new(),
        }
    }

    /// The offset of the next record after the current element's attributes:
    /// once the root element is closed, the number of bytes the document
    /// occupies.
    pub fn position(&self) -> usize {
        self.end
    }

    /// The byte at `pos`, or the padding byte at the end of the data.
    fn peek(&self, pos: usize) -> u8 {
        self.bytes.get(pos).copied().unwrap_or(ELEMENT_END)
    }

    /// Consumes the byte at `*pos`. The padding byte cannot be consumed.
    fn take(&self, pos: &mut usize) -> Result<u8, DecodeError> {
        let byte = *self
            .bytes
            .get(*pos)
            .ok_or(DecodeError::UnexpectedEof { offset: *pos })?;
        *pos += 1;
        Ok(byte)
    }

    /// The id in the header at `pos`, without consuming it.
    fn peek_id(&self, pos: usize, header: u8) -> u32 {
        let mut id = u32::from(header & ELEMENTID_MASK);
        if header & HEADEREXTEND_MASK != 0 {
            id = (id << RAWDATA_BITSPERBYTE) | u32::from(self.peek(pos + 1) & RAWDATA_MASK);
        }
        id
    }

    /// Reads `length` seven-bit groups at `*pos`, most significant first.
    fn read_integer(&self, pos: &mut usize, length: u8) -> Result<u64, DecodeError> {
        let end = *pos + usize::from(length);
        let groups = self
            .bytes
            .get(*pos..end)
            .ok_or(DecodeError::UnexpectedEof {
                offset: self.bytes.len(),
            })?;
        *pos = end;
        // More than ten groups overflow; the excess high bits are dropped, as
        // in Ghidra.
        Ok(groups.iter().fold(0u64, |value, &byte| {
            (value << RAWDATA_BITSPERBYTE) | u64::from(byte & RAWDATA_MASK)
        }))
    }

    /// Moves `*pos` forward over `count` data bytes.
    fn advance(&self, pos: &mut usize, count: u64) -> Result<(), DecodeError> {
        let eof = DecodeError::UnexpectedEof {
            offset: self.bytes.len(),
        };
        let count = usize::try_from(count).map_err(|_| eof.clone())?;
        let target = pos
            .checked_add(count)
            .filter(|&target| target <= self.bytes.len())
            .ok_or(eof)?;
        *pos = target;
        Ok(())
    }

    /// Skips what follows the type byte of an attribute.
    fn skip_value(&self, pos: &mut usize, type_byte: u8) -> Result<(), DecodeError> {
        let type_code = type_byte >> TYPECODE_SHIFT;
        if type_code == TYPECODE_BOOLEAN || type_code == TYPECODE_SPECIALSPACE {
            return Ok(());
        }
        let length_code = type_byte & LENGTHCODE_MASK;
        let length = if type_code == TYPECODE_STRING {
            self.read_integer(pos, length_code)?
        } else {
            u64::from(length_code)
        };
        self.advance(pos, length)
    }

    /// Consumes an attribute's header and returns its type byte and the
    /// offset of that byte.
    fn take_type(&self, pos: &mut usize) -> Result<(u8, usize), DecodeError> {
        let header = self.take(pos)?;
        if header & HEADEREXTEND_MASK != 0 {
            self.take(pos)?;
        }
        let offset = *pos;
        Ok((self.take(pos)?, offset))
    }

    /// Skips the whole attribute at `*pos`.
    fn skip_attribute(&self, pos: &mut usize) -> Result<(), DecodeError> {
        let (type_byte, _) = self.take_type(pos)?;
        self.skip_value(pos, type_byte)
    }

    /// Opens the element at `end` without the depth check.
    fn open_next(&mut self) -> Result<Option<u32>, DecodeError> {
        let header = self.peek(self.end);
        if header & HEADER_MASK != ELEMENT_START {
            return Ok(None);
        }
        let mut pos = self.end;
        self.take(&mut pos)?;
        let mut id = u32::from(header & ELEMENTID_MASK);
        if header & HEADEREXTEND_MASK != 0 {
            id = (id << RAWDATA_BITSPERBYTE) | u32::from(self.take(&mut pos)? & RAWDATA_MASK);
        }
        self.start = pos;
        self.end = pos;
        while self.peek(pos) & HEADER_MASK == ATTRIBUTE {
            self.skip_attribute(&mut pos)?;
        }
        self.end = pos;
        self.cur = self.start;
        self.attribute_read = true;
        self.attributes_open = true;
        self.depth += 1;
        Ok(Some(id))
    }

    /// Consumes the end record at `end`, which must carry the id `expected`.
    fn close_next(&mut self, expected: u32) -> Result<(), DecodeError> {
        let offset = self.end;
        let mut pos = self.end;
        let header = self.take(&mut pos)?;
        self.end = pos;
        match header & HEADER_MASK {
            ELEMENT_END => {}
            ELEMENT_START => {
                return Err(DecodeError::UnreadChildren {
                    element: format!("id {expected}"),
                });
            }
            _ => return Err(DecodeError::CorruptStream { offset }),
        }
        let mut found = u32::from(header & ELEMENTID_MASK);
        if header & HEADEREXTEND_MASK != 0 {
            found = (found << RAWDATA_BITSPERBYTE) | u32::from(self.take(&mut pos)? & RAWDATA_MASK);
            self.end = pos;
        }
        if found != expected {
            return Err(DecodeError::CloseMismatch { expected, found });
        }
        self.attributes_open = false;
        self.attribute_read = true;
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }

    /// Fails unless `next_attribute` has returned an attribute that has not
    /// been read yet.
    fn require_current(&self) -> Result<(), DecodeError> {
        if self.attributes_open && !self.attribute_read {
            Ok(())
        } else {
            Err(DecodeError::NoCurrentAttribute)
        }
    }

    /// Positions `cur` on the attribute with the given id.
    fn find(&mut self, attribute: AttributeId) -> Result<(), DecodeError> {
        if !self.attributes_open {
            return Err(if self.depth == 0 {
                DecodeError::NoOpenElement
            } else {
                DecodeError::AttributesUnavailable
            });
        }
        let mut pos = self.start;
        self.cur = self.start;
        self.attribute_read = true;
        loop {
            let header = self.peek(pos);
            if header & HEADER_MASK != ATTRIBUTE {
                return Err(DecodeError::AttributeMissing {
                    name: attribute.name(),
                });
            }
            if self.peek_id(pos, header) == attribute.id() {
                self.cur = pos;
                return Ok(());
            }
            self.skip_attribute(&mut pos)?;
        }
    }

    /// Runs `read` on the attribute with the given id, then resets iteration.
    fn with_attribute<T>(
        &mut self,
        attribute: AttributeId,
        read: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        self.find(attribute)?;
        let result = read(self);
        self.cur = self.start;
        self.attribute_read = true;
        result
    }

    /// Consumes the header of the attribute at `cur`; the attribute counts as
    /// read from here on, whatever its type turns out to be.
    fn begin_value(&mut self) -> Result<(u8, usize), DecodeError> {
        let mut pos = self.cur;
        let taken = self.take_type(&mut pos);
        self.cur = pos;
        self.attribute_read = true;
        taken
    }

    /// Skips the rest of an attribute of the wrong type and reports it.
    fn wrong_kind<T>(
        &mut self,
        expected: AttributeKind,
        type_byte: u8,
        offset: usize,
    ) -> Result<T, DecodeError> {
        let mut pos = self.cur;
        self.skip_value(&mut pos, type_byte)?;
        self.cur = pos;
        Err(DecodeError::WrongAttributeKind { expected, offset })
    }

    fn integer_value(&mut self, type_byte: u8) -> Result<u64, DecodeError> {
        let mut pos = self.cur;
        let value = self.read_integer(&mut pos, type_byte & LENGTHCODE_MASK);
        self.cur = pos;
        value
    }

    fn bool_value(&mut self) -> Result<bool, DecodeError> {
        let (type_byte, offset) = self.begin_value()?;
        if type_byte >> TYPECODE_SHIFT != TYPECODE_BOOLEAN {
            return self.wrong_kind(AttributeKind::Boolean, type_byte, offset);
        }
        Ok(type_byte & LENGTHCODE_MASK != 0)
    }

    fn signed_value(&mut self) -> Result<i64, DecodeError> {
        let (type_byte, offset) = self.begin_value()?;
        match type_byte >> TYPECODE_SHIFT {
            TYPECODE_SIGNEDINT_POSITIVE => Ok(self.integer_value(type_byte)?.cast_signed()),
            TYPECODE_SIGNEDINT_NEGATIVE => {
                Ok(self.integer_value(type_byte)?.cast_signed().wrapping_neg())
            }
            _ => self.wrong_kind(AttributeKind::SignedInteger, type_byte, offset),
        }
    }

    fn unsigned_value(&mut self) -> Result<u64, DecodeError> {
        let (type_byte, offset) = self.begin_value()?;
        if type_byte >> TYPECODE_SHIFT != TYPECODE_UNSIGNEDINT {
            return self.wrong_kind(AttributeKind::UnsignedInteger, type_byte, offset);
        }
        self.integer_value(type_byte)
    }

    fn string_value(&mut self) -> Result<&'a str, DecodeError> {
        let (type_byte, offset) = self.begin_value()?;
        if type_byte >> TYPECODE_SHIFT != TYPECODE_STRING {
            return self.wrong_kind(AttributeKind::String, type_byte, offset);
        }
        let length = self.integer_value(type_byte)?;
        let begin = self.cur;
        let mut pos = self.cur;
        self.advance(&mut pos, length)?;
        self.cur = pos;
        let bytes = self.bytes.get(begin..pos).unwrap_or_default();
        std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { offset: begin })
    }

    fn space_value(&mut self) -> Result<SpaceId, DecodeError> {
        let (type_byte, offset) = self.begin_value()?;
        match type_byte >> TYPECODE_SHIFT {
            TYPECODE_ADDRESSSPACE => {
                let index = self.integer_value(type_byte)?;
                if index >= self.spaces.space_count() {
                    return Err(DecodeError::InvalidSpaceIndex(index));
                }
                self.spaces
                    .space_by_index(index)
                    .ok_or(DecodeError::UnknownSpaceIndex(index))
            }
            TYPECODE_SPECIALSPACE => {
                let code = type_byte & LENGTHCODE_MASK;
                let space = match code {
                    SPECIALSPACE_STACK => self.spaces.stack_space(),
                    SPECIALSPACE_JOIN => self.spaces.join_space(),
                    _ => None,
                };
                space.ok_or(DecodeError::UnsupportedSpecialSpace(code))
            }
            _ => self.wrong_kind(AttributeKind::Space, type_byte, offset),
        }
    }

    fn signed_or_string_value(&mut self, expect: &str, value: i64) -> Result<i64, DecodeError> {
        let mut pos = self.cur;
        let (type_byte, _) = self.take_type(&mut pos)?;
        if type_byte >> TYPECODE_SHIFT != TYPECODE_STRING {
            return self.signed_value();
        }
        let found = self.string_value()?;
        if found == expect {
            Ok(value)
        } else {
            Err(DecodeError::UnexpectedString {
                expected: expect.to_owned(),
                found: found.to_owned(),
            })
        }
    }
}

impl<'a> Decoder<'a> for PackedDecoder<'a> {
    fn peek_element(&self) -> Option<ElemCode> {
        let header = self.peek(self.end);
        (header & HEADER_MASK == ELEMENT_START)
            .then(|| ElemCode::new(self.peek_id(self.end, header)))
    }

    fn open_element(&mut self) -> Result<Option<ElemCode>, DecodeError> {
        if self.depth >= MAX_ELEMENT_DEPTH && self.peek(self.end) & HEADER_MASK == ELEMENT_START {
            return Err(DecodeError::TooDeep {
                limit: MAX_ELEMENT_DEPTH,
            });
        }
        Ok(self.open_next()?.map(ElemCode::new))
    }

    fn open_element_expecting(&mut self, element: ElementId) -> Result<ElemCode, DecodeError> {
        match self.open_element()? {
            None => Err(DecodeError::NoElement {
                expected: element.name(),
            }),
            Some(found) if found == element => Ok(found),
            Some(found) => Err(DecodeError::ElementMismatch {
                expected: element.name(),
                found: format!("id {}", found.get()),
            }),
        }
    }

    fn close_element(&mut self, element: ElemCode) -> Result<(), DecodeError> {
        self.close_next(element.get())
    }

    fn close_element_skipping(&mut self, element: ElemCode) -> Result<(), DecodeError> {
        self.skipping.clear();
        self.skipping.push(element.get());
        while let Some(&innermost) = self.skipping.last() {
            match self.peek(self.end) & HEADER_MASK {
                ELEMENT_END => {
                    self.close_next(innermost)?;
                    self.skipping.pop();
                }
                ELEMENT_START => {
                    if let Some(child) = self.open_next()? {
                        self.skipping.push(child);
                    }
                }
                _ => return Err(DecodeError::CorruptStream { offset: self.end }),
            }
        }
        Ok(())
    }

    fn next_attribute(&mut self) -> Result<Option<AttrCode>, DecodeError> {
        if !self.attributes_open {
            return Ok(None);
        }
        if !self.attribute_read {
            let mut pos = self.cur;
            let skipped = self.skip_attribute(&mut pos);
            self.cur = pos;
            self.attribute_read = true;
            skipped?;
        }
        let header = self.peek(self.cur);
        if header & HEADER_MASK != ATTRIBUTE {
            return Ok(None);
        }
        self.attribute_read = false;
        Ok(Some(AttrCode::new(self.peek_id(self.cur, header))))
    }

    fn indexed_attribute(&mut self, _base: AttributeId) -> Result<AttrCode, DecodeError> {
        // The packed form stores indexed attributes under their own ids, so
        // there is never anything to reinterpret.
        Ok(ATTRIB_UNKNOWN.code())
    }

    fn rewind_attributes(&mut self) {
        self.cur = self.start;
        self.attribute_read = true;
    }

    fn read_bool(&mut self) -> Result<bool, DecodeError> {
        self.require_current()?;
        self.bool_value()
    }

    fn read_bool_attr(&mut self, attribute: AttributeId) -> Result<bool, DecodeError> {
        self.with_attribute(attribute, Self::bool_value)
    }

    fn read_signed(&mut self) -> Result<i64, DecodeError> {
        self.require_current()?;
        self.signed_value()
    }

    fn read_signed_attr(&mut self, attribute: AttributeId) -> Result<i64, DecodeError> {
        self.with_attribute(attribute, Self::signed_value)
    }

    fn read_signed_or_string(&mut self, expect: &str, value: i64) -> Result<i64, DecodeError> {
        self.require_current()?;
        self.signed_or_string_value(expect, value)
    }

    fn read_signed_or_string_attr(
        &mut self,
        attribute: AttributeId,
        expect: &str,
        value: i64,
    ) -> Result<i64, DecodeError> {
        self.with_attribute(attribute, |decoder| {
            decoder.signed_or_string_value(expect, value)
        })
    }

    fn read_unsigned(&mut self) -> Result<u64, DecodeError> {
        self.require_current()?;
        self.unsigned_value()
    }

    fn read_unsigned_attr(&mut self, attribute: AttributeId) -> Result<u64, DecodeError> {
        self.with_attribute(attribute, Self::unsigned_value)
    }

    fn read_string(&mut self) -> Result<&'a str, DecodeError> {
        self.require_current()?;
        self.string_value()
    }

    fn read_string_attr(&mut self, attribute: AttributeId) -> Result<&'a str, DecodeError> {
        self.with_attribute(attribute, Self::string_value)
    }

    fn read_space(&mut self) -> Result<SpaceId, DecodeError> {
        self.require_current()?;
        self.space_value()
    }

    fn read_space_attr(&mut self, attribute: AttributeId) -> Result<SpaceId, DecodeError> {
        self.with_attribute(attribute, Self::space_value)
    }

    fn read_enum(&mut self, _by_name: &dyn Fn(&str) -> Option<i64>) -> Result<i64, DecodeError> {
        self.require_current()?;
        self.signed_value()
    }

    fn read_enum_attr(
        &mut self,
        attribute: AttributeId,
        _by_name: &dyn Fn(&str) -> Option<i64>,
    ) -> Result<i64, DecodeError> {
        self.with_attribute(attribute, Self::signed_value)
    }
}
