//! The decoder interface shared by the XML and packed forms.
//!
//! Ghidra: `class Decoder` in `marshal.hh`. A document is a tree of elements,
//! each with attributes and child elements. It is walked depth first with
//! [`Decoder::open_element`] and [`Decoder::close_element`]; the attributes of
//! the open element are either iterated with [`Decoder::next_attribute`] and
//! read with the plain `read_*` methods, or looked up by id with the
//! `read_*_attr` methods. As in Ghidra, a lookup by id restarts iteration in
//! the packed form and leaves it alone in the XML form, so the two styles are
//! not mixed within one pass over an element's attributes.
//!
//! Where Ghidra returns the id 0 for "nothing there", these methods return
//! `None`.

use crate::error::DecodeError;
use crate::ids::{AttrCode, AttributeId, ElemCode, ElementId};
use crate::space::SpaceId;

/// Reads structured data from a document in either marshalling form.
///
/// Both implementations give the same results for the same logical document.
/// `'a` is the lifetime of the document: strings are borrowed from it and stay
/// valid while decoding continues.
///
/// The text content of an XML element is the attribute
/// [`ATTRIB_CONTENT`](crate::ids::ATTRIB_CONTENT): it is read with a
/// `read_*_attr` call and never returned by [`Decoder::next_attribute`]. Code
/// that must work with both forms reads it before opening any child.
pub trait Decoder<'a> {
    /// The id of the next child of the current element, without opening it.
    /// `None` when no child remains.
    fn peek_element(&self) -> Option<ElemCode>;

    /// Opens the next child of the current element, which becomes the current
    /// element with its attributes ready for [`Decoder::next_attribute`].
    /// Returns `None`, opening nothing, when no child remains.
    fn open_element(&mut self) -> Result<Option<ElemCode>, DecodeError>;

    /// Opens the next child, which must be the given element.
    fn open_element_expecting(&mut self, element: ElementId) -> Result<ElemCode, DecodeError>;

    /// Closes the current element, whose id must be `element`. Fails if child
    /// elements remain unread.
    fn close_element(&mut self, element: ElemCode) -> Result<(), DecodeError>;

    /// Closes the current element, skipping any child elements not yet read.
    fn close_element_skipping(&mut self, element: ElemCode) -> Result<(), DecodeError>;

    /// Moves to the next attribute of the current element and returns its id,
    /// or `None` when all attributes have been visited.
    fn next_attribute(&mut self) -> Result<Option<AttrCode>, DecodeError>;

    /// Reinterprets the current attribute, for which
    /// [`Decoder::next_attribute`] returned the unknown-attribute code, as a
    /// member of the indexed family based at `base` (`piece1`, `piece2`, …).
    /// Returns the member's code, or the unknown-attribute code if the
    /// attribute does not belong to the family.
    fn indexed_attribute(&mut self, base: AttributeId) -> Result<AttrCode, DecodeError>;

    /// Restarts attribute iteration for the current element.
    fn rewind_attributes(&mut self);

    /// Reads the current attribute as a boolean.
    fn read_bool(&mut self) -> Result<bool, DecodeError>;

    /// Finds the given attribute in the current element and reads it as a
    /// boolean.
    fn read_bool_attr(&mut self, attribute: AttributeId) -> Result<bool, DecodeError>;

    /// Reads the current attribute as a signed integer.
    fn read_signed(&mut self) -> Result<i64, DecodeError>;

    /// Finds the given attribute and reads it as a signed integer.
    fn read_signed_attr(&mut self, attribute: AttributeId) -> Result<i64, DecodeError>;

    /// Reads the current attribute as a signed integer, accepting the string
    /// `expect` as a stand-in for `value`.
    fn read_signed_or_string(&mut self, expect: &str, value: i64) -> Result<i64, DecodeError>;

    /// Finds the given attribute and reads it as a signed integer, accepting
    /// the string `expect` as a stand-in for `value`.
    fn read_signed_or_string_attr(
        &mut self,
        attribute: AttributeId,
        expect: &str,
        value: i64,
    ) -> Result<i64, DecodeError>;

    /// Reads the current attribute as an unsigned integer.
    fn read_unsigned(&mut self) -> Result<u64, DecodeError>;

    /// Finds the given attribute and reads it as an unsigned integer.
    fn read_unsigned_attr(&mut self, attribute: AttributeId) -> Result<u64, DecodeError>;

    /// Reads the current attribute as a string borrowed from the document.
    fn read_string(&mut self) -> Result<&'a str, DecodeError>;

    /// Finds the given attribute and reads it as a string.
    fn read_string_attr(&mut self, attribute: AttributeId) -> Result<&'a str, DecodeError>;

    /// Reads the current attribute as an address space.
    fn read_space(&mut self) -> Result<SpaceId, DecodeError>;

    /// Finds the given attribute and reads it as an address space.
    fn read_space_attr(&mut self, attribute: AttributeId) -> Result<SpaceId, DecodeError>;

    /// Reads the current attribute as a member of a named enumeration.
    ///
    /// The XML form holds the member's name, which `by_name` maps to its
    /// number; the packed form holds the number as a non-negative signed
    /// integer. This is how Ghidra marshals p-code opcodes and data-type
    /// metatypes (`readOpcode`, `readDatatypeMeta`); the crates that own those
    /// enumerations build their readers on it.
    fn read_enum(&mut self, by_name: &dyn Fn(&str) -> Option<i64>) -> Result<i64, DecodeError>;

    /// Finds the given attribute and reads it as a member of a named
    /// enumeration (see [`Decoder::read_enum`]).
    fn read_enum_attr(
        &mut self,
        attribute: AttributeId,
        by_name: &dyn Fn(&str) -> Option<i64>,
    ) -> Result<i64, DecodeError>;

    /// Skips the element that the next [`Decoder::open_element`] would open,
    /// with everything inside it. Does nothing when no child remains.
    fn skip_element(&mut self) -> Result<(), DecodeError> {
        match self.open_element()? {
            Some(element) => self.close_element_skipping(element),
            None => Ok(()),
        }
    }
}
