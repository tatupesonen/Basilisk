//! The encoder interface shared by the XML and packed forms.
//!
//! Ghidra: `class Encoder` in `marshal.hh`.

use crate::error::EncodeError;
use crate::ids::{AttributeId, ElementId};
use crate::space::SpaceRef;

/// Writes structured data as a document in either marshalling form.
///
/// A document is written with nested [`Encoder::open_element`] and
/// [`Encoder::close_element`] calls. All attributes of an element are written
/// before its first child. The text content of an XML element is written with
/// the attribute [`ATTRIB_CONTENT`](crate::ids::ATTRIB_CONTENT), after the
/// element's other attributes.
///
/// As in Ghidra, the encoders do not check that opens and closes pair up; a
/// document closed in the wrong order is written as given.
pub trait Encoder {
    /// Begins a new element, which becomes the current element.
    fn open_element(&mut self, element: ElementId);

    /// Ends the current element.
    fn close_element(&mut self, element: ElementId);

    /// Writes a boolean attribute of the current element.
    fn write_bool(&mut self, attribute: AttributeId, value: bool);

    /// Writes a signed integer attribute of the current element.
    fn write_signed(&mut self, attribute: AttributeId, value: i64);

    /// Writes an unsigned integer attribute of the current element.
    fn write_unsigned(&mut self, attribute: AttributeId, value: u64);

    /// Writes a string attribute of the current element.
    fn write_string(&mut self, attribute: AttributeId, value: &str) -> Result<(), EncodeError>;

    /// Writes one member of an indexed attribute family (`piece1`, `piece2`,
    /// …). `index` starts at 0. The family occupies the ids from the base id
    /// upwards, so no other attribute with a larger id may be used in the same
    /// element.
    fn write_string_indexed(
        &mut self,
        attribute: AttributeId,
        index: u32,
        value: &str,
    ) -> Result<(), EncodeError>;

    /// Writes a reference to an address space.
    fn write_space(&mut self, attribute: AttributeId, space: &SpaceRef<'_>);

    /// Writes a member of a named enumeration: its name in the XML form, its
    /// number (which must not be negative) in the packed form. This is how
    /// Ghidra marshals p-code opcodes and data-type metatypes (`writeOpcode`,
    /// `writeDatatypeMeta`).
    fn write_enum(&mut self, attribute: AttributeId, value: u64, name: &str);
}
