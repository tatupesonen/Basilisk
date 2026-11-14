//! Element and attribute ids this crate reads and writes.
//!
//! Names and numbers are Ghidra's: those of `type.cc` first, then the few of
//! `address.cc`, `fspec.cc` and `jumptable.cc` that the type marshalling uses
//! (Ghidra defines each id once, in the file that owns it; no other crate of
//! basilisk defines these yet).

use bk_marshal::{AttributeId, ElementId, IdTable};

/// `alignment` (type.cc).
pub const ATTRIB_ALIGNMENT: AttributeId = AttributeId::new("alignment", 47);
/// `arraysize` (type.cc).
pub const ATTRIB_ARRAYSIZE: AttributeId = AttributeId::new("arraysize", 48);
/// `char` (type.cc).
pub const ATTRIB_CHAR: AttributeId = AttributeId::new("char", 49);
/// `core` (type.cc).
pub const ATTRIB_CORE: AttributeId = AttributeId::new("core", 50);
/// `incomplete` (type.cc).
pub const ATTRIB_INCOMPLETE: AttributeId = AttributeId::new("incomplete", 52);
/// `opaquestring` (type.cc).
pub const ATTRIB_OPAQUESTRING: AttributeId = AttributeId::new("opaquestring", 56);
/// `signed` (type.cc).
pub const ATTRIB_SIGNED: AttributeId = AttributeId::new("signed", 57);
/// `structalign` (type.cc).
pub const ATTRIB_STRUCTALIGN: AttributeId = AttributeId::new("structalign", 58);
/// `utf` (type.cc).
pub const ATTRIB_UTF: AttributeId = AttributeId::new("utf", 59);
/// `varlength` (type.cc).
pub const ATTRIB_VARLENGTH: AttributeId = AttributeId::new("varlength", 60);
/// `first` (address.cc).
pub const ATTRIB_FIRST: AttributeId = AttributeId::new("first", 27);
/// `label` (jumptable.cc).
pub const ATTRIB_LABEL: AttributeId = AttributeId::new("label", 131);
/// `custom` (fspec.cc).
pub const ATTRIB_CUSTOM: AttributeId = AttributeId::new("custom", 114);
/// `dotdotdot` (fspec.cc).
pub const ATTRIB_DOTDOTDOT: AttributeId = AttributeId::new("dotdotdot", 115);
/// `hasthis` (fspec.cc).
pub const ATTRIB_HASTHIS: AttributeId = AttributeId::new("hasthis", 117);
/// `inline` (fspec.cc).
pub const ATTRIB_INLINE: AttributeId = AttributeId::new("inline", 118);
/// `modellock` (fspec.cc).
pub const ATTRIB_MODELLOCK: AttributeId = AttributeId::new("modellock", 122);
/// `noreturn` (fspec.cc).
pub const ATTRIB_NORETURN: AttributeId = AttributeId::new("noreturn", 123);
/// `voidlock` (fspec.cc).
pub const ATTRIB_VOIDLOCK: AttributeId = AttributeId::new("voidlock", 129);

/// `<char_size>` (type.cc).
pub const ELEM_CHAR_SIZE: ElementId = ElementId::new("char_size", 39);
/// `<coretypes>` (type.cc).
pub const ELEM_CORETYPES: ElementId = ElementId::new("coretypes", 41);
/// `<data_organization>` (type.cc).
pub const ELEM_DATA_ORGANIZATION: ElementId = ElementId::new("data_organization", 42);
/// `<def>` (type.cc).
pub const ELEM_DEF: ElementId = ElementId::new("def", 43);
/// `<entry>` (type.cc).
pub const ELEM_ENTRY: ElementId = ElementId::new("entry", 47);
/// `<enum>` (type.cc).
pub const ELEM_ENUM: ElementId = ElementId::new("enum", 48);
/// `<field>` (type.cc).
pub const ELEM_FIELD: ElementId = ElementId::new("field", 49);
/// `<integer_size>` (type.cc).
pub const ELEM_INTEGER_SIZE: ElementId = ElementId::new("integer_size", 51);
/// `<long_size>` (type.cc).
pub const ELEM_LONG_SIZE: ElementId = ElementId::new("long_size", 54);
/// `<pointer_size>` (type.cc).
pub const ELEM_POINTER_SIZE: ElementId = ElementId::new("pointer_size", 57);
/// `<size_alignment_map>` (type.cc).
pub const ELEM_SIZE_ALIGNMENT_MAP: ElementId = ElementId::new("size_alignment_map", 59);
/// `<type>` (type.cc).
pub const ELEM_TYPE: ElementId = ElementId::new("type", 60);
/// `<typegrp>` (type.cc).
pub const ELEM_TYPEGRP: ElementId = ElementId::new("typegrp", 62);
/// `<typeref>` (type.cc).
pub const ELEM_TYPEREF: ElementId = ElementId::new("typeref", 63);
/// `<wchar_size>` (type.cc).
pub const ELEM_WCHAR_SIZE: ElementId = ElementId::new("wchar_size", 65);
/// `<bitfield>` (type.cc).
pub const ELEM_BITFIELD: ElementId = ElementId::new("bitfield", 289);
/// `<addr>` (address.cc).
pub const ELEM_ADDR: ElementId = ElementId::new("addr", 11);
/// `<prototype>` (fspec.cc).
pub const ELEM_PROTOTYPE: ElementId = ElementId::new("prototype", 169);
/// `<returnsym>` (fspec.cc).
pub const ELEM_RETURNSYM: ElementId = ElementId::new("returnsym", 172);
/// `<internallist>` (fspec.cc).
pub const ELEM_INTERNALLIST: ElementId = ElementId::new("internallist", 161);
/// `<param>` (fspec.cc).
pub const ELEM_PARAM: ElementId = ElementId::new("param", 166);

/// The attributes this crate contributes to the default id scope.
pub static ATTRIBUTES: &[AttributeId] = &[
    ATTRIB_ALIGNMENT,
    ATTRIB_ARRAYSIZE,
    ATTRIB_CHAR,
    ATTRIB_CORE,
    ATTRIB_INCOMPLETE,
    ATTRIB_OPAQUESTRING,
    ATTRIB_SIGNED,
    ATTRIB_STRUCTALIGN,
    ATTRIB_UTF,
    ATTRIB_VARLENGTH,
    ATTRIB_FIRST,
    ATTRIB_LABEL,
    ATTRIB_CUSTOM,
    ATTRIB_DOTDOTDOT,
    ATTRIB_HASTHIS,
    ATTRIB_INLINE,
    ATTRIB_MODELLOCK,
    ATTRIB_NORETURN,
    ATTRIB_VOIDLOCK,
];

/// The elements this crate contributes to the default id scope.
pub static ELEMENTS: &[ElementId] = &[
    ELEM_CHAR_SIZE,
    ELEM_CORETYPES,
    ELEM_DATA_ORGANIZATION,
    ELEM_DEF,
    ELEM_ENTRY,
    ELEM_ENUM,
    ELEM_FIELD,
    ELEM_INTEGER_SIZE,
    ELEM_LONG_SIZE,
    ELEM_POINTER_SIZE,
    ELEM_SIZE_ALIGNMENT_MAP,
    ELEM_TYPE,
    ELEM_TYPEGRP,
    ELEM_TYPEREF,
    ELEM_WCHAR_SIZE,
    ELEM_BITFIELD,
    ELEM_ADDR,
    ELEM_PROTOTYPE,
    ELEM_RETURNSYM,
    ELEM_INTERNALLIST,
    ELEM_PARAM,
];

/// An id table holding `marshal.cc`'s ids and this crate's.
pub fn id_table() -> IdTable {
    // The slices hold no conflicting names (checked by a test), so the
    // fallback is never taken.
    IdTable::new(
        &[bk_marshal::ids::ATTRIBUTES, ATTRIBUTES],
        &[bk_marshal::ids::ELEMENTS, ELEMENTS],
    )
    .unwrap_or_else(|_| IdTable::marshal_only())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_do_not_conflict() {
        assert!(
            bk_marshal::IdTable::new(
                &[bk_marshal::ids::ATTRIBUTES, super::ATTRIBUTES],
                &[bk_marshal::ids::ELEMENTS, super::ELEMENTS],
            )
            .is_ok()
        );
    }
}
