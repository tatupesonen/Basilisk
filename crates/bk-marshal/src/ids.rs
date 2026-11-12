//! Element and attribute ids, and the name lookup table for a scope.
//!
//! Ghidra: `AttributeId` and `ElementId` in `marshal.hh`/`marshal.cc`. An id
//! is a name plus a number: the XML form writes the name, the packed form the
//! number. Ghidra registers every id in a process-wide table through static
//! constructors; here an id is a `const` value, each crate lists its ids in a
//! static slice, and an [`IdTable`] is built once from the slices that make up
//! a scope (the default scope, or the SLEIGH format scope with its own
//! numbering).

use std::collections::HashMap;
use std::hash::Hasher;

macro_rules! define_id {
    (
        $(#[$id_doc:meta])* $id:ident,
        $(#[$code_doc:meta])* $code:ident
    ) => {
        $(#[$id_doc])*
        #[derive(Clone, Copy, Debug)]
        pub struct $id {
            name: &'static str,
            id: u32,
        }

        impl $id {
            /// Defines an id from its name and number. Both must equal Ghidra's.
            pub const fn new(name: &'static str, id: u32) -> Self {
                Self { name, id }
            }

            /// The name, as written in the XML form.
            pub const fn name(&self) -> &'static str {
                self.name
            }

            /// The number, as written in the packed form.
            pub const fn id(&self) -> u32 {
                self.id
            }

            /// The number as the code a decoder returns.
            pub const fn code(&self) -> $code {
                $code(self.id)
            }
        }

        /// Ids are equal when their numbers are, as in Ghidra.
        impl PartialEq for $id {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }

        impl Eq for $id {}

        impl std::hash::Hash for $id {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.id.hash(state);
            }
        }

        $(#[$code_doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $code(u32);

        impl $code {
            /// Wraps a raw number read from a stream.
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            /// The raw number.
            pub const fn get(self) -> u32 {
                self.0
            }
        }

        impl PartialEq<$id> for $code {
            fn eq(&self, other: &$id) -> bool {
                self.0 == other.id
            }
        }

        impl PartialEq<$code> for $id {
            fn eq(&self, other: &$code) -> bool {
                self.id == other.0
            }
        }

        impl From<$id> for $code {
            fn from(id: $id) -> Self {
                id.code()
            }
        }
    };
}

define_id!(
    /// The definition of an attribute: its name and number (Ghidra `AttributeId`).
    AttributeId,
    /// The number of an attribute as it appears in a document. Compare it with
    /// an [`AttributeId`] using `==`.
    AttrCode
);

define_id!(
    /// The definition of an element: its name and number (Ghidra `ElementId`).
    ElementId,
    /// The number of an element as it appears in a document. Compare it with
    /// an [`ElementId`] using `==`.
    ElemCode
);

impl AttributeId {
    /// The code of the `index`-th member of an indexed attribute family, such
    /// as `piece1`, `piece2`, … (index 0 is the base id itself).
    pub const fn indexed(&self, index: u32) -> AttrCode {
        AttrCode(self.id.wrapping_add(index))
    }
}

/// Stands for an attribute whose name is not registered.
///
/// Its number is the next free slot in Ghidra's default scope (161 at the
/// pinned commit), not 0: 0 means "no more attributes" in Ghidra's decoder and
/// is `None` here.
pub const ATTRIB_UNKNOWN: AttributeId = AttributeId::new("XMLunknown", 161);
/// Stands for an element's text content in the XML form; an ordinary attribute
/// in the packed form.
pub const ATTRIB_CONTENT: AttributeId = AttributeId::new("XMLcontent", 1);
/// Marshalling attribute `align`.
pub const ATTRIB_ALIGN: AttributeId = AttributeId::new("align", 2);
/// Marshalling attribute `bigendian`.
pub const ATTRIB_BIGENDIAN: AttributeId = AttributeId::new("bigendian", 3);
/// Marshalling attribute `constructor`.
pub const ATTRIB_CONSTRUCTOR: AttributeId = AttributeId::new("constructor", 4);
/// Marshalling attribute `destructor`.
pub const ATTRIB_DESTRUCTOR: AttributeId = AttributeId::new("destructor", 5);
/// Marshalling attribute `extrapop`.
pub const ATTRIB_EXTRAPOP: AttributeId = AttributeId::new("extrapop", 6);
/// Marshalling attribute `format`.
pub const ATTRIB_FORMAT: AttributeId = AttributeId::new("format", 7);
/// Marshalling attribute `hiddenretparm`.
pub const ATTRIB_HIDDENRETPARM: AttributeId = AttributeId::new("hiddenretparm", 8);
/// Marshalling attribute `id`.
pub const ATTRIB_ID: AttributeId = AttributeId::new("id", 9);
/// Marshalling attribute `index`.
pub const ATTRIB_INDEX: AttributeId = AttributeId::new("index", 10);
/// Marshalling attribute `indirectstorage`.
pub const ATTRIB_INDIRECTSTORAGE: AttributeId = AttributeId::new("indirectstorage", 11);
/// Marshalling attribute `metatype`.
pub const ATTRIB_METATYPE: AttributeId = AttributeId::new("metatype", 12);
/// Marshalling attribute `model`.
pub const ATTRIB_MODEL: AttributeId = AttributeId::new("model", 13);
/// Marshalling attribute `name`.
pub const ATTRIB_NAME: AttributeId = AttributeId::new("name", 14);
/// Marshalling attribute `namelock`.
pub const ATTRIB_NAMELOCK: AttributeId = AttributeId::new("namelock", 15);
/// Marshalling attribute `offset`.
pub const ATTRIB_OFFSET: AttributeId = AttributeId::new("offset", 16);
/// Marshalling attribute `readonly`.
pub const ATTRIB_READONLY: AttributeId = AttributeId::new("readonly", 17);
/// Marshalling attribute `ref`.
pub const ATTRIB_REF: AttributeId = AttributeId::new("ref", 18);
/// Marshalling attribute `size`.
pub const ATTRIB_SIZE: AttributeId = AttributeId::new("size", 19);
/// Marshalling attribute `space`.
pub const ATTRIB_SPACE: AttributeId = AttributeId::new("space", 20);
/// Marshalling attribute `thisptr`.
pub const ATTRIB_THISPTR: AttributeId = AttributeId::new("thisptr", 21);
/// Marshalling attribute `type`.
pub const ATTRIB_TYPE: AttributeId = AttributeId::new("type", 22);
/// Marshalling attribute `typelock`.
pub const ATTRIB_TYPELOCK: AttributeId = AttributeId::new("typelock", 23);
/// Marshalling attribute `val`.
pub const ATTRIB_VAL: AttributeId = AttributeId::new("val", 24);
/// Marshalling attribute `value`.
pub const ATTRIB_VALUE: AttributeId = AttributeId::new("value", 25);
/// Marshalling attribute `wordsize`.
pub const ATTRIB_WORDSIZE: AttributeId = AttributeId::new("wordsize", 26);
/// Marshalling attribute `storage`.
pub const ATTRIB_STORAGE: AttributeId = AttributeId::new("storage", 149);
/// Marshalling attribute `stackspill`.
pub const ATTRIB_STACKSPILL: AttributeId = AttributeId::new("stackspill", 150);

/// Stands for an element whose name is not registered.
///
/// Its number is the next free slot in Ghidra's default scope (292 at the
/// pinned commit).
pub const ELEM_UNKNOWN: ElementId = ElementId::new("XMLunknown", 292);
/// Marshalling element `<data>`.
pub const ELEM_DATA: ElementId = ElementId::new("data", 1);
/// Marshalling element `<input>`.
pub const ELEM_INPUT: ElementId = ElementId::new("input", 2);
/// Marshalling element `<off>`.
pub const ELEM_OFF: ElementId = ElementId::new("off", 3);
/// Marshalling element `<output>`.
pub const ELEM_OUTPUT: ElementId = ElementId::new("output", 4);
/// Marshalling element `<returnaddress>`.
pub const ELEM_RETURNADDRESS: ElementId = ElementId::new("returnaddress", 5);
/// Marshalling element `<symbol>`.
pub const ELEM_SYMBOL: ElementId = ElementId::new("symbol", 6);
/// Marshalling element `<target>`.
pub const ELEM_TARGET: ElementId = ElementId::new("target", 7);
/// Marshalling element `<val>`.
pub const ELEM_VAL: ElementId = ElementId::new("val", 8);
/// Marshalling element `<value>`.
pub const ELEM_VALUE: ElementId = ElementId::new("value", 9);
/// Marshalling element `<void>`.
pub const ELEM_VOID: ElementId = ElementId::new("void", 10);

/// The attributes defined in Ghidra's `marshal.cc` (default scope).
pub static ATTRIBUTES: &[AttributeId] = &[
    ATTRIB_CONTENT,
    ATTRIB_ALIGN,
    ATTRIB_BIGENDIAN,
    ATTRIB_CONSTRUCTOR,
    ATTRIB_DESTRUCTOR,
    ATTRIB_EXTRAPOP,
    ATTRIB_FORMAT,
    ATTRIB_HIDDENRETPARM,
    ATTRIB_ID,
    ATTRIB_INDEX,
    ATTRIB_INDIRECTSTORAGE,
    ATTRIB_METATYPE,
    ATTRIB_MODEL,
    ATTRIB_NAME,
    ATTRIB_NAMELOCK,
    ATTRIB_OFFSET,
    ATTRIB_READONLY,
    ATTRIB_REF,
    ATTRIB_SIZE,
    ATTRIB_SPACE,
    ATTRIB_THISPTR,
    ATTRIB_TYPE,
    ATTRIB_TYPELOCK,
    ATTRIB_VAL,
    ATTRIB_VALUE,
    ATTRIB_WORDSIZE,
    ATTRIB_STORAGE,
    ATTRIB_STACKSPILL,
    ATTRIB_UNKNOWN,
];

/// The elements defined in Ghidra's `marshal.cc` (default scope).
pub static ELEMENTS: &[ElementId] = &[
    ELEM_DATA,
    ELEM_INPUT,
    ELEM_OFF,
    ELEM_OUTPUT,
    ELEM_RETURNADDRESS,
    ELEM_SYMBOL,
    ELEM_TARGET,
    ELEM_VAL,
    ELEM_VALUE,
    ELEM_VOID,
    ELEM_UNKNOWN,
];

/// A problem found while building an [`IdTable`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdTableError {
    /// Two attributes share a name but not a number. The XML form could not
    /// tell them apart.
    #[error("attribute `{name}` registered with ids {first} and {second}")]
    AttributeConflict {
        /// The shared name.
        name: &'static str,
        /// The number registered first.
        first: u32,
        /// The conflicting number.
        second: u32,
    },
    /// Two elements share a name but not a number.
    #[error("element `{name}` registered with ids {first} and {second}")]
    ElementConflict {
        /// The shared name.
        name: &'static str,
        /// The number registered first.
        first: u32,
        /// The conflicting number.
        second: u32,
    },
}

/// The name lookup table of one id scope: built once, immutable afterwards.
///
/// Each crate contributes the static slices of ids it defines. A table for
/// Ghidra's default scope combines [`ATTRIBUTES`] and [`ELEMENTS`] with the
/// slices of every other crate whose documents are to be read; the SLEIGH
/// format scope is a separate table with its own numbering. Lookup by name is
/// a hash lookup, as the XML decoder calls it for every element and attribute.
#[derive(Debug, Clone)]
pub struct IdTable {
    attributes: NameMap,
    elements: NameMap,
    attribute_names: Vec<(u32, &'static str)>,
    element_names: Vec<(u32, &'static str)>,
    unknown_attribute: AttrCode,
    unknown_element: ElemCode,
}

type NameMap = HashMap<&'static str, u32>;

impl IdTable {
    /// Builds a table from the id slices of a scope.
    ///
    /// The same id may appear more than once; a name registered with two
    /// different numbers is an error (Ghidra checks this only in debug
    /// builds). Names that are not registered resolve to [`ATTRIB_UNKNOWN`]
    /// and [`ELEM_UNKNOWN`].
    pub fn new(
        attributes: &[&[AttributeId]],
        elements: &[&[ElementId]],
    ) -> Result<Self, IdTableError> {
        let mut attribute_map = NameMap::default();
        for id in attributes.iter().copied().flatten() {
            if let Some(&first) = attribute_map.get(id.name()) {
                if first != id.id() {
                    return Err(IdTableError::AttributeConflict {
                        name: id.name(),
                        first,
                        second: id.id(),
                    });
                }
            } else {
                attribute_map.insert(id.name(), id.id());
            }
        }
        let mut element_map = NameMap::default();
        for id in elements.iter().copied().flatten() {
            if let Some(&first) = element_map.get(id.name()) {
                if first != id.id() {
                    return Err(IdTableError::ElementConflict {
                        name: id.name(),
                        first,
                        second: id.id(),
                    });
                }
            } else {
                element_map.insert(id.name(), id.id());
            }
        }
        let attribute_names = reverse(&attribute_map);
        let element_names = reverse(&element_map);
        Ok(Self {
            attributes: attribute_map,
            elements: element_map,
            attribute_names,
            element_names,
            unknown_attribute: ATTRIB_UNKNOWN.code(),
            unknown_element: ELEM_UNKNOWN.code(),
        })
    }

    /// A table holding only the ids of `marshal.cc`.
    pub fn marshal_only() -> Self {
        // The built-in slices carry no conflicting names (checked by a unit
        // test), so the fallback is never taken.
        Self::new(&[ATTRIBUTES], &[ELEMENTS]).unwrap_or_else(|_| Self {
            attributes: NameMap::default(),
            elements: NameMap::default(),
            attribute_names: Vec::new(),
            element_names: Vec::new(),
            unknown_attribute: ATTRIB_UNKNOWN.code(),
            unknown_element: ELEM_UNKNOWN.code(),
        })
    }

    /// Replaces the codes returned for names that are not registered.
    #[must_use]
    pub fn with_unknown(mut self, attribute: AttrCode, element: ElemCode) -> Self {
        self.unknown_attribute = attribute;
        self.unknown_element = element;
        self
    }

    /// The code of the attribute called `name`, or the unknown-attribute code.
    pub fn attribute(&self, name: &str) -> AttrCode {
        self.attributes
            .get(name)
            .map_or(self.unknown_attribute, |&id| AttrCode(id))
    }

    /// The code of the element called `name`, or the unknown-element code.
    pub fn element(&self, name: &str) -> ElemCode {
        self.elements
            .get(name)
            .map_or(self.unknown_element, |&id| ElemCode(id))
    }

    /// The name registered for an attribute code, for diagnostics.
    pub fn attribute_name(&self, code: AttrCode) -> Option<&'static str> {
        lookup_name(&self.attribute_names, code.get())
    }

    /// The name registered for an element code, for diagnostics.
    pub fn element_name(&self, code: ElemCode) -> Option<&'static str> {
        lookup_name(&self.element_names, code.get())
    }

    /// The code returned for attribute names that are not registered.
    pub fn unknown_attribute(&self) -> AttrCode {
        self.unknown_attribute
    }

    /// The code returned for element names that are not registered.
    pub fn unknown_element(&self) -> ElemCode {
        self.unknown_element
    }

    /// The number of attribute names registered.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// The number of element names registered.
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }
}

fn reverse(map: &NameMap) -> Vec<(u32, &'static str)> {
    let mut names: Vec<(u32, &'static str)> = map.iter().map(|(&name, &id)| (id, name)).collect();
    // Two names may share a number across unrelated documents; keep the
    // alphabetically first so the result does not depend on hash order.
    names.sort_unstable();
    names.dedup_by_key(|entry| entry.0);
    names
}

fn lookup_name(names: &[(u32, &'static str)], id: u32) -> Option<&'static str> {
    let at = names.binary_search_by_key(&id, |entry| entry.0).ok()?;
    names.get(at).map(|entry| entry.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_compare_by_number() {
        assert_eq!(ATTRIB_NAME, AttributeId::new("other", 14));
        assert_ne!(ATTRIB_NAME, ATTRIB_SIZE);
        assert_eq!(ATTRIB_NAME.code(), ATTRIB_NAME);
        assert_eq!(ELEM_DATA, ELEM_DATA.code());
        assert_eq!(AttrCode::new(14), ATTRIB_NAME);
        assert_eq!(ATTRIB_NAME.indexed(3).get(), 17);
    }

    #[test]
    fn numbers_match_ghidra() {
        // Spot checks against marshal.cc; the full list is asserted below.
        assert_eq!(ATTRIB_CONTENT.id(), 1);
        assert_eq!(ATTRIB_WORDSIZE.id(), 26);
        assert_eq!(ATTRIB_STORAGE.id(), 149);
        assert_eq!(ATTRIB_STACKSPILL.id(), 150);
        assert_eq!(ATTRIB_UNKNOWN.id(), 161);
        assert_eq!(ELEM_VOID.id(), 10);
        assert_eq!(ELEM_UNKNOWN.id(), 292);
        let expected = [
            ("XMLcontent", 1),
            ("align", 2),
            ("bigendian", 3),
            ("constructor", 4),
            ("destructor", 5),
            ("extrapop", 6),
            ("format", 7),
            ("hiddenretparm", 8),
            ("id", 9),
            ("index", 10),
            ("indirectstorage", 11),
            ("metatype", 12),
            ("model", 13),
            ("name", 14),
            ("namelock", 15),
            ("offset", 16),
            ("readonly", 17),
            ("ref", 18),
            ("size", 19),
            ("space", 20),
            ("thisptr", 21),
            ("type", 22),
            ("typelock", 23),
            ("val", 24),
            ("value", 25),
            ("wordsize", 26),
            ("storage", 149),
            ("stackspill", 150),
            ("XMLunknown", 161),
        ];
        let actual: Vec<(&str, u32)> = ATTRIBUTES.iter().map(|a| (a.name(), a.id())).collect();
        assert_eq!(actual, expected);
        let expected = [
            ("data", 1),
            ("input", 2),
            ("off", 3),
            ("output", 4),
            ("returnaddress", 5),
            ("symbol", 6),
            ("target", 7),
            ("val", 8),
            ("value", 9),
            ("void", 10),
            ("XMLunknown", 292),
        ];
        let actual: Vec<(&str, u32)> = ELEMENTS.iter().map(|e| (e.name(), e.id())).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn table_resolves_names_and_unknowns() {
        let table = IdTable::new(&[ATTRIBUTES], &[ELEMENTS]).unwrap();
        assert_eq!(table.attribute("name"), ATTRIB_NAME);
        assert_eq!(table.attribute("XMLcontent"), ATTRIB_CONTENT);
        assert_eq!(table.attribute("nonesuch"), ATTRIB_UNKNOWN);
        assert_eq!(table.attribute(""), ATTRIB_UNKNOWN);
        assert_eq!(table.element("void"), ELEM_VOID);
        assert_eq!(table.element("nonesuch"), ELEM_UNKNOWN);
        assert_eq!(table.attribute_name(ATTRIB_NAME.code()), Some("name"));
        assert_eq!(table.element_name(ELEM_VOID.code()), Some("void"));
        assert_eq!(table.element_name(ElemCode::new(9999)), None);
        assert_eq!(table.attribute_count(), ATTRIBUTES.len());
        assert_eq!(table.element_count(), ELEMENTS.len());
    }

    #[test]
    fn marshal_only_is_complete() {
        let table = IdTable::marshal_only();
        assert_eq!(table.attribute_count(), ATTRIBUTES.len());
        assert_eq!(table.element_count(), ELEMENTS.len());
    }

    #[test]
    fn scopes_are_numbered_independently() {
        // The SLEIGH format scope reuses names with other numbers.
        const FORMAT_VAL: AttributeId = AttributeId::new("val", 2);
        const FORMAT_ELEM: ElementId = ElementId::new("sleigh", 1);
        let format = IdTable::new(&[&[FORMAT_VAL]], &[&[FORMAT_ELEM]]).unwrap();
        assert_eq!(format.attribute("val").get(), 2);
        assert_eq!(format.element("sleigh").get(), 1);
        let default = IdTable::marshal_only();
        assert_eq!(default.attribute("val"), ATTRIB_VAL);
    }

    #[test]
    fn conflicting_names_are_rejected() {
        const OTHER_NAME: AttributeId = AttributeId::new("name", 99);
        const OTHER_DATA: ElementId = ElementId::new("data", 77);
        let err = IdTable::new(&[ATTRIBUTES, &[OTHER_NAME]], &[]).unwrap_err();
        assert_eq!(
            err,
            IdTableError::AttributeConflict {
                name: "name",
                first: 14,
                second: 99
            }
        );
        let err = IdTable::new(&[], &[ELEMENTS, &[OTHER_DATA]]).unwrap_err();
        assert_eq!(
            err,
            IdTableError::ElementConflict {
                name: "data",
                first: 1,
                second: 77
            }
        );
        // Listing the same id twice is harmless.
        assert!(IdTable::new(&[ATTRIBUTES, ATTRIBUTES], &[ELEMENTS, ELEMENTS]).is_ok());
    }

    #[test]
    fn unknown_codes_can_be_replaced() {
        let table = IdTable::marshal_only().with_unknown(AttrCode::new(500), ElemCode::new(600));
        assert_eq!(table.attribute("nonesuch").get(), 500);
        assert_eq!(table.element("nonesuch").get(), 600);
        assert_eq!(table.unknown_attribute().get(), 500);
        assert_eq!(table.unknown_element().get(), 600);
    }
}
