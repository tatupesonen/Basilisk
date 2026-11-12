//! The element and attribute ids defined in Ghidra's `space.cc`,
//! `address.cc` and `translate.cc` (default scope).
//!
//! `pcoderaw.cc` defines none of its own. Names and numbers equal Ghidra's.

use bk_marshal::{AttributeId, ElementId, IdTable};

/// Marshalling attribute `first` (`address.cc`).
pub const ATTRIB_FIRST: AttributeId = AttributeId::new("first", 27);
/// Marshalling attribute `last` (`address.cc`).
pub const ATTRIB_LAST: AttributeId = AttributeId::new("last", 28);
/// Marshalling attribute `uniq` (`address.cc`).
pub const ATTRIB_UNIQ: AttributeId = AttributeId::new("uniq", 29);
/// Marshalling attribute `code` (`translate.cc`).
pub const ATTRIB_CODE: AttributeId = AttributeId::new("code", 43);
/// Marshalling attribute `contain` (`translate.cc`).
pub const ATTRIB_CONTAIN: AttributeId = AttributeId::new("contain", 44);
/// Marshalling attribute `defaultspace` (`translate.cc`).
pub const ATTRIB_DEFAULTSPACE: AttributeId = AttributeId::new("defaultspace", 45);
/// Marshalling attribute `uniqbase` (`translate.cc`).
pub const ATTRIB_UNIQBASE: AttributeId = AttributeId::new("uniqbase", 46);
/// Marshalling attribute `base` (`space.cc`).
pub const ATTRIB_BASE: AttributeId = AttributeId::new("base", 89);
/// Marshalling attribute `deadcodedelay` (`space.cc`).
pub const ATTRIB_DEADCODEDELAY: AttributeId = AttributeId::new("deadcodedelay", 90);
/// Marshalling attribute `delay` (`space.cc`).
pub const ATTRIB_DELAY: AttributeId = AttributeId::new("delay", 91);
/// Marshalling attribute `logicalsize` (`space.cc`).
pub const ATTRIB_LOGICALSIZE: AttributeId = AttributeId::new("logicalsize", 92);
/// Marshalling attribute `physical` (`space.cc`).
pub const ATTRIB_PHYSICAL: AttributeId = AttributeId::new("physical", 93);
/// The indexed attribute family `piece1`, `piece2`, … of a join address
/// (`space.cc`). It occupies the ids from 94 upwards; Ghidra reserves 94 to
/// 102 for `piece1` to `piece9`, and longer joins run past that.
pub const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 94);

/// Marshalling element `<addr>` (`address.cc`).
pub const ELEM_ADDR: ElementId = ElementId::new("addr", 11);
/// Marshalling element `<range>` (`address.cc`).
pub const ELEM_RANGE: ElementId = ElementId::new("range", 12);
/// Marshalling element `<rangelist>` (`address.cc`).
pub const ELEM_RANGELIST: ElementId = ElementId::new("rangelist", 13);
/// Marshalling element `<register>` (`address.cc`).
pub const ELEM_REGISTER: ElementId = ElementId::new("register", 14);
/// Marshalling element `<seqnum>` (`address.cc`).
pub const ELEM_SEQNUM: ElementId = ElementId::new("seqnum", 15);
/// Marshalling element `<varnode>` (`address.cc`).
pub const ELEM_VARNODE: ElementId = ElementId::new("varnode", 16);
/// Marshalling element `<op>` (`translate.cc`).
pub const ELEM_OP: ElementId = ElementId::new("op", 27);
/// Marshalling element `<sleigh>` (`translate.cc`).
pub const ELEM_SLEIGH: ElementId = ElementId::new("sleigh", 28);
/// Marshalling element `<space>` (`translate.cc`).
pub const ELEM_SPACE: ElementId = ElementId::new("space", 29);
/// Marshalling element `<spaceid>` (`translate.cc`).
pub const ELEM_SPACEID: ElementId = ElementId::new("spaceid", 30);
/// Marshalling element `<spaces>` (`translate.cc`).
pub const ELEM_SPACES: ElementId = ElementId::new("spaces", 31);
/// Marshalling element `<space_base>` (`translate.cc`).
pub const ELEM_SPACE_BASE: ElementId = ElementId::new("space_base", 32);
/// Marshalling element `<space_other>` (`translate.cc`).
pub const ELEM_SPACE_OTHER: ElementId = ElementId::new("space_other", 33);
/// Marshalling element `<space_overlay>` (`translate.cc`).
pub const ELEM_SPACE_OVERLAY: ElementId = ElementId::new("space_overlay", 34);
/// Marshalling element `<space_unique>` (`translate.cc`).
pub const ELEM_SPACE_UNIQUE: ElementId = ElementId::new("space_unique", 35);
/// Marshalling element `<truncate_space>` (`translate.cc`).
pub const ELEM_TRUNCATE_SPACE: ElementId = ElementId::new("truncate_space", 36);

/// The attributes this crate defines.
pub static ATTRIBUTES: &[AttributeId] = &[
    ATTRIB_FIRST,
    ATTRIB_LAST,
    ATTRIB_UNIQ,
    ATTRIB_CODE,
    ATTRIB_CONTAIN,
    ATTRIB_DEFAULTSPACE,
    ATTRIB_UNIQBASE,
    ATTRIB_BASE,
    ATTRIB_DEADCODEDELAY,
    ATTRIB_DELAY,
    ATTRIB_LOGICALSIZE,
    ATTRIB_PHYSICAL,
    ATTRIB_PIECE,
];

/// The elements this crate defines.
pub static ELEMENTS: &[ElementId] = &[
    ELEM_ADDR,
    ELEM_RANGE,
    ELEM_RANGELIST,
    ELEM_REGISTER,
    ELEM_SEQNUM,
    ELEM_VARNODE,
    ELEM_OP,
    ELEM_SLEIGH,
    ELEM_SPACE,
    ELEM_SPACEID,
    ELEM_SPACES,
    ELEM_SPACE_BASE,
    ELEM_SPACE_OTHER,
    ELEM_SPACE_OVERLAY,
    ELEM_SPACE_UNIQUE,
    ELEM_TRUNCATE_SPACE,
];

/// A name table holding the ids of `bk-marshal` and of this crate: enough to
/// decode the XML forms of the types defined here. Crates higher up build
/// their own table from these slices plus theirs.
pub fn id_table() -> IdTable {
    // The slices are free of conflicting names (checked by a unit test), so
    // the fallback is never taken.
    IdTable::new(
        &[bk_marshal::ids::ATTRIBUTES, ATTRIBUTES],
        &[bk_marshal::ids::ELEMENTS, ELEMENTS],
    )
    .unwrap_or_else(|_| IdTable::marshal_only())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_match_ghidra() {
        let attributes: Vec<(&str, u32)> = ATTRIBUTES.iter().map(|a| (a.name(), a.id())).collect();
        assert_eq!(
            attributes,
            [
                ("first", 27),
                ("last", 28),
                ("uniq", 29),
                ("code", 43),
                ("contain", 44),
                ("defaultspace", 45),
                ("uniqbase", 46),
                ("base", 89),
                ("deadcodedelay", 90),
                ("delay", 91),
                ("logicalsize", 92),
                ("physical", 93),
                ("piece", 94),
            ]
        );
        let elements: Vec<(&str, u32)> = ELEMENTS.iter().map(|e| (e.name(), e.id())).collect();
        assert_eq!(
            elements,
            [
                ("addr", 11),
                ("range", 12),
                ("rangelist", 13),
                ("register", 14),
                ("seqnum", 15),
                ("varnode", 16),
                ("op", 27),
                ("sleigh", 28),
                ("space", 29),
                ("spaceid", 30),
                ("spaces", 31),
                ("space_base", 32),
                ("space_other", 33),
                ("space_overlay", 34),
                ("space_unique", 35),
                ("truncate_space", 36),
            ]
        );
    }

    #[test]
    fn table_combines_both_crates_without_conflict() {
        let table = IdTable::new(
            &[bk_marshal::ids::ATTRIBUTES, ATTRIBUTES],
            &[bk_marshal::ids::ELEMENTS, ELEMENTS],
        )
        .unwrap();
        assert_eq!(
            table.attribute_count(),
            bk_marshal::ids::ATTRIBUTES.len() + ATTRIBUTES.len()
        );
        assert_eq!(
            table.element_count(),
            bk_marshal::ids::ELEMENTS.len() + ELEMENTS.len()
        );
        let table = id_table();
        assert_eq!(table.element("addr"), ELEM_ADDR);
        assert_eq!(table.element("data"), bk_marshal::ids::ELEM_DATA);
        assert_eq!(table.attribute("piece"), ATTRIB_PIECE);
        assert_eq!(table.attribute("space"), bk_marshal::ids::ATTRIB_SPACE);
        // No id number is used twice within the scope.
        let mut numbers: Vec<u32> = bk_marshal::ids::ATTRIBUTES
            .iter()
            .chain(ATTRIBUTES)
            .map(AttributeId::id)
            .collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), table.attribute_count());
        let mut numbers: Vec<u32> = bk_marshal::ids::ELEMENTS
            .iter()
            .chain(ELEMENTS)
            .map(ElementId::id)
            .collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), table.element_count());
    }
}
