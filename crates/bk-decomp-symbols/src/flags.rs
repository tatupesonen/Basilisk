//! The `Varnode` flag bits symbols and entries carry, the display flags and
//! the symbol categories (spec 4.1; `varnode.hh` 79–115, `database.hh`
//! 271–290).
//!
//! The values are Ghidra's. D05's varnode flags use the same bits; which
//! crate owns the shared type is open item 10.1 of the specification.

use bitflags::bitflags;

bitflags! {
    /// Ghidra's `Varnode` flags, the subset symbols, entries and property
    /// maps use (with their Ghidra values).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct VarnodeFlags: u32 {
        /// `input`.
        const INPUT = 0x08;
        /// `typelock`.
        const TYPELOCK = 0x100;
        /// `namelock`.
        const NAMELOCK = 0x200;
        /// `nolocalalias`.
        const NOLOCALALIAS = 0x400;
        /// `volatil`.
        const VOLATILE = 0x800;
        /// `externref`.
        const EXTERNREF = 0x1000;
        /// `readonly`.
        const READONLY = 0x2000;
        /// `persist`.
        const PERSIST = 0x4000;
        /// `addrtied`.
        const ADDRTIED = 0x8000;
        /// `unaffected`.
        const UNAFFECTED = 0x10000;
        /// `mapped`.
        const MAPPED = 0x20_0000;
        /// `indirect_creation`.
        const INDIRECT_CREATION = 0x40_0000;
        /// `return_address`.
        const RETURN_ADDRESS = 0x80_0000;
        /// `precislo`.
        const PRECISLO = 0x200_0000;
        /// `precishi`.
        const PRECISHI = 0x400_0000;
        /// `indirectstorage`.
        const INDIRECTSTORAGE = 0x800_0000;
        /// `hiddenretparm`.
        const HIDDENRETPARM = 0x1000_0000;
        /// `incidental_copy`.
        const INCIDENTAL_COPY = 0x2000_0000;
    }
}

impl VarnodeFlags {
    /// The attributes `setAttribute`/`clearAttribute` may change
    /// (database.cc:2352).
    pub const SETTABLE: Self = Self::TYPELOCK
        .union(Self::NAMELOCK)
        .union(Self::READONLY)
        .union(Self::INCIDENTAL_COPY)
        .union(Self::NOLOCALALIAS)
        .union(Self::VOLATILE)
        .union(Self::INDIRECTSTORAGE)
        .union(Self::HIDDENRETPARM);
}

/// Display flags of a symbol (Ghidra `Symbol::dispflags`).
pub mod disp {
    /// Mask of the display format (the low three bits).
    pub const FORMAT_MASK: u32 = 7;
    /// `force_hex`.
    pub const FORCE_HEX: u32 = 1;
    /// `force_dec`.
    pub const FORCE_DEC: u32 = 2;
    /// `force_oct`.
    pub const FORCE_OCT: u32 = 3;
    /// `force_bin`.
    pub const FORCE_BIN: u32 = 4;
    /// `force_char`.
    pub const FORCE_CHAR: u32 = 5;
    /// `size_typelock`: only the size of the type is locked.
    pub const SIZE_TYPELOCK: u32 = 8;
    /// `isolate`: not merged speculatively.
    pub const ISOLATE: u32 = 16;
    /// `merge_problems`.
    pub const MERGE_PROBLEMS: u32 = 32;
    /// `is_this_ptr`.
    pub const IS_THIS_PTR: u32 = 64;
}

/// Symbol categories (Ghidra `Symbol::no_category` …).
pub mod category {
    /// Not in a category.
    pub const NONE: i16 = -1;
    /// A function parameter.
    pub const FUNCTION_PARAMETER: i16 = 0;
    /// An equate.
    pub const EQUATE: i16 = 1;
    /// A union facet.
    pub const UNION_FACET: i16 = 2;
    /// A placeholder input before parameters are formalised.
    pub const FAKE_INPUT: i16 = 3;
}

/// Entry property bits (Ghidra `SymbolEntry` `map_entry` …).
pub mod entry_props {
    /// A `MapEntry`.
    pub const MAP_ENTRY: u32 = 1;
    /// A `MapEntryConflict`.
    pub const CONFLICT_ENTRY: u32 = 2;
    /// A `DynamicEntry`.
    pub const DYNAMIC_ENTRY: u32 = 4;
    /// An `UnassignedEntry`.
    pub const UNASSIGNED_ENTRY: u32 = 8;
    /// A proper piece of a whole symbol.
    pub const PIECE: u32 = 16;
}
