//! Typed ids of the IR's objects.
//!
//! Ghidra names its objects by host pointers; Basilisk by indices into the
//! function's arenas. An id is never reused within a function: a destroyed
//! varnode or a retired op keeps its slot, so a stale id is detected, never
//! confused with a newer object.

use std::fmt;

/// The raw value meaning "none" inside the packed structs.
pub(crate) const NONE: u32 = u32::MAX;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) u32);

        impl $name {
            /// The id with the given index.
            pub const fn new(index: u32) -> Self {
                Self(index)
            }

            /// The index of the id.
            pub const fn index(self) -> usize {
                self.0 as usize
            }

            /// The raw value.
            pub const fn get(self) -> u32 {
                self.0
            }

            /// The id stored in a packed field, `None` for [`NONE`].
            pub(crate) const fn from_packed(raw: u32) -> Option<Self> {
                if raw == NONE { None } else { Some(Self(raw)) }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), self.0)
            }
        }
    };
}

id_type!(
    /// A varnode of one function (Ghidra `Varnode *`). Not Ghidra's
    /// `create_index`: an `xref` merge consumes a create index without a
    /// surviving varnode; the create index is a field of the varnode.
    VarnodeId,
    "vn#"
);
id_type!(
    /// A p-code op of one function (Ghidra `PcodeOp *`).
    OpId,
    "op#"
);
id_type!(
    /// A high variable (Ghidra `HighVariable *`); the high variables
    /// themselves are D14's, this crate only stores the reference.
    HighId,
    "h"
);
id_type!(
    /// A call specification (Ghidra `FuncCallSpecs *`), named by creation
    /// order. A loaded state numbers them by their position in
    /// `Funcdata::qlst` at the time of the dump; [`CallSpecId::DEAD`] is a
    /// call spec Ghidra deleted while a varnode still names it.
    CallSpecId,
    "c"
);
id_type!(
    /// A unit of the pipeline (an action, rule, merge pass, structuring
    /// step or output pass; ADR-025 item 1).
    UnitId,
    "unit#"
);

impl CallSpecId {
    /// A call spec that no longer exists (the dump's `call:-`). It sorts
    /// after every live call spec.
    pub const DEAD: Self = Self(u32::MAX - 1);
}

/// A varnode's symbol entry, opaque to this crate (D06's `SymbolEntry`):
/// the symbol's id and the entry's position among the symbol's map
/// entries, as the state dump names it (`s<id>:<position>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryRef {
    /// `Symbol::symbolId`.
    pub symbol: u64,
    /// The position in `Symbol::mapentry` (-1 when not found).
    pub position: i32,
}
