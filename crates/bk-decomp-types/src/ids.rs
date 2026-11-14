//! Typed ids of factory entries.

/// The bit of a [`TypeId`] that marks an entry of a forked (overlay)
/// factory.
const OVERLAY_BIT: u32 = 1 << 31;

/// The id of a type in a [`TypeFactory`](crate::TypeFactory): an index into
/// its arena. The top bit says which layer holds the entry: clear for the
/// root factory, set for the per-function overlay of a forked factory
/// (ADR-025 3e), so ids are stable and independent of what other functions
/// create.
///
/// This is not Ghidra's 64-bit type id (the `id` attribute of a type), which
/// is [`TypeEntry::id`](crate::TypeEntry::id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(u32);

impl TypeId {
    pub(crate) const fn new(index: u32, overlay: bool) -> Self {
        if overlay {
            Self(index | OVERLAY_BIT)
        } else {
            Self(index)
        }
    }

    /// Rebuilds an id from [`TypeId::raw`].
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw number, layer bit included.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// The index within the entry's layer.
    pub const fn index(self) -> usize {
        (self.0 & !OVERLAY_BIT) as usize
    }

    /// Whether the entry lives in the overlay of a forked factory: the
    /// category of *inferred* types (ADR-025 3e).
    pub const fn is_overlay(self) -> bool {
        self.0 & OVERLAY_BIT != 0
    }
}
