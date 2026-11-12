//! Address-space attributes, seen abstractly.
//!
//! This crate is below `bk-core` and knows nothing about address spaces
//! beyond what marshalling needs: an opaque identity ([`SpaceId`]), the facts
//! an encoder writes ([`SpaceRef`]) and the lookups a decoder performs
//! ([`SpaceResolver`]). `bk-core`'s space manager implements the resolver.

/// The identity of an address space: its index in the manager that owns it.
///
/// The marshalling layer never interprets the number; it hands back whatever
/// the [`SpaceResolver`] returned. `bk-core` re-exports this type as its typed
/// index into the space manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId(u32);

impl SpaceId {
    /// Wraps a space index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The space index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// How the packed form writes a reference to an address space.
///
/// Ordinary spaces are written as their index. The special spaces have no
/// stable index across the marshalling boundary and are written as codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackedSpace {
    /// An ordinary space, written as its index.
    Index(u32),
    /// The formal stack space.
    Stack,
    /// The join space.
    Join,
    /// The function-call-specification space.
    Fspec,
    /// The p-code operation reference space.
    Iop,
    /// A register-relative space that is not the formal stack.
    Spacebase,
}

/// What an encoder needs to know about a space to write a reference to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceRef<'a> {
    /// The space's name, written by the XML form.
    pub name: &'a str,
    /// The reference written by the packed form.
    pub packed: PackedSpace,
}

/// The lookups a decoder needs to turn a space attribute into a [`SpaceId`].
///
/// Ghidra's decoders hold a pointer to the `AddrSpaceManager`; this trait is
/// the part of it they use.
pub trait SpaceResolver {
    /// The space with the given name (XML form).
    fn space_by_name(&self, name: &str) -> Option<SpaceId>;

    /// The space with the given index (packed form). `None` when the slot is
    /// empty or the index is out of range.
    fn space_by_index(&self, index: u64) -> Option<SpaceId>;

    /// One more than the highest space index in use.
    fn space_count(&self) -> u64;

    /// The formal stack space, if the processor has one.
    fn stack_space(&self) -> Option<SpaceId>;

    /// The join space, if it exists.
    fn join_space(&self) -> Option<SpaceId>;
}

/// A resolver that knows no spaces, for documents without space attributes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSpaces;

impl SpaceResolver for NoSpaces {
    fn space_by_name(&self, _name: &str) -> Option<SpaceId> {
        None
    }

    fn space_by_index(&self, _index: u64) -> Option<SpaceId> {
        None
    }

    fn space_count(&self) -> u64 {
        0
    }

    fn stack_space(&self) -> Option<SpaceId> {
        None
    }

    fn join_space(&self) -> Option<SpaceId> {
        None
    }
}

impl<T: SpaceResolver + ?Sized> SpaceResolver for &T {
    fn space_by_name(&self, name: &str) -> Option<SpaceId> {
        (**self).space_by_name(name)
    }

    fn space_by_index(&self, index: u64) -> Option<SpaceId> {
        (**self).space_by_index(index)
    }

    fn space_count(&self) -> u64 {
        (**self).space_count()
    }

    fn stack_space(&self) -> Option<SpaceId> {
        (**self).stack_space()
    }

    fn join_space(&self) -> Option<SpaceId> {
        (**self).join_space()
    }
}
