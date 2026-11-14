//! Address spaces as the compiler knows them (`AddrSpace`, `newSpace`,
//! `predefinedSymbols`).

/// The kind of an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpaceKind {
    /// The constant space (`IPTR_CONSTANT`), index 0.
    Constant,
    /// A processor space (`IPTR_PROCESSOR`): `OTHER` and every `define space`.
    Processor,
    /// The unique space (`IPTR_INTERNAL`), index 2.
    Unique,
}

/// One address space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceInfo {
    /// Its name.
    pub name: String,
    /// Its index.
    pub index: u32,
    /// What it is.
    pub kind: SpaceKind,
    /// Whether it is the `OTHER` space.
    pub is_other: bool,
    /// Byte order.
    pub big_endian: bool,
    /// Size of an address in bytes.
    pub addr_size: u32,
    /// Bytes per addressable unit.
    pub word_size: u32,
    /// Heritage delay (0 for register spaces, 1 for RAM spaces).
    pub delay: i32,
    /// Backed by physical memory.
    pub physical: bool,
}

impl SpaceInfo {
    /// The constant space.
    pub(crate) fn constant() -> Self {
        Self {
            name: "const".to_owned(),
            index: 0,
            kind: SpaceKind::Constant,
            is_other: false,
            big_endian: false,
            addr_size: 8,
            word_size: 1,
            delay: 0,
            physical: false,
        }
    }

    /// The `OTHER` space (`OtherSpace`: little endian, 8-byte offsets).
    pub(crate) fn other() -> Self {
        Self {
            name: "OTHER".to_owned(),
            index: 1,
            kind: SpaceKind::Processor,
            is_other: true,
            big_endian: false,
            addr_size: 8,
            word_size: 1,
            delay: 0,
            physical: true,
        }
    }

    /// The unique space (`UniqueSpace`: 4-byte offsets, language
    /// endianness).
    pub(crate) fn unique(big_endian: bool) -> Self {
        Self {
            name: "unique".to_owned(),
            index: 2,
            kind: SpaceKind::Unique,
            is_other: false,
            big_endian,
            addr_size: 4,
            word_size: 1,
            delay: 0,
            physical: true,
        }
    }

    /// `AddrSpace::byteToAddress`: a byte offset in addressable units.
    pub fn byte_to_address(&self, offset: u64) -> u64 {
        offset / u64::from(self.word_size.max(1))
    }
}
