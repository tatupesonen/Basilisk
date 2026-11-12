//! The register queries the address model makes of a processor.
//!
//! In Ghidra every `AddrSpace` points at its `Translate`, and the address
//! code asks it for registers when parsing and printing. The `Translate`
//! interface itself arrives with the SLEIGH runtime; this trait is the part of
//! it used here, and the space manager holds an implementation of it.

use std::fmt::Debug;

use bk_marshal::SpaceId;

use crate::varnode::VarnodeData;

/// Looks up processor registers by name and by location (the register
/// queries of Ghidra's `Translate`).
pub trait RegisterLookup: Debug + Send + Sync {
    /// The location and size of the register called `name` (Ghidra
    /// `getRegister`, which throws where this returns `None`).
    fn register(&self, name: &str) -> Option<VarnodeData>;

    /// The name of the smallest register containing the given bytes (Ghidra
    /// `getRegisterName`, which returns an empty string where this returns
    /// `None`).
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str>;

    /// The name of the register occupying exactly the given bytes (Ghidra
    /// `getExactRegisterName`).
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str>;
}

/// A processor without named registers.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRegisters;

impl RegisterLookup for NoRegisters {
    fn register(&self, _name: &str) -> Option<VarnodeData> {
        None
    }

    fn register_name(&self, _space: SpaceId, _offset: u64, _size: u32) -> Option<&str> {
        None
    }

    fn exact_register_name(&self, _space: SpaceId, _offset: u64, _size: u32) -> Option<&str> {
        None
    }
}
