//! The raw parts of a prototype (Ghidra `PrototypePieces`) and one assigned
//! parameter (Ghidra `ParameterPieces`).

use bitflags::bitflags;
use bk_core::{Address, Provenance, SpaceManager, VarnodeData};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::types::TypeHandle;

bitflags! {
    /// Properties of an assigned parameter (Ghidra's `ParameterPieces`
    /// flag values).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
    pub struct PieceFlags: u32 {
        /// The `this` pointer.
        const ISTHIS = 1;
        /// The hidden pointer to the return value.
        const HIDDENRETPARM = 2;
        /// A pointer to the true parameter.
        const INDIRECTSTORAGE = 4;
        /// The name is locked.
        const NAMELOCK = 8;
        /// The data type is locked.
        const TYPELOCK = 16;
        /// The size is locked, not the type.
        const SIZELOCK = 32;
    }
}

/// One parameter or the return value with its storage (Ghidra
/// `ParameterPieces`). An invalid address means no storage (a `void`
/// return, or a hidden return parameter not yet assigned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterPieces {
    /// Storage of the value.
    pub addr: Address,
    /// Its data type.
    pub ty: TypeHandle,
    /// Its properties.
    pub flags: PieceFlags,
}

impl ParameterPieces {
    /// A piece of the given type without storage or flags.
    pub const fn new(ty: TypeHandle) -> Self {
        Self {
            addr: Address::INVALID,
            ty,
            flags: PieceFlags::empty(),
        }
    }

    /// Exchanges type and flags with `other`, keeping both addresses
    /// (Ghidra `swapMarkup`).
    pub fn swap_markup(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.ty, &mut other.ty);
        std::mem::swap(&mut self.flags, &mut other.flags);
    }

    /// Sets the address from the pieces making up the value: one piece is
    /// its own address, several become a join address (Ghidra
    /// `assignAddressFromPieces`). `most_to_least` tells the order of
    /// `pieces`.
    pub fn assign_from_pieces(
        &mut self,
        manager: &SpaceManager,
        mut pieces: Vec<VarnodeData>,
        most_to_least: bool,
    ) -> Result<()> {
        if !most_to_least && pieces.len() > 1 {
            pieces.reverse();
        }
        self.addr = manager.join_pieces(pieces)?;
        Ok(())
    }
}

/// The parts of a function prototype as parsed from source (Ghidra
/// `PrototypePieces`). The model is named, not pointed at (spec 8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrototypePieces {
    /// Name of the prototype model, if any.
    pub model: Option<String>,
    /// The function's name.
    pub name: String,
    /// The return type.
    pub outtype: TypeHandle,
    /// The parameter types.
    pub intypes: Vec<TypeHandle>,
    /// The parameter names.
    pub innames: Vec<String>,
    /// Position of the first variadic argument, or -1 (Ghidra
    /// `firstVarArgSlot`).
    pub first_vararg: i32,
    /// Where the prototype came from (ADR-025 3f); takes no part in any
    /// decision of this crate.
    #[serde(with = "crate::provenance_serde")]
    pub provenance: Provenance,
}

impl PrototypePieces {
    /// A prototype without model, name or parameters.
    pub fn new(outtype: TypeHandle) -> Self {
        Self {
            model: None,
            name: String::new(),
            outtype,
            intypes: Vec::new(),
            innames: Vec::new(),
            first_vararg: -1,
            provenance: Provenance::Default,
        }
    }

    /// The same prototype with the given parameter types (unnamed).
    #[must_use]
    pub fn with_inputs(mut self, intypes: Vec<TypeHandle>) -> Self {
        self.innames = vec![String::new(); intypes.len()];
        self.intypes = intypes;
        self
    }
}
