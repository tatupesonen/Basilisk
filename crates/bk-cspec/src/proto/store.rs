//! Parameters of a prototype without a symbol table behind them (Ghidra
//! `ProtoParameter`, `ParameterBasic`, `ProtoStoreInternal`).

use bk_core::{Address, Provenance};

use super::pieces::{ParameterPieces, PieceFlags};
use crate::error::{CspecError, Result};
use crate::types::{Metatype, ParamTypes, TypeHandle};

/// One parameter or the return value (Ghidra `ParameterBasic`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterBasic {
    /// The name; empty for the return value or an unnamed parameter.
    pub name: String,
    /// The storage; invalid when there is none.
    pub addr: Address,
    /// The data type.
    pub ty: TypeHandle,
    /// Size of the type in bytes, recorded when the parameter was set.
    pub size: i32,
    /// Locks and properties.
    pub flags: PieceFlags,
    /// Where the name and type came from (ADR-025 3f); takes no part in
    /// any decision of this crate.
    pub provenance: Provenance,
}

impl ParameterBasic {
    /// A parameter from its parts.
    pub fn new(name: &str, pieces: &ParameterPieces, size: i32) -> Self {
        Self {
            name: name.to_owned(),
            addr: pieces.addr,
            ty: pieces.ty,
            size,
            flags: pieces.flags,
            provenance: Provenance::Default,
        }
    }

    /// A `void` return value without storage.
    pub fn void(ty: TypeHandle) -> Self {
        Self {
            name: String::new(),
            addr: Address::INVALID,
            ty,
            size: 0,
            flags: PieceFlags::empty(),
            provenance: Provenance::Default,
        }
    }

    /// Ghidra `hasStorage`.
    pub const fn has_storage(&self) -> bool {
        !self.addr.is_invalid()
    }
    /// Ghidra `isTypeLocked`.
    pub const fn is_type_locked(&self) -> bool {
        self.flags.contains(PieceFlags::TYPELOCK)
    }
    /// Ghidra `isNameLocked`.
    pub const fn is_name_locked(&self) -> bool {
        self.flags.contains(PieceFlags::NAMELOCK)
    }
    /// Ghidra `isSizeTypeLocked`.
    pub const fn is_size_type_locked(&self) -> bool {
        self.flags.contains(PieceFlags::SIZELOCK)
    }
    /// Ghidra `isThisPointer`.
    pub const fn is_this_pointer(&self) -> bool {
        self.flags.contains(PieceFlags::ISTHIS)
    }
    /// Ghidra `isIndirectStorage`.
    pub const fn is_indirect_storage(&self) -> bool {
        self.flags.contains(PieceFlags::INDIRECTSTORAGE)
    }
    /// Ghidra `isHiddenReturn`.
    pub const fn is_hidden_return(&self) -> bool {
        self.flags.contains(PieceFlags::HIDDENRETPARM)
    }
    /// Ghidra `isNameUndefined`.
    pub fn is_name_undefined(&self) -> bool {
        self.name.is_empty()
    }

    /// Locks or unlocks the type; locking an unknown type also locks the
    /// size (Ghidra `setTypeLock`).
    pub fn set_type_lock(&mut self, types: &dyn ParamTypes, val: bool) {
        if val {
            self.flags |= PieceFlags::TYPELOCK;
            if types.metatype(self.ty) == Metatype::Unknown {
                self.flags |= PieceFlags::SIZELOCK;
            }
        } else {
            self.flags
                .remove(PieceFlags::TYPELOCK | PieceFlags::SIZELOCK);
        }
    }
    /// Ghidra `setNameLock`.
    pub fn set_name_lock(&mut self, val: bool) {
        self.flags.set(PieceFlags::NAMELOCK, val);
    }
    /// Ghidra `setThisPointer`.
    pub fn set_this_pointer(&mut self, val: bool) {
        self.flags.set(PieceFlags::ISTHIS, val);
    }

    /// Replaces the type of a size-locked parameter (Ghidra
    /// `overrideSizeLockType`).
    pub fn override_size_lock_type(
        &mut self,
        types: &dyn ParamTypes,
        ty: TypeHandle,
    ) -> Result<()> {
        if self.size != types.size(ty) {
            return Err(CspecError::new(
                "Overriding parameter with different type size",
            ));
        }
        if !self.is_size_type_locked() {
            return Err(CspecError::new(
                "Overriding parameter that is not size locked",
            ));
        }
        self.ty = ty;
        Ok(())
    }

    /// Returns a size-locked parameter to an unknown type of its size
    /// (Ghidra `resetSizeLockType`).
    pub fn reset_size_lock_type(&mut self, types: &mut dyn ParamTypes) {
        if types.metatype(self.ty) == Metatype::Unknown {
            return;
        }
        self.ty = types.unknown(self.size);
    }
}

/// The parameters and return value of a prototype (Ghidra
/// `ProtoStoreInternal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoStoreInternal {
    pub(crate) void_ty: TypeHandle,
    pub(crate) inputs: Vec<Option<ParameterBasic>>,
    pub(crate) output: ParameterBasic,
}

impl ProtoStoreInternal {
    /// An empty store whose return value is `void_ty` (Ghidra's
    /// constructor).
    pub fn new(void_ty: TypeHandle) -> Self {
        Self {
            void_ty,
            inputs: Vec::new(),
            output: ParameterBasic::void(void_ty),
        }
    }

    /// Sets the `i`-th parameter (Ghidra `setInput`).
    #[expect(
        clippy::indexing_slicing,
        reason = "the vector is resized to hold index i first"
    )]
    pub fn set_input(
        &mut self,
        i: usize,
        name: &str,
        pieces: &ParameterPieces,
        size: i32,
    ) -> &mut ParameterBasic {
        if self.inputs.len() <= i {
            self.inputs.resize(i + 1, None);
        }
        self.inputs[i].insert(ParameterBasic::new(name, pieces, size))
    }

    /// Removes the `i`-th parameter, shifting later ones down (Ghidra
    /// `clearInput`).
    pub fn clear_input(&mut self, i: usize) {
        if i >= self.inputs.len() {
            return;
        }
        self.inputs.remove(i);
        while self.inputs.last().is_some_and(Option::is_none) {
            self.inputs.pop();
        }
    }

    /// Ghidra `clearAllInputs`.
    pub fn clear_all_inputs(&mut self) {
        self.inputs.clear();
    }
    /// Ghidra `getNumInputs`.
    pub fn num_inputs(&self) -> usize {
        self.inputs.len()
    }
    /// Ghidra `getInput`.
    pub fn input(&self, i: usize) -> Option<&ParameterBasic> {
        self.inputs.get(i).and_then(Option::as_ref)
    }
    /// Ghidra `getInput`, mutably.
    pub fn input_mut(&mut self, i: usize) -> Option<&mut ParameterBasic> {
        self.inputs.get_mut(i).and_then(Option::as_mut)
    }
    /// Ghidra `setOutput`.
    pub fn set_output(&mut self, pieces: &ParameterPieces, size: i32) -> &mut ParameterBasic {
        self.output = ParameterBasic::new("", pieces, size);
        &mut self.output
    }
    /// Resets the return value to `void` (Ghidra `clearOutput`).
    pub fn clear_output(&mut self) {
        self.output = ParameterBasic::void(self.void_ty);
    }
    /// Ghidra `getOutput`.
    pub const fn output(&self) -> &ParameterBasic {
        &self.output
    }
    /// Ghidra `getOutput`, mutably.
    pub fn output_mut(&mut self) -> &mut ParameterBasic {
        &mut self.output
    }
}
