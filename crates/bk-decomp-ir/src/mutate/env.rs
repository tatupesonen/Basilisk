//! [`FunctionEnv`] (ADR-046): the state of `Funcdata` this crate does not
//! hold — types, symbols, prototypes, high variables, laned registers,
//! join addresses — consulted by the mutation methods at exactly the points
//! Ghidra consults it.
//!
//! One trait, not split into a read-only and a mutable half (spec open item
//! 10.3, settled here): every mutation that asks a query (`default_type`,
//! `symbol_properties`, …) also reaches a recording step in the same call
//! (`assign_high`, `laned_register`, `wrapping_address`, which may create a
//! join record), so a split would make every such method take two objects
//! for one function's state.

use std::collections::HashMap;

use bk_core::Address;
use bk_decomp_types::TypeId;

use crate::flags::vflags;
use crate::ids::{EntryRef, VarnodeId};
use crate::ssa::Ssa;

/// `EffectRecord`'s effect types (fspec.hh), what
/// [`FunctionEnv::input_effect`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Effect {
    /// `unaffected` (1).
    Unaffected,
    /// `killedbycall` (2).
    KilledByCall,
    /// `return_address` (3).
    ReturnAddress,
    /// `unknown_effect` (4).
    Unknown,
}

/// A symbol entry's type for the varnode, when the entry is type-locked
/// (`SymbolEntry::updateType` through `getSizedType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LockedType {
    /// The type.
    pub ty: TypeId,
    /// Its metatype is `TYPE_UNKNOWN` (never locked, `Varnode::updateType`).
    pub unknown: bool,
}

/// What `ScopeLocal::queryProperties` answers for a storage range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PropertiesAnswer {
    /// No entry: flags to set (`typelock` is masked off).
    Flags(u32),
    /// An entry: `Varnode::setSymbolProperties` applies it.
    Entry {
        /// The entry.
        entry: EntryRef,
        /// The type to lock in, when the entry's flags have `typelock` and a
        /// sized type exists.
        locked_type: Option<LockedType>,
        /// `getSymbol()->isTypeLocked()`: the varnode keeps a reference to
        /// the entry.
        symbol_type_locked: bool,
        /// `getAllFlags()` (`typelock` is masked off).
        flags: u32,
    },
}

/// The environment of one function's mutation methods (ADR-046),
/// implemented by D07's function state; [`TableEnv`] for tests.
/// Object-safe (plugin binding constraint 8).
pub trait FunctionEnv {
    /// `getBase(size, TYPE_UNKNOWN)`.
    fn default_type(&self, size: i32) -> TypeId;
    /// `getTypeCode()`.
    fn code_type(&self) -> TypeId;
    /// `localmap->queryProperties(addr, size, usepoint)`; `use_point` is
    /// `None` for Ghidra's invalid `Address()`.
    fn symbol_properties(
        &self,
        addr: Address,
        size: i32,
        use_point: Option<Address>,
    ) -> PropertiesAnswer;
    /// `Funcdata::assignHigh` (when `highlevel_on`: computes the cover
    /// through [`Ssa::calc_cover`], issues a data-type warning, gives a
    /// non-annotation varnode its own high variable through
    /// [`Ssa::set_high`]).
    fn assign_high(&mut self, ssa: &mut Ssa, vn: VarnodeId);
    /// `checkForLanedRegister(size, addr)`, called only when `size >=
    /// minLanedSize` (the environment decides; it is called for every
    /// creation Ghidra checks).
    fn laned_register(&mut self, size: i32, addr: Address);
    /// `constructWrappingAddress(addr, size)`, called when the range is not
    /// valid in its space.
    fn wrapping_address(&mut self, addr: Address, size: i32) -> Address;
    /// `funcp.hasEffect(addr, size)`.
    fn input_effect(&self, addr: Address, size: i32) -> Effect;
    /// `isHighOn()` (`setVarnodeProperties` computes the cover then).
    fn cover_on(&self) -> bool;
}

/// A table-driven [`FunctionEnv`] for tests: default types by size, symbol
/// answers by storage, effects by storage; high variables off unless
/// `high_on`; every call recorded.
#[derive(Clone, Debug, Default)]
pub struct TableEnv {
    /// `getBase(size, TYPE_UNKNOWN)` by size; a missing size gives
    /// `TypeId::from_raw(size)`.
    pub default_types: HashMap<i32, TypeId>,
    /// `getTypeCode()`.
    pub code: Option<TypeId>,
    /// Answers by (address, size); others are `Flags(0)`.
    pub properties: HashMap<(Address, i32), PropertiesAnswer>,
    /// Effects by (address, size); others are `Unknown`.
    pub effects: HashMap<(Address, i32), Effect>,
    /// `highlevel_on` / `isHighOn`.
    pub high_on: bool,
    /// `minLanedSize`.
    pub min_laned_size: i32,
    /// Every call, in order, for tests that check the call points.
    pub log: Vec<String>,
}

impl FunctionEnv for TableEnv {
    fn default_type(&self, size: i32) -> TypeId {
        self.default_types
            .get(&size)
            .copied()
            .unwrap_or_else(|| TypeId::from_raw(size as u32))
    }

    fn code_type(&self) -> TypeId {
        self.code.unwrap_or(TypeId::from_raw(0xc0de))
    }

    fn symbol_properties(
        &self,
        addr: Address,
        size: i32,
        _use_point: Option<Address>,
    ) -> PropertiesAnswer {
        self.properties
            .get(&(addr, size))
            .copied()
            .unwrap_or(PropertiesAnswer::Flags(0))
    }

    fn assign_high(&mut self, ssa: &mut Ssa, vn: VarnodeId) {
        self.log
            .push(format!("assign_high {}", ssa.varnode_create_index(vn)));
        if self.high_on {
            if ssa.has_cover(vn) {
                let _ = ssa.calc_cover(vn);
            }
            if ssa.varnode_flags(vn) & vflags::ANNOTATION == 0 {
                let id = crate::ids::HighId::new(ssa.varnode_create_index(vn));
                let _ = ssa.set_high(vn, Some(id), 0);
            }
        }
    }

    fn laned_register(&mut self, size: i32, _addr: Address) {
        if size >= self.min_laned_size && self.min_laned_size > 0 {
            self.log.push(format!("laned {size}"));
        }
    }

    fn wrapping_address(&mut self, addr: Address, size: i32) -> Address {
        self.log.push(format!("wrap {size}"));
        addr
    }

    fn input_effect(&self, addr: Address, size: i32) -> Effect {
        self.effects
            .get(&(addr, size))
            .copied()
            .unwrap_or(Effect::Unknown)
    }

    fn cover_on(&self) -> bool {
        self.high_on
    }
}
