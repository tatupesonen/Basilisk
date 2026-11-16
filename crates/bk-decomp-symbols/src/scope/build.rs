//! The public builders that add one symbol of each kind (database.cc
//! 1630–1900; spec 4.9).

use bk_core::Address;
use bk_decomp_types::{Metatype, TypeFactory, TypeId};

use super::add::{ConflictFacts, stripped};
use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::{VarnodeFlags, entry_props};
use crate::ids::{EntryId, ScopeId, SymbolId};
use crate::model::{EntryData, EntryKind, Handle, SymbolKind};

impl Database {
    /// Adds a plain symbol without mapping it (Ghidra `addSymbol(nm, ct)`).
    pub fn add_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        types: &TypeFactory,
    ) -> Result<SymbolId> {
        let sym = Self::new_symbol(scope, SymbolKind::Plain, name, ty, types)?;
        self.add_symbol_internal(scope, sym)
    }

    /// Adds a plain symbol of the stripped form of `ty` mapped at `addr`
    /// (Ghidra `addSymbol(nm, ct, addr, usepoint)`); returns the entry.
    pub fn add_symbol_at(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        addr: Address,
        usepoint: Address,
        types: &TypeFactory,
    ) -> Result<EntryId> {
        let ty = stripped(types, ty);
        let sym = Self::new_symbol(scope, SymbolKind::Plain, name, ty, types)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.add_map_point(sym, addr, usepoint)
    }

    /// Adds a function symbol at `addr` with no use limit (Ghidra
    /// `addFunction`), warning when the address is inside another symbol.
    pub fn add_function(
        &mut self,
        scope: ScopeId,
        addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        if let Some(overlap) = self.query_container(scope, addr, 1, Address::INVALID)? {
            let other = self.symbol(self.entry(overlap)?.symbol)?.name.to_string();
            self.warn(format!("Function {name} overlaps object: {other}"));
        }
        let code = types.type_code()?;
        let consume_size = self.env.min_funcsymbol_size;
        let mut sym = Self::new_symbol(
            scope,
            SymbolKind::Function { consume_size },
            name,
            code,
            types,
        )?;
        sym.flags |= VarnodeFlags::NAMELOCK | VarnodeFlags::TYPELOCK;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.add_map_point(sym, addr, Address::INVALID)?;
        Ok(sym)
    }

    /// Adds an external reference at `addr` to the function at `ref_addr`
    /// (Ghidra `addExternalRef`); an empty name becomes
    /// `<shortcut><ref address>_exref`. `readonly` is cleared after mapping.
    pub fn add_external_ref(
        &mut self,
        scope: ScopeId,
        addr: Address,
        ref_addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        let sym = self.new_extern_ref(scope, ref_addr, name, "", types)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.add_map_point(sym, addr, Address::INVALID)?;
        self.symbol_mut(sym)?.flags.remove(VarnodeFlags::READONLY);
        Ok(sym)
    }

    /// An external-reference symbol record (Ghidra `ExternRefSymbol`'s
    /// `buildNameType`).
    pub(crate) fn new_extern_ref(
        &self,
        scope: ScopeId,
        ref_addr: Address,
        name: &str,
        display: &str,
        types: &mut TypeFactory,
    ) -> Result<crate::model::SymbolData> {
        let spaces = &self.env.spaces;
        let code = types.type_code()?;
        let word = spaces
            .space_of(ref_addr)
            .map_or(1, bk_core::Space::word_size);
        let size = ref_addr.addr_size(spaces) as i32;
        let ty = types.pointer(size, code, word)?;
        let mut name = name.to_owned();
        if name.is_empty() {
            let shortcut = ref_addr
                .shortcut(spaces)
                .map(String::from)
                .unwrap_or_default();
            name = format!("{shortcut}{}_exref", ref_addr.raw(spaces));
        }
        let mut sym =
            Self::new_symbol(scope, SymbolKind::ExternRef { ref_addr }, &name, ty, types)?;
        sym.display_name = if display.is_empty() {
            name.into()
        } else {
            display.into()
        };
        sym.flags |= VarnodeFlags::EXTERNREF | VarnodeFlags::TYPELOCK;
        Ok(sym)
    }

    /// Adds a code label at `addr` (Ghidra `addCodeLabel`), warning when
    /// the address is inside a symbol that is not a function.
    pub fn add_code_label(
        &mut self,
        scope: ScopeId,
        addr: Address,
        name: &str,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        if let Some(overlap) = self.query_container(scope, addr, 1, addr)? {
            let other = self.symbol(self.entry(overlap)?.symbol)?;
            if !other.is_function() {
                let other = other.name.to_string();
                self.warn(format!("Codelabel {name} overlaps object: {other}"));
            }
        }
        let ty = types.base(1, Metatype::Unknown)?;
        let sym = Self::new_symbol(scope, SymbolKind::Label, name, ty, types)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.add_map_point(sym, addr, Address::INVALID)?;
        Ok(sym)
    }

    /// Adds a symbol attached to a dynamic hash (Ghidra
    /// `addDynamicSymbol`); valid at `caddr` only when that is valid.
    pub fn add_dynamic_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        caddr: Address,
        hash: u64,
        types: &TypeFactory,
    ) -> Result<SymbolId> {
        let sym = Self::new_symbol(scope, SymbolKind::Plain, name, ty, types)?;
        let size = sym.type_size;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.direct_dynamic_entry(scope, sym, hash, size, caddr)?;
        Ok(sym)
    }

    /// Adds an equate (Ghidra `addEquateSymbol`).
    #[expect(
        clippy::too_many_arguments,
        reason = "Ghidra's addEquateSymbol arguments plus the scope and type factory it reads from `this`"
    )]
    pub fn add_equate_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        format: u32,
        value: u64,
        addr: Address,
        hash: u64,
        types: &mut TypeFactory,
    ) -> Result<SymbolId> {
        let ty = types.base(1, Metatype::Unknown)?;
        let mut sym = Self::new_symbol(scope, SymbolKind::Equate { value }, name, ty, types)?;
        sym.disp |= format;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.direct_dynamic_entry(scope, sym, hash, 1, addr)?;
        Ok(sym)
    }

    /// Adds a union facet (Ghidra `addUnionFacetSymbol`).
    #[expect(
        clippy::too_many_arguments,
        reason = "Ghidra's addUnionFacetSymbol arguments plus the scope and type factory it reads from `this`"
    )]
    pub fn add_union_facet_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        field: i32,
        addr: Address,
        hash: u64,
        types: &TypeFactory,
    ) -> Result<SymbolId> {
        let kind = SymbolKind::UnionFacet {
            field,
            addr_based: false,
        };
        let sym = Self::new_symbol(scope, kind, name, ty, types)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        self.direct_dynamic_entry(scope, sym, hash, 1, addr)?;
        Ok(sym)
    }

    /// Adds a symbol whose storage may hold other symbols at the same code
    /// point (Ghidra `addSymbolWithConflict`).
    pub fn add_symbol_with_conflict(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: TypeId,
        facts: ConflictFacts,
        types: &TypeFactory,
    ) -> Result<EntryId> {
        if !facts.written {
            return Err(SymbolError::ConflictVarnode);
        }
        let ty = stripped(types, ty);
        let sym = Self::new_symbol(scope, SymbolKind::Plain, name, ty, types)?;
        let sym = self.add_symbol_internal(scope, sym)?;
        let mut use_limit = bk_core::RangeList::default();
        if let Some(space) = facts.def_addr.space() {
            use_limit.insert_range(space, facts.def_addr.offset(), facts.def_addr.offset());
        }
        let entry = EntryData {
            symbol: sym,
            kind: EntryKind::Map {
                addr: facts.addr,
                conflict: Some(facts.def_time),
            },
            use_limit,
            properties: entry_props::MAP_ENTRY | entry_props::CONFLICT_ENTRY,
            extra_flags: VarnodeFlags::empty(),
            offset: 0,
            size: facts.size,
            handle: Handle::None,
            live: true,
        };
        self.add_map(scope, entry)
    }
}
