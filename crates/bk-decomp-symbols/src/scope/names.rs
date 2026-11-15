//! Building names (database.cc 1909–1941, 2616–2799, 3035–3050; spec
//! 4.8).

use std::fmt::Write as _;

use bk_core::Address;
use bk_decomp_types::{TypeFactory, TypeId, TypeKind};

use crate::database::Database;
use crate::error::{Result, SymbolError};
use crate::flags::{VarnodeFlags, category};
use crate::ids::{ScopeId, SymbolId};
use crate::model::{ScopeKind, is_undefined_name};

/// What `buildDefaultName` reads of a varnode (spec 3.3 item 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarnodeFacts {
    /// The varnode's address.
    pub addr: Address,
    /// Its use point in the function (Ghidra `Varnode::getUsePoint`).
    pub use_point: Address,
    /// Its flags.
    pub flags: VarnodeFlags,
    /// Whether its high variable is an input.
    pub high_is_input: bool,
    /// Whether it is a constant.
    pub is_constant: bool,
    /// Whether it is address-tied.
    pub addr_tied: bool,
}

/// Ghidra `Datatype::printNameBase`: the first character of the name,
/// prefixed by `p` per pointer and `a` per array level.
pub fn name_base(types: &TypeFactory, ty: TypeId) -> String {
    let mut out = String::new();
    let mut cur = ty;
    for _ in 0..=bk_decomp_types::MAX_DEPTH {
        let Some(entry) = types.get(cur) else {
            break;
        };
        match entry.kind() {
            TypeKind::Pointer(p) | TypeKind::PointerRel { ptr: p, .. } => {
                out.push('p');
                cur = p.ptrto;
            }
            TypeKind::Array { element, .. } => {
                out.push('a');
                cur = *element;
            }
            _ => {
                if let Some(c) = entry.name().chars().next() {
                    out.push(c);
                }
                break;
            }
        }
    }
    out
}

/// The space name with its first letter in upper case (Ghidra's
/// `toupper(spacename[0])`).
fn capitalised(name: &str) -> String {
    let mut s = name.to_owned();
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// C++ `istream >> hex >> uint4` on Ghidra's eight undefined-name digits:
/// the longest hex prefix (after an optional `0x`), 0 when there is none,
/// saturating past 32 bits.
fn read_hex_u32(text: &str) -> u32 {
    let t = text.trim_start();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let mut value: u64 = 0;
    for c in t.chars() {
        let Some(d) = c.to_digit(16) else { break };
        value = (value << 4) | u64::from(d);
        if value > u64::from(u32::MAX) {
            return u32::MAX;
        }
    }
    value as u32
}

impl Database {
    fn register_name(&self, addr: Address, size: u32) -> Option<String> {
        let space = addr.space()?;
        self.env
            .registers
            .as_ref()?
            .register_name(space, addr.offset(), size)
            .map(str::to_owned)
    }

    fn space_word_name(&self, out: &mut String, addr: Address, types: &TypeFactory, ty: Option<TypeId>) {
        if let Some(ty) = ty {
            out.push_str(&name_base(types, ty));
        }
        let Some(space) = self.env.spaces.space_of(addr) else {
            return;
        };
        out.push_str(&capitalised(space.name()));
        let width = 2 * space.addr_size() as usize;
        let _ = write!(out, "{:0width$x}", space.byte_to_address(addr.offset()));
    }

    /// Ghidra `ScopeInternal::buildVariableName` (spec 4.8, rules 1–8).
    /// `index` is read and, for local variables, advanced.
    pub fn build_variable_name(
        &self,
        scope: ScopeId,
        addr: Address,
        pc: Address,
        ty: Option<TypeId>,
        index: &mut i32,
        flags: VarnodeFlags,
        types: &TypeFactory,
    ) -> Result<String> {
        let _ = pc;
        let sz = ty
            .and_then(|t| types.get(t))
            .map_or(1, |e| u32::try_from(e.size()).unwrap_or(0));
        let mut s = String::new();
        if addr.is_invalid() {
            s.push_str("unassigned_");
        } else if flags.contains(VarnodeFlags::UNAFFECTED) {
            if flags.contains(VarnodeFlags::RETURN_ADDRESS) {
                s.push_str("unaff_retaddr");
            } else {
                match self.register_name(addr, sz) {
                    Some(reg) => {
                        let _ = write!(s, "unaff_{reg}");
                    }
                    None => {
                        let _ = write!(s, "unaff_{:08x}", addr.offset());
                    }
                }
            }
        } else if flags.contains(VarnodeFlags::PERSIST) {
            match self.register_name(addr, sz) {
                Some(reg) => s.push_str(&reg),
                None => self.space_word_name(&mut s, addr, types, ty),
            }
        } else if flags.contains(VarnodeFlags::INPUT) && *index < 0 {
            match self.register_name(addr, sz) {
                Some(reg) => {
                    let _ = write!(s, "in_{reg}");
                }
                None => {
                    let space = self.env.spaces.space_of(addr).map_or("", bk_core::Space::name);
                    let _ = write!(s, "in_{space}_{:08x}", addr.offset());
                }
            }
        } else if flags.contains(VarnodeFlags::INPUT) {
            let _ = write!(s, "param_{index}");
        } else if flags.contains(VarnodeFlags::ADDRTIED) {
            self.space_word_name(&mut s, addr, types, ty);
        } else if flags.contains(VarnodeFlags::INDIRECT_CREATION) {
            s.push_str("extraout_");
            match self.register_name(addr, sz) {
                Some(reg) => s.push_str(&reg),
                None => s.push_str("var"),
            }
        } else {
            let base = ty.map(|t| name_base(types, t)).unwrap_or_default();
            let _ = write!(s, "{base}Var{index}");
            *index = index.wrapping_add(1);
            if self.name_exists(scope, &s) {
                for _ in 0..10 {
                    let candidate = format!("{base}Var{index}");
                    *index = index.wrapping_add(1);
                    if !self.name_exists(scope, &candidate) {
                        return Ok(candidate);
                    }
                }
            }
        }
        self.make_name_unique(scope, &s)
    }

    /// Ghidra `buildUndefinedName`: the next `$$undefXXXXXXXX` after the last
    /// one in the name tree.
    pub fn build_undefined_name(&self, scope: ScopeId) -> Result<String> {
        let data = self.scope(scope)?;
        let probe: (Box<str>, u32) = ("$$undefz".into(), 0);
        let candidate = match data.names.range(..probe.clone()).next_back() {
            Some((key, _)) => Some(key),
            // lower_bound is the first element (or the end of an empty tree).
            None => data.names.keys().next(),
        };
        if let Some((name, _)) = candidate
            && is_undefined_name(name)
        {
            let digits = name.get(7..15).unwrap_or("");
            let uniq = read_hex_u32(digits);
            if uniq == u32::MAX {
                return Err(SymbolError::UndefinedName);
            }
            return Ok(format!("$$undef{:08x}", uniq + 1));
        }
        Ok("$$undef00000000".to_owned())
    }

    /// Ghidra `makeNameUnique` (spec 4.8): `nm`, or `nm_DD` / `nm_xDDDDD`
    /// one past the last such name.
    pub fn make_name_unique(&self, scope: ScopeId, nm: &str) -> Result<String> {
        if !self.name_exists(scope, nm) {
            return Ok(nm.to_owned());
        }
        let data = self.scope(scope)?;
        let first: (Box<str>, u32) = (nm.into(), 0);
        let bound: (Box<str>, u32) = (format!("{nm}_x99999").into(), u32::MAX);
        let mut uniqid = u32::MAX;
        // Walk back from the bound to (excluding) the first symbol named nm.
        let first_key = data.names.range(first..).next().map(|(k, _)| k.clone());
        for (key, _) in data.names.range(..bound).rev() {
            if Some(key) == first_key.as_ref() {
                break;
            }
            let bname = key.0.as_bytes();
            let n = nm.len();
            let mut candidate = u32::MAX;
            if bname.len() >= n + 3 && bname.get(n) == Some(&b'_') {
                let mut i = n + 1;
                let xform = bname.get(i) == Some(&b'x');
                if xform {
                    i += 1;
                }
                let mut value: u32 = 0;
                let mut count = 0;
                let mut ok = true;
                for &dig in bname.get(i..).unwrap_or(&[]) {
                    if !dig.is_ascii_digit() {
                        ok = false;
                        break;
                    }
                    value = value.wrapping_mul(10).wrapping_add(u32::from(dig - b'0'));
                    count += 1;
                }
                if ok && ((xform && count == 5) || (!xform && count == 2)) {
                    candidate = value;
                }
            }
            if candidate != u32::MAX {
                uniqid = candidate;
                break;
            }
        }
        let result = if uniqid == u32::MAX {
            format!("{nm}_00")
        } else {
            let next = uniqid.wrapping_add(1);
            if next < 100 {
                format!("{nm}_{next:02}")
            } else {
                format!("{nm}_x{next:05}")
            }
        };
        if self.name_exists(scope, &result) {
            return Err(SymbolError::Uniquify { name: result });
        }
        Ok(result)
    }

    /// Ghidra `buildDefaultName` (spec 4.8): from varnode facts when given
    /// (and not a constant), else from the symbol's first entry.
    pub fn build_default_name(
        &self,
        sym: SymbolId,
        base: &mut i32,
        facts: Option<VarnodeFacts>,
        types: &TypeFactory,
    ) -> Result<String> {
        let data = self.symbol(sym)?;
        let scope = data.scope;
        let ty = Some(data.ty);
        let is_param = data.category == category::FUNCTION_PARAMETER;
        let catindex = data.catindex as i32;
        if let Some(f) = facts.filter(|f| !f.is_constant) {
            let in_function = matches!(self.scope(scope)?.kind, ScopeKind::Function(_));
            let usepoint = if !f.addr_tied && in_function {
                f.use_point
            } else {
                Address::INVALID
            };
            if is_param || f.high_is_input {
                let mut index = if is_param { catindex.wrapping_add(1) } else { -1 };
                return self.build_variable_name(scope, f.addr, usepoint, ty, &mut index, f.flags | VarnodeFlags::INPUT, types);
            }
            return self.build_variable_name(scope, f.addr, usepoint, ty, base, f.flags, types);
        }
        if let Some(first) = data.entries.first() {
            let entry = self.entry(*first)?;
            let addr = if entry.is_map_entry() {
                entry.addr().unwrap_or(Address::INVALID)
            } else {
                Address::INVALID
            };
            let usepoint = entry.first_use_address();
            let mut flags = if usepoint.is_invalid() {
                VarnodeFlags::ADDRTIED
            } else {
                VarnodeFlags::empty()
            };
            if is_param {
                flags |= VarnodeFlags::INPUT;
                let mut index = catindex.wrapping_add(1);
                return self.build_variable_name(scope, addr, usepoint, ty, &mut index, flags, types);
            }
            return self.build_variable_name(scope, addr, usepoint, ty, base, flags, types);
        }
        self.build_variable_name(scope, Address::INVALID, Address::INVALID, ty, base, VarnodeFlags::empty(), types)
    }

    /// Ghidra `assignDefaultNames`: renames every symbol with an undefined
    /// name to its default name, in name order.
    pub fn assign_default_names(&mut self, scope: ScopeId, base: &mut i32, types: &TypeFactory) -> Result<()> {
        let start: (Box<str>, u32) = ("$$undef".into(), 0);
        let todo: Vec<SymbolId> = {
            use std::ops::Bound;
            self.scope(scope)?
                .names
                .range((Bound::Excluded(start), Bound::Unbounded))
                .take_while(|((name, _), _)| is_undefined_name(name))
                .map(|(_, id)| *id)
                .collect()
        };
        for sym in todo {
            let name = self.build_default_name(sym, base, None, types)?;
            self.rename_symbol(sym, &name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reading_follows_the_stream() {
        assert_eq!(read_hex_u32("0000001f"), 0x1f);
        assert_eq!(read_hex_u32("ffffffff"), u32::MAX);
        assert_eq!(read_hex_u32("12zz"), 0x12);
        assert_eq!(read_hex_u32("zz"), 0);
        assert_eq!(read_hex_u32("0x1f"), 0x1f);
        assert_eq!(read_hex_u32("123456789"), u32::MAX);
        assert_eq!(capitalised("ram"), "Ram");
        assert_eq!(capitalised(""), "");
    }
}
