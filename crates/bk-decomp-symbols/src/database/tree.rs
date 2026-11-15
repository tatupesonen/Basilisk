//! Navigating the scope tree: hashed ids, resolution by name, full names,
//! paths (database.cc 947–985, 1435–1624, 3294–3371; spec 4.7).

use super::Database;
use crate::error::{Result, SymbolError, limits};
use crate::ids::ScopeId;

/// Ghidra's CRC-32 table (`crc32.cc`, the reflected 0xEDB88320
/// polynomial).
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Ghidra `crc_update`: only the low byte of `val` is used.
pub(crate) fn crc_update(reg: u32, val: u32) -> u32 {
    CRC_TABLE[((reg ^ val) & 0xff) as usize] ^ (reg >> 8)
}

/// The id of a namespace named `name` under the scope of id `parent`
/// (Ghidra `Scope::hashScopeName`).
pub fn hash_scope_name(parent: u64, name: &str) -> u64 {
    let mut reg1 = (parent >> 32) as u32;
    let mut reg2 = parent as u32;
    reg1 = crc_update(reg1, 0xa9);
    reg2 = crc_update(reg2, reg1);
    for byte in name.bytes() {
        reg1 = crc_update(reg1, u32::from(byte));
        reg2 = crc_update(reg2, reg1);
    }
    (u64::from(reg1) << 32) | u64::from(reg2)
}

/// C++ `istream >> uint8` with base detection (`unsetf(dec|hex|oct)`):
/// `0x` hex, a leading `0` octal, else decimal; the longest valid prefix.
/// Overflow saturates, as `num_get` does.
fn parse_c_integer(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let (radix, digits) = if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] | 0x20) == b'x' {
        (16, &bytes[2..])
    } else if bytes.first() == Some(&b'0') {
        (8, &bytes[1..])
    } else {
        (10, bytes)
    };
    let mut value: u64 = 0;
    for &b in digits {
        let Some(d) = char::from(b).to_digit(radix) else {
            break;
        };
        value = match value
            .checked_mul(u64::from(radix))
            .and_then(|v| v.checked_add(u64::from(d)))
        {
            Some(v) => v,
            None => return u64::MAX,
        };
    }
    value
}

impl Database {
    /// The child of `scope` named `name` (Ghidra `Scope::resolveScope`):
    /// with hashed ids the child of the hashed id if its name matches;
    /// otherwise a name starting with a digit is an id, else the first child
    /// in id order with that name.
    pub fn resolve_child(&self, scope: ScopeId, name: &str) -> Option<ScopeId> {
        let data = self.scope(scope).ok()?;
        if self.id_by_name_hash {
            let key = hash_scope_name(data.ghidra_id, name);
            let child = *data.children.get(&key)?;
            return (self.scope(child).ok()?.name.as_ref() == name).then_some(child);
        }
        if name.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            return data.children.get(&parse_c_integer(name)).copied();
        }
        data.children
            .values()
            .copied()
            .find(|c| self.scope(*c).is_ok_and(|s| s.name.as_ref() == name))
    }

    /// Splits a full symbol name at the scope delimiter (never inside
    /// template arguments) and resolves the scopes (Ghidra
    /// `resolveScopeFromSymbolName`). Returns the scope and the base name.
    pub fn resolve_scope_from_symbol_name<'n>(
        &self,
        full: &'n str,
        start: Option<ScopeId>,
    ) -> Option<(ScopeId, &'n str)> {
        let mut scope = start.or(self.global)?;
        let delim = self.env.scope_delimiter.clone();
        let template = full.find('<');
        let mut mark = 0usize;
        loop {
            let Some(rel) = full.get(mark..).and_then(|rest| rest.find(delim.as_ref())) else {
                break;
            };
            let end = mark + rel;
            if template.is_some_and(|t| end > t) {
                break;
            }
            if end == 0 {
                scope = self.global?;
            } else {
                let component = full.get(mark..end)?;
                scope = self.resolve_child(scope, component)?;
            }
            mark = end + delim.len();
        }
        Some((scope, full.get(mark..)?))
    }

    /// Like [`resolve_scope_from_symbol_name`](Self::resolve_scope_from_symbol_name)
    /// but creates missing namespaces with hashed ids (Ghidra
    /// `findCreateScopeFromSymbolName`). An empty component is hashed like
    /// any other, as in Ghidra.
    pub fn find_create_scope_from_symbol_name<'n>(
        &mut self,
        full: &'n str,
        start: Option<ScopeId>,
    ) -> Result<(ScopeId, &'n str)> {
        let mut scope = match start.or(self.global) {
            Some(s) => s,
            None => self.global_scope()?,
        };
        let delim = self.env.scope_delimiter.clone();
        let template = full.find('<');
        let mut mark = 0usize;
        let mut components = 0usize;
        loop {
            let Some(rel) = full.get(mark..).and_then(|rest| rest.find(delim.as_ref())) else {
                break;
            };
            let end = mark + rel;
            if template.is_some_and(|t| end > t) {
                break;
            }
            if !self.id_by_name_hash {
                return Err(SymbolError::ScopeHashes);
            }
            components += 1;
            if components > limits::MAX_PATH {
                return Err(SymbolError::Limit("namespace path length"));
            }
            let component = full.get(mark..end).unwrap_or("");
            let id = hash_scope_name(self.scope(scope)?.ghidra_id, component);
            scope = self.find_create_scope(id, component, Some(scope))?;
            mark = end + delim.len();
        }
        Ok((scope, full.get(mark..).unwrap_or("")))
    }

    /// The scope's name with its ancestors', joined by the delimiter;
    /// empty for the global scope (Ghidra `getFullName`).
    pub fn full_name(&self, scope: ScopeId) -> String {
        let Ok(data) = self.scope(scope) else {
            return String::new();
        };
        if data.parent.is_none() {
            return String::new();
        }
        let mut name = data.name.to_string();
        let mut cur = data.parent;
        let mut guard = 0;
        while let Some(p) = cur {
            let Ok(pd) = self.scope(p) else { break };
            if pd.parent.is_none() || guard > limits::MAX_SCOPE_DEPTH {
                break;
            }
            name = format!("{}{}{}", pd.name, self.env.scope_delimiter, name);
            cur = pd.parent;
            guard += 1;
        }
        name
    }

    /// The scopes from the global scope down to `scope` (Ghidra
    /// `getScopePath`).
    pub fn scope_path(&self, scope: ScopeId) -> Vec<ScopeId> {
        let mut path = Vec::new();
        let mut cur = Some(scope);
        while let Some(id) = cur {
            if path.len() > limits::MAX_SCOPE_DEPTH {
                break;
            }
            path.push(id);
            cur = self.scope(id).ok().and_then(|s| s.parent);
        }
        path.reverse();
        path
    }

    /// Whether `other` is `scope` or one of its ancestors (Ghidra
    /// `isSubScope`).
    pub fn is_sub_scope(&self, scope: ScopeId, other: ScopeId) -> bool {
        self.scope_path(scope).contains(&other)
    }

    /// The first ancestor of `scope` that `other` does not share (Ghidra
    /// `findDistinguishingScope`); `None` when `scope` is `other` or an
    /// ancestor of it.
    pub fn find_distinguishing_scope(&self, scope: ScopeId, other: ScopeId) -> Option<ScopeId> {
        if scope == other {
            return None;
        }
        let parent = self.scope(scope).ok()?.parent;
        let other_parent = self.scope(other).ok()?.parent;
        if parent == Some(other) {
            return Some(scope);
        }
        if other_parent == Some(scope) {
            return None;
        }
        if parent == other_parent {
            return Some(scope);
        }
        let this_path = self.scope_path(scope);
        let other_path = self.scope_path(other);
        let min = this_path.len().min(other_path.len());
        for i in 0..min {
            if this_path.get(i) != other_path.get(i) {
                return this_path.get(i).copied();
            }
        }
        if min < this_path.len() {
            return this_path.get(min).copied();
        }
        if min < other_path.len() {
            return None;
        }
        Some(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_integers_detect_their_base() {
        assert_eq!(parse_c_integer("0x1f"), 0x1f);
        assert_eq!(parse_c_integer("017"), 0o17);
        assert_eq!(parse_c_integer("19z"), 19);
        assert_eq!(parse_c_integer("0"), 0);
        assert_eq!(parse_c_integer("0x"), 0);
        assert_eq!(parse_c_integer("99999999999999999999999"), u64::MAX);
        assert_eq!(crc_update(0, 0), 0);
        assert_eq!(CRC_TABLE[1], 0x7707_3096);
    }
}
