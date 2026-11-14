//! Enumerations (Ghidra `getTypeEnum`, `setEnumValues`,
//! `TypeEnum::assignValues`, `getMatches`, `hasNamedValue` and the
//! `TypePartialEnum` versions).

use std::collections::BTreeMap;

use bk_core::bits::{calc_mask, coveringmask};

use crate::entry::{EnumValues, TypeEntry, TypeFlags, TypeKind, hash_name};
use crate::error::{Result, TypeError};
use crate::factory::TypeFactory;
use crate::ids::TypeId;
use crate::meta::Metatype;

/// How a value is written with an enumeration's names (Ghidra
/// `TypeEnum::Representation`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Representation {
    /// Names ORed together; empty when no representation exists.
    pub names: Vec<String>,
    /// Whether the ORed value is complemented.
    pub complement: bool,
    /// Left shift applied to the final value (partial enumerations).
    pub shift: i32,
}

/// One enumerator of a declaration: a name and an optional explicit value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enumerator {
    /// The name.
    pub name: String,
    /// The value, if given.
    pub value: Option<u64>,
}

/// Builds the candidate for `TypeEnum(size, m, name)`.
pub(crate) fn enum_entry(size: i32, meta: Metatype, name: &str) -> TypeEntry {
    let internal = if meta == Metatype::EnumInt {
        Metatype::Int
    } else {
        Metatype::Uint
    };
    let mut e = TypeEntry::new(size, -1, meta, TypeKind::Enum(Box::default()));
    e.flags |= TypeFlags::ENUMTYPE;
    e.metatype = internal;
    if !name.is_empty() {
        e.set_name(name, 0);
    }
    e
}

/// Ghidra `TypeEnum::assignValues`: values for the names, explicit ones
/// first (masked to the size), the rest counting up from the largest seen.
pub fn assign_values(
    list: &[Enumerator],
    size: i32,
    type_name: &str,
) -> Result<BTreeMap<u64, Box<str>>> {
    let mask = calc_mask(size.max(0) as u32);
    let mut map: BTreeMap<u64, Box<str>> = BTreeMap::new();
    let mut maxval: u64 = 0;
    for en in list {
        if let Some(v) = en.value {
            if v > maxval {
                maxval = v;
            }
            let v = v & mask;
            if map.contains_key(&v) {
                return Err(TypeError::new(format!(
                    "Enum \"{type_name}\": \"{}\" is a duplicate value",
                    en.name
                )));
            }
            map.insert(v, en.name.as_str().into());
        }
    }
    for en in list.iter().filter(|e| e.value.is_none()) {
        let mut guard: u64 = 0;
        let v = loop {
            maxval = maxval.wrapping_add(1);
            let v = maxval & mask;
            if !map.contains_key(&v) {
                break v;
            }
            guard += 1;
            if guard > map.len() as u64 + 1 {
                return Err(TypeError::new(format!(
                    "Enum \"{type_name}\": no value left"
                )));
            }
        };
        map.insert(v, en.name.as_str().into());
    }
    Ok(map)
}

impl TypeFactory {
    /// Ghidra `getTypeEnum`: an empty enumeration with the factory's
    /// enumeration size and signedness.
    pub fn enum_stub(&mut self, name: &str) -> Result<TypeId> {
        let mut tmp = enum_entry(self.org.enum_size, self.org.enum_metatype(), name);
        tmp.set_name(name, hash_name(name));
        self.find_add(tmp)
    }

    /// Ghidra `setEnumValues`: installs the value map.
    pub fn set_enum_values(&mut self, id: TypeId, values: BTreeMap<u64, Box<str>>) -> Result<()> {
        if !matches!(self.entry_checked(id)?.kind, TypeKind::Enum(_)) {
            return Err(TypeError::new("Not an enumeration"));
        }
        self.modify(id, |e| {
            e.kind = TypeKind::Enum(Box::new(EnumValues { values }))
        })
    }

    /// Ghidra `hasNamedValue` (of an enumeration or a partial enumeration).
    pub fn has_named_value(&self, id: TypeId, val: u64) -> bool {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Enum(v) => v.values.contains_key(&val),
            TypeKind::PartialEnum { parent, offset, .. } => {
                self.has_named_value(*parent, shl(val, offset.saturating_mul(8)))
            }
            _ => false,
        }
    }

    /// Ghidra `getMatches`: `val` as an OR of names, possibly complemented.
    pub fn enum_matches(&self, id: TypeId, val: u64) -> Representation {
        let e = self.entry(id);
        match &e.kind {
            TypeKind::Enum(v) => matches_in(&v.values, e.size, val),
            TypeKind::PartialEnum { parent, offset, .. } => {
                let shift = offset.saturating_mul(8);
                let p = self.entry(*parent);
                let mut rep = match &p.kind {
                    TypeKind::Enum(v) => matches_in(&v.values, p.size, shl(val, shift)),
                    _ => Representation::default(),
                };
                rep.shift = shift;
                rep
            }
            _ => Representation::default(),
        }
    }
}

/// Left shift with Ghidra's x86-64 meaning for in-range counts and 0 past
/// the width (where C++ is undefined).
fn shl(val: u64, by: i32) -> u64 {
    u32::try_from(by)
        .ok()
        .and_then(|b| val.checked_shl(b))
        .unwrap_or(0)
}

fn matches_in(map: &BTreeMap<u64, Box<str>>, size: i32, mut val: u64) -> Representation {
    let mut rep = Representation::default();
    for count in 0..2 {
        let allmatch = if val == 0 {
            match map.get(&0) {
                Some(n) => {
                    rep.names.push(n.to_string());
                    true
                }
                None => false,
            }
        } else {
            let mut bitsleft = val;
            let mut target = val;
            while target != 0 {
                let Some((&curval, name)) = map.range(..=target).next_back() else {
                    break;
                };
                let diff = coveringmask(bitsleft ^ curval);
                if diff >= bitsleft {
                    break;
                }
                if curval & diff == 0 {
                    rep.names.push(name.to_string());
                    bitsleft ^= curval;
                    target = bitsleft;
                } else {
                    target = curval & !diff;
                }
            }
            bitsleft == 0
        };
        if allmatch {
            rep.complement = count == 1;
            return rep;
        }
        val ^= calc_mask(size.max(0) as u32);
        rep.names.clear();
    }
    rep
}
