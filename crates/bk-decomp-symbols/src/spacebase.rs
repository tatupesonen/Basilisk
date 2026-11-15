//! `bk-decomp-types`' `SpacebaseScopes` over a frozen database (spec 5.5;
//! Ghidra `TypeSpacebase::getSubType`, `nearestArrayedComponentForward`/
//! `Backward`, type.cc 3340–3495).

use std::sync::Arc;

use bk_core::{Address, SpaceId};
use bk_decomp_types::xml::SpacebaseScopes;
use bk_decomp_types::{Metatype, Nearest, TypeFactory, TypeId};

use crate::database::Database;
use crate::ids::{EntryId, ScopeId};
use crate::model::{EntryKind, ScopeKind};

/// Ghidra `TypeSpacebase::MAX_ARRAY_SLACK_FORWARD`.
const SLACK_FORWARD: i64 = 128;
/// Ghidra `TypeSpacebase::MAX_ARRAY_SLACK_BACKWARD`.
const SLACK_BACKWARD: i64 = 8;

/// The scope look-ups behind `TypeSpacebase`, over a frozen database and
/// the frozen type factory its symbols' types live in.
#[derive(Debug, Clone)]
pub struct DatabaseScopes {
    db: Arc<Database>,
    types: Arc<TypeFactory>,
    undefined1: TypeId,
}

impl DatabaseScopes {
    /// The view; `undefined1` is the factory's one-byte undefined type
    /// (Ghidra's `getBase(1, TYPE_UNKNOWN)`, the answer inside a scope with
    /// no symbol there).
    pub fn new(db: Arc<Database>, types: Arc<TypeFactory>, undefined1: TypeId) -> Self {
        Self {
            db,
            types,
            undefined1,
        }
    }

    fn scope(&self, id: u64) -> Option<ScopeId> {
        self.db.resolve_scope_id(id)
    }

    /// Ghidra `resolveConstant` with size −1 and no point.
    fn address(&self, space: SpaceId, off: i64) -> Option<Address> {
        let spc = self.db.spaces().space(space)?;
        let unit = spc.byte_to_address(off as u64);
        let (addr, _) = self
            .db
            .spaces()
            .resolve_constant(space, unit, u32::MAX, Address::INVALID)
            .ok()?;
        Some(addr)
    }

    fn entry_parts(&self, e: EntryId) -> Option<(Address, i32, TypeId)> {
        let entry = self.db.entry(e).ok()?;
        let EntryKind::Map { addr, .. } = entry.kind() else {
            return None;
        };
        let ty = self.db.symbol(entry.symbol()).ok()?.type_id();
        Some((addr, entry.offset(), ty))
    }
}

impl SpacebaseScopes for DatabaseScopes {
    fn frame_of_scope(&self, scope: u64) -> Option<(SpaceId, u64)> {
        let s = self.scope(scope)?;
        let ScopeKind::Function(sym) = self.db.scope(s).ok()?.kind() else {
            return None;
        };
        let e = self.db.first_whole_map(sym).ok()?;
        let addr = self.db.entry(e).ok()?.addr()?;
        Some((addr.space()?, addr.offset()))
    }

    fn scope_of_frame(&self, frame: Option<(SpaceId, u64)>) -> u64 {
        let Some(global) = self.db.global() else {
            return 0;
        };
        let global_id = self.db.scope(global).map_or(0, |s| s.ghidra_id());
        let Some((space, off)) = frame else {
            return global_id;
        };
        let Ok(Some(sym)) = self.db.query_function(global, Address::new(space, off)) else {
            return global_id;
        };
        self.db
            .scope_ids()
            .find(|s| {
                self.db
                    .scope(*s)
                    .is_ok_and(|d| d.kind() == ScopeKind::Function(sym))
            })
            .and_then(|s| self.db.scope(s).ok())
            .map_or(global_id, |d| d.ghidra_id())
    }

    fn sub_type(&self, space: SpaceId, scope: u64, off: i64) -> Option<(TypeId, i64)> {
        let s = self.scope(scope)?;
        let addr = self.address(space, off)?;
        match self.db.query_container(s, addr, 1, Address::INVALID).ok()? {
            Some(e) => {
                let (start, offset, ty) = self.entry_parts(e)?;
                let newoff = (addr.offset().wrapping_sub(start.offset()) as i64)
                    .wrapping_add(i64::from(offset));
                Some((ty, newoff))
            }
            None => self
                .db
                .in_scope(s, addr, 1)
                .ok()?
                .then_some((self.undefined1, 0)),
        }
    }

    fn nearest(&self, space: SpaceId, scope: u64, off: i64, forward: bool) -> Option<Nearest> {
        let s = self.scope(scope)?;
        let addr = self.address(space, off)?;
        let types = &self.types;
        let at = self.db.query_container(s, addr, 1, Address::INVALID).ok()?;
        let mut max = SLACK_BACKWARD;
        if let Some((start, 0, ty)) = at.and_then(|e| self.entry_parts(e)) {
            let struct_off = addr.offset().wrapping_sub(start.offset()) as i64;
            let found = if forward {
                types.nearest_forward(ty, struct_off)
            } else {
                types.nearest_backward(ty, struct_off)
            };
            if let Some(mut res) = found {
                res.offset = struct_off;
                return Some(res);
            }
        } else if !forward {
            max = SLACK_FORWARD;
        }
        let mut next = addr;
        for _ in 0..=SLACK_FORWARD {
            let e = if forward {
                self.db.find_symbol_after(s, next, Address::INVALID).ok()?
            } else {
                self.db.find_symbol_before(s, next, Address::INVALID).ok()?
            };
            let (start, offset, ty) = e.and_then(|e| self.entry_parts(e))?;
            if offset != 0 {
                return None;
            }
            next = start;
            let struct_off = addr.offset().wrapping_sub(next.offset()) as i64;
            let entry = types.get(ty)?;
            let size = i64::from(entry.size());
            let is_array = entry.metatype() == Metatype::Array;
            let res = if forward {
                types.nearest_forward(ty, 0).map(|mut r| {
                    r.distance -= struct_off;
                    r
                })
            } else {
                types.nearest_backward(ty, size).map(|mut r| {
                    r.distance = r.distance + struct_off - size;
                    r
                })
            };
            if let Some(mut r) = res {
                r.offset = struct_off;
                let limit = if forward { SLACK_FORWARD } else { max };
                if r.distance > limit {
                    return None;
                }
                if r.distance <= size || is_array {
                    return Some(r);
                }
            }
            let gap = if forward {
                next.offset().wrapping_sub(addr.offset()) as i64
            } else {
                addr.offset().wrapping_sub(next.offset()) as i64
            };
            if gap >= if forward { SLACK_FORWARD } else { max } {
                return None;
            }
        }
        None
    }
}
