//! The scope resolve map (Ghidra `ScopeResolve`, `clearResolve`,
//! `fillResolve`, `mapScope`; database.cc 3055–3100, 3373–3400).

use std::cmp::Ordering;

use bk_core::{Address, Range};

use super::Database;
use crate::entrymap::{Line, NullSubsort};
use crate::error::Result;
use crate::ids::ScopeId;

/// An address as the resolve map's line type: ordered as Ghidra orders
/// addresses, with `±1` wrapping inside the address's space (Ghidra's
/// `Address::operator+`/`-`).
#[derive(Clone, Copy, Debug)]
pub struct ResolveLine {
    addr: Address,
    highest: u64,
}

impl ResolveLine {
    /// The line point of an address in a space whose highest offset is
    /// `highest`.
    pub fn new(addr: Address, highest: u64) -> Self {
        Self { addr, highest }
    }

    /// The address.
    pub fn addr(self) -> Address {
        self.addr
    }
}

impl PartialEq for ResolveLine {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}
impl Eq for ResolveLine {}
impl PartialOrd for ResolveLine {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ResolveLine {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl Line for ResolveLine {
    fn prev(self) -> Self {
        let off = self.addr.offset();
        let new = if off == 0 { self.highest } else { off - 1 };
        Self {
            addr: with_offset(self.addr, new),
            ..self
        }
    }
    fn next(self) -> Self {
        let off = self.addr.offset();
        let new = if off >= self.highest { 0 } else { off + 1 };
        Self {
            addr: with_offset(self.addr, new),
            ..self
        }
    }
}

fn with_offset(addr: Address, offset: u64) -> Address {
    match addr.space() {
        Some(space) => Address::new(space, offset),
        None => addr,
    }
}

impl Database {
    pub(crate) fn line(&self, addr: Address) -> ResolveLine {
        let highest = self
            .env
            .spaces
            .space_of(addr)
            .map_or(u64::MAX, bk_core::Space::highest);
        ResolveLine::new(addr, highest)
    }

    fn applies_to_resolve(&self, scope: ScopeId) -> Result<bool> {
        let data = self.scope(scope)?;
        Ok(self.global != Some(scope) && data.is_global())
    }

    /// Ghidra `clearResolve`: for each owned range, erases the first resolve
    /// record of this scope in the piece at the range's start.
    pub(crate) fn clear_resolve(&mut self, scope: ScopeId) -> Result<()> {
        if !self.applies_to_resolve(scope)? {
            return Ok(());
        }
        let ranges: Vec<Range> = self.scope(scope)?.ranges.iter().collect();
        for range in ranges {
            let line = self.line(range.first_addr());
            let hit = self
                .resolve
                .find(line)
                .find(|frag| frag.value == scope)
                .map(|frag| frag.record);
            if let Some(record) = hit {
                self.resolve.erase(record);
            }
        }
        Ok(())
    }

    /// Ghidra `fillResolve`: one resolve record per owned range.
    pub(crate) fn fill_resolve(&mut self, scope: ScopeId) -> Result<()> {
        if !self.applies_to_resolve(scope)? {
            return Ok(());
        }
        let ranges: Vec<Range> = self.scope(scope)?.ranges.iter().collect();
        for range in ranges {
            let first = self.line(range.first_addr());
            let last = self.line(range.last_addr());
            self.resolve.insert(scope, first, last, NullSubsort);
        }
        Ok(())
    }

    /// The scope a query from `from` at `addr` starts in (Ghidra
    /// `mapScope`): the scope of the first resolve fragment containing
    /// `addr`, else `from`. The use point is ignored, as in Ghidra.
    pub fn map_scope(&self, from: ScopeId, addr: Address) -> ScopeId {
        if self.resolve.is_empty() {
            return from;
        }
        self.resolve
            .find(self.line(addr))
            .next()
            .map_or(from, |frag| frag.value)
    }

    /// The resolve map's records in list order: `(scope, first, last)`.
    pub fn resolve_records(&self) -> impl Iterator<Item = (ScopeId, Address, Address)> + '_ {
        self.resolve.records().filter_map(|(rec, scope)| {
            let (a, b) = self.resolve.bounds(rec)?;
            Some((scope, a.addr(), b.addr()))
        })
    }
}
