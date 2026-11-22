//! Cursors over the two varnode orders, whole or over one range, with the
//! semantics of Ghidra's `vn = *iter++` loops between a begin and an end
//! iterator taken before the loop (`beginLoc(spc)`..`endLoc(spc)` and the
//! other pairs, `varnode.cc:1554`–`1961`; the loops of `Heritage::collect`,
//! `processJoins`, heritage.cc:307–360, 2272–2310, and
//! `clearDeadVarnodes`, `funcdata_varnode.cc:860`).
//!
//! A cursor holds keys, not borrows, so the body may create and destroy
//! varnodes between steps:
//!
//! * each step returns the current varnode and remembers its successor *at
//!   that time* (`iter++` before the body runs): a varnode inserted between
//!   the current one and that successor is not visited; one inserted after
//!   it, up to the end, is;
//! * the end is the varnode the end iterator named when the cursor was
//!   made, not a key bound: as in Ghidra, a varnode inserted after the
//!   range's last member but before that end varnode *is* visited
//!   (`processJoins` checks the space of each varnode for this reason,
//!   heritage.cc:2282); an end of `end()` means the rest of the order;
//! * where Ghidra's behaviour is undefined (the remembered successor or the
//!   end varnode destroyed in the body), the walk goes on from the first
//!   key after the remembered one and stops at the first key at or after
//!   the end's.

use std::collections::BTreeMap;
use std::ops::Bound;

use bk_core::{Address, SpaceId};

use super::keys::{DefKey, LocKey};
use super::range::{DefBounds, LocBounds, VnClass, crossed};
use crate::error::IrResult;
use crate::ids::VarnodeId;
use crate::ssa::Ssa;

/// The first key of `map` at or after `lo` (the begin iterator).
fn first_from<K: Ord + Copy>(map: &BTreeMap<K, VarnodeId>, lo: Bound<K>) -> Option<K> {
    map.range((lo, Bound::Unbounded)).next().map(|(k, _)| *k)
}

/// The first key of `map` past `hi` (the end iterator; `None` is `end()`).
fn first_past<K: Ord + Copy>(map: &BTreeMap<K, VarnodeId>, hi: Bound<K>) -> Option<K> {
    let past = match hi {
        Bound::Included(k) => Bound::Excluded(k),
        Bound::Excluded(k) => Bound::Included(k),
        Bound::Unbounded => return None,
    };
    map.range((past, Bound::Unbounded)).next().map(|(k, _)| *k)
}

/// One step of a cursor over `map`.
fn step<K: Ord + Copy>(
    map: &BTreeMap<K, VarnodeId>,
    pending: &mut Option<K>,
    end: Option<K>,
) -> Option<VarnodeId> {
    let k = (*pending)?;
    let Some((&cur, &vn)) = map.range(k..).next() else {
        *pending = None;
        return None;
    };
    if end.is_some_and(|e| cur >= e) {
        *pending = None;
        return None;
    }
    *pending = map
        .range((Bound::Excluded(cur), Bound::Unbounded))
        .next()
        .map(|(k, _)| *k);
    Some(vn)
}

/// (begin, pending, end): the begin iterator's key, the first key to
/// visit (none when the range is empty) and the end iterator's key.
fn make<K: Ord + Copy>(
    map: &BTreeMap<K, VarnodeId>,
    (lo, hi): (Bound<K>, Bound<K>),
) -> (Option<K>, Option<K>, Option<K>) {
    let begin = first_from(map, lo);
    if crossed(&lo, &hi) {
        return (begin, None, None);
    }
    let end = first_past(map, hi);
    let pending = begin.filter(|&p| end.is_none_or(|e| p < e));
    (begin, pending, end)
}

/// Steps through loc order, whole or over one range (see the module
/// documentation for what it sees of changes made between steps).
#[derive(Clone, Copy, Debug)]
pub struct LocCursor {
    begin: Option<LocKey>,
    pending: Option<LocKey>,
    end: Option<LocKey>,
}

impl LocCursor {
    fn new(ssa: &Ssa, bounds: LocBounds) -> Self {
        let (begin, pending, end) = make(&ssa.loc, bounds);
        Self {
            begin,
            pending,
            end,
        }
    }

    /// The next varnode, or `None` at the end.
    pub fn next(&mut self, ssa: &Ssa) -> Option<VarnodeId> {
        step(&ssa.loc, &mut self.pending, self.end)
    }

    /// This cursor (not yet stepped) running from its begin to where
    /// `other` begins: a loop from one `beginLoc` to another, as
    /// `Heritage::collect`'s `beginLoc(addr)`..`beginLoc(endaddr)`
    /// (heritage.cc:315–323).
    #[must_use]
    pub fn until_start_of(self, other: &Self) -> Self {
        self.with_end(other.begin)
    }

    /// This cursor (not yet stepped) running from its begin to where
    /// `other` ends, as `Heritage::collect`'s `endLoc(tmp)` after a
    /// wraparound (heritage.cc:317–319).
    #[must_use]
    pub fn until_end_of(self, other: &Self) -> Self {
        self.with_end(other.end)
    }

    fn with_end(mut self, end: Option<LocKey>) -> Self {
        self.end = end;
        self.pending = self.begin.filter(|&p| end.is_none_or(|e| p < e));
        self
    }
}

/// [`LocCursor`] for def order.
#[derive(Clone, Copy, Debug)]
pub struct DefCursor {
    pending: Option<DefKey>,
    end: Option<DefKey>,
}

impl DefCursor {
    fn new(ssa: &Ssa, bounds: DefBounds) -> Self {
        let (_, pending, end) = make(&ssa.def, bounds);
        Self { pending, end }
    }

    /// The next varnode, or `None` at the end.
    pub fn next(&mut self, ssa: &Ssa) -> Option<VarnodeId> {
        step(&ssa.def, &mut self.pending, self.end)
    }
}

impl Ssa {
    /// A cursor over all of loc order (`beginLoc()`..`endLoc()`).
    pub fn loc_cursor(&self) -> LocCursor {
        LocCursor::new(self, (Bound::Unbounded, Bound::Unbounded))
    }

    /// A cursor over all of def order (`beginDef()`..`endDef()`).
    pub fn def_cursor(&self) -> DefCursor {
        DefCursor::new(self, (Bound::Unbounded, Bound::Unbounded))
    }

    /// A cursor over [`Ssa::loc_in_space`] (`beginLoc(spc)`..`endLoc(spc)`).
    pub fn loc_cursor_in_space(&self, space: SpaceId) -> LocCursor {
        LocCursor::new(self, self.loc_in_space_bounds(space))
    }

    /// A cursor over [`Ssa::loc_at`] (`beginLoc(addr)`..`endLoc(addr)`).
    pub fn loc_cursor_at(&self, addr: Address) -> LocCursor {
        LocCursor::new(self, self.loc_at_bounds(addr))
    }

    /// A cursor over [`Ssa::loc_sized`] (`beginLoc(s,addr)`..`endLoc(s,addr)`).
    pub fn loc_cursor_sized(&self, size: i32, addr: Address) -> LocCursor {
        LocCursor::new(self, Self::loc_sized_bounds(size, addr))
    }

    /// A cursor over [`Ssa::loc_class`]
    /// (`beginLoc(s,addr,fl)`..`endLoc(s,addr,fl)`).
    pub fn loc_cursor_class(&self, size: i32, addr: Address, class: VnClass) -> LocCursor {
        LocCursor::new(self, Self::loc_class_bounds(size, addr, class))
    }

    /// A cursor over [`Ssa::loc_defined`]
    /// (`beginLoc(s,addr,pc,uniq)`..`endLoc(s,addr,pc,uniq)`).
    pub fn loc_cursor_defined(
        &self,
        size: i32,
        addr: Address,
        pc: Address,
        uniq: Option<u32>,
    ) -> LocCursor {
        LocCursor::new(self, Self::loc_defined_bounds(size, addr, pc, uniq))
    }

    /// A cursor over [`Ssa::def_class`] (`beginDef(fl)`..`endDef(fl)`).
    pub fn def_cursor_class(&self, class: VnClass) -> DefCursor {
        DefCursor::new(self, Self::def_class_bounds(class))
    }

    /// A cursor over [`Ssa::def_class_at`]
    /// (`beginDef(fl,addr)`..`endDef(fl,addr)`); written varnodes are
    /// refused as there.
    pub fn def_cursor_class_at(&self, class: VnClass, addr: Address) -> IrResult<DefCursor> {
        Ok(DefCursor::new(
            self,
            Self::def_class_addr_bounds(class, addr)?,
        ))
    }
}
