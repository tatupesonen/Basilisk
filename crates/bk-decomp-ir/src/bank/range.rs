//! Range queries and cursors over the two varnode orders (Ghidra
//! `VarnodeBank::beginLoc`/`endLoc`/`beginDef`/`endDef`, `find`,
//! `findInput`, `findCoveredInput`, `findCoveringInput`,
//! `hasInputIntersection`, `overlapLoc`; varnode.cc:1428–1961).
//!
//! Ghidra searches with a template varnode (an input of size 0 at the
//! minimal address) whose fields it sets per query; here each query builds
//! the equivalent key. A begin/end pair of Ghidra's is one method returning
//! the range between them.

use std::collections::BTreeMap;
use std::ops::Bound;

use bk_core::{Address, SpaceId};

use super::keys::{
    DefKey, FREE_CLASS, INPUT_CLASS, LocKey, SEQ_MAX, SEQ_MIN, SeqKey, WRITTEN_CLASS,
};
use crate::error::{IrError, IrResult};
use crate::flags::vflags;
use crate::ids::VarnodeId;
use crate::ssa::Ssa;

/// Which varnodes a class-restricted query wants (Ghidra passes
/// `Varnode::input`, `Varnode::written` or 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VnClass {
    /// Inputs to the function.
    Input,
    /// Varnodes written by an op.
    Written,
    /// Free varnodes.
    Free,
}

const fn lk(addr: Address, size: i32, class: u32, seq: SeqKey) -> LocKey {
    LocKey {
        addr,
        size,
        class,
        seq,
        create: 0,
    }
}

const fn dk(class: u32, seq: SeqKey, addr: Address, size: i32) -> DefKey {
    DefKey {
        class,
        seq,
        addr,
        size,
        create: 0,
    }
}

/// Whether a bound pair is crossed (`BTreeMap::range` panics on one).
pub(crate) fn crossed<K: Ord>(lo: &Bound<K>, hi: &Bound<K>) -> bool {
    match (lo, hi) {
        (Bound::Included(a), Bound::Included(b)) => a > b,
        (Bound::Included(a) | Bound::Excluded(a), Bound::Excluded(b))
        | (Bound::Excluded(a), Bound::Included(b)) => a >= b,
        _ => false,
    }
}

/// A range of a map that never panics on crossed bounds.
fn safe_range<K: Ord + Copy>(
    map: &BTreeMap<K, VarnodeId>,
    lo: Bound<K>,
    hi: Bound<K>,
) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
    let r = (!crossed(&lo, &hi)).then(|| map.range((lo, hi)));
    r.into_iter().flatten().map(|(_, v)| *v)
}

fn lower<K>(k: K) -> Bound<K> {
    Bound::Included(k)
}

fn upper<K>(k: K) -> Bound<K> {
    Bound::Excluded(k)
}

/// The `end` of a half-open range from a Ghidra `lower_bound`.
fn before<K>(k: K) -> Bound<K> {
    Bound::Excluded(k)
}

/// The `end` of a half-open range from a Ghidra `upper_bound`.
fn through<K>(k: K) -> Bound<K> {
    Bound::Included(k)
}

impl Ssa {
    /// The number of varnodes (`numVarnodes`).
    pub fn num_varnodes(&self) -> usize {
        self.loc.len()
    }

    /// Every varnode in loc order (`beginLoc()`..`endLoc()`).
    pub fn loc_order(&self) -> impl Iterator<Item = VarnodeId> + '_ {
        self.loc.values().copied()
    }

    /// Every varnode in def order (`beginDef()`..`endDef()`).
    pub fn def_order(&self) -> impl Iterator<Item = VarnodeId> + '_ {
        self.def.values().copied()
    }

    fn next_space_start(&self, space: SpaceId) -> Address {
        self.spaces
            .next_space_after(space)
            .map_or(Address::MAXIMAL, |s| Address::new(s, 0))
    }

    /// The varnodes of one space in loc order (`beginLoc(spc)`..`endLoc(spc)`).
    pub fn loc_in_space(
        &self,
        space: SpaceId,
    ) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let lo = lk(Address::new(space, 0), 0, INPUT_CLASS, SEQ_MIN);
        let hi = lk(self.next_space_start(space), 0, INPUT_CLASS, SEQ_MIN);
        safe_range(&self.loc, lower(lo), before(hi))
    }

    /// The varnodes starting at `addr` (`beginLoc(addr)`..`endLoc(addr)`).
    pub fn loc_at(&self, addr: Address) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let lo = lk(addr, 0, INPUT_CLASS, SEQ_MIN);
        let end = match addr.space() {
            Some(space)
                if self
                    .spaces
                    .space(space)
                    .is_some_and(|s| s.highest() == addr.offset()) =>
            {
                self.next_space_start(space)
            }
            Some(space) => Address::new(space, addr.offset().wrapping_add(1)),
            None => Address::MAXIMAL,
        };
        safe_range(
            &self.loc,
            lower(lo),
            before(lk(end, 0, INPUT_CLASS, SEQ_MIN)),
        )
    }

    /// The varnodes of size `size` at `addr` (`beginLoc(s,addr)`..`endLoc(s,addr)`).
    pub fn loc_sized(
        &self,
        size: i32,
        addr: Address,
    ) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let lo = lk(addr, size, INPUT_CLASS, SEQ_MIN);
        let hi = lk(addr, size.saturating_add(1), INPUT_CLASS, SEQ_MIN);
        safe_range(&self.loc, lower(lo), before(hi))
    }

    fn loc_class_bounds(
        size: i32,
        addr: Address,
        class: VnClass,
    ) -> (Bound<LocKey>, Bound<LocKey>) {
        let begin = match class {
            VnClass::Input => lower(lk(addr, size, INPUT_CLASS, SEQ_MIN)),
            VnClass::Written => lower(lk(addr, size, WRITTEN_CLASS, SEQ_MIN)),
            VnClass::Free => upper(lk(addr, size, WRITTEN_CLASS, SEQ_MAX)),
        };
        let end = match class {
            VnClass::Written => through(lk(addr, size, WRITTEN_CLASS, SEQ_MAX)),
            VnClass::Input => through(lk(addr, size, INPUT_CLASS, SEQ_MIN)),
            VnClass::Free => before(lk(addr, size.saturating_add(1), INPUT_CLASS, SEQ_MIN)),
        };
        (begin, end)
    }

    /// The varnodes of one class, size and address
    /// (`beginLoc(s,addr,fl)`..`endLoc(s,addr,fl)`).
    pub fn loc_class(
        &self,
        size: i32,
        addr: Address,
        class: VnClass,
    ) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let (lo, hi) = Self::loc_class_bounds(size, addr, class);
        safe_range(&self.loc, lo, hi)
    }

    /// The written varnodes of a size and address defined at `pc`, from the
    /// op with time `uniq` on (`None`: any time)
    /// (`beginLoc(s,addr,pc,uniq)`..`endLoc(s,addr,pc,uniq)`).
    pub fn loc_defined(
        &self,
        size: i32,
        addr: Address,
        pc: Address,
        uniq: Option<u32>,
    ) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let lo = lk(addr, size, WRITTEN_CLASS, (pc, uniq.unwrap_or(0)));
        let hi = lk(addr, size, WRITTEN_CLASS, (pc, uniq.unwrap_or(u32::MAX)));
        safe_range(&self.loc, lower(lo), through(hi))
    }

    /// The varnodes of one class in def order (`beginDef(fl)`..`endDef(fl)`).
    pub fn def_class(
        &self,
        class: VnClass,
    ) -> impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_ {
        let first_written = dk(WRITTEN_CLASS, SEQ_MIN, Address::MINIMAL, 0);
        let last_written = dk(WRITTEN_CLASS, SEQ_MAX, Address::MAXIMAL, 0);
        match class {
            VnClass::Input => safe_range(&self.def, Bound::Unbounded, before(first_written)),
            VnClass::Written => safe_range(&self.def, lower(first_written), through(last_written)),
            VnClass::Free => safe_range(&self.def, upper(last_written), Bound::Unbounded),
        }
    }

    fn def_class_addr_bounds(
        class: VnClass,
        addr: Address,
    ) -> IrResult<(Bound<DefKey>, Bound<DefKey>)> {
        match class {
            VnClass::Written => Err(IrError::WrittenByAddress),
            VnClass::Input => Ok((
                lower(dk(INPUT_CLASS, SEQ_MIN, addr, 0)),
                before(dk(INPUT_CLASS, SEQ_MIN, addr, 1_000_000)),
            )),
            VnClass::Free => Ok((
                upper(dk(FREE_CLASS, SEQ_MIN, addr, 0)),
                before(dk(FREE_CLASS, SEQ_MIN, addr, 1_000_000)),
            )),
        }
    }

    /// The inputs or free varnodes at `addr` in def order
    /// (`beginDef(fl,addr)`..`endDef(fl,addr)`); written ones are Ghidra's
    /// error "Cannot get contiguous written AND addressed".
    pub fn def_class_at(
        &self,
        class: VnClass,
        addr: Address,
    ) -> IrResult<impl DoubleEndedIterator<Item = VarnodeId> + Clone + '_> {
        let (lo, hi) = Self::def_class_addr_bounds(class, addr)?;
        Ok(safe_range(&self.def, lo, hi))
    }

    /// `VarnodeBank::find`: the varnode of a size and address written at
    /// `pc` (by the op with time `uniq`, if given).
    pub fn find_varnode(
        &self,
        size: i32,
        addr: Address,
        pc: Address,
        uniq: Option<u32>,
    ) -> Option<VarnodeId> {
        let start = lk(addr, size, WRITTEN_CLASS, (pc, uniq.unwrap_or(0)));
        for (_, &vn) in self.loc.range(start..) {
            let d = self.vns.get(vn.index())?;
            if d.size != size || d.loc != addr {
                break;
            }
            if let Some(op) = d.def().and_then(|o| self.ops.get(o.index()))
                && op.pc == pc
                && uniq.is_none_or(|u| u == op.time)
            {
                return Some(vn);
            }
        }
        None
    }

    /// `VarnodeBank::findInput`.
    pub fn find_input(&self, size: i32, addr: Address) -> Option<VarnodeId> {
        let k = lk(addr, size, INPUT_CLASS, SEQ_MIN);
        let (_, &vn) = self.loc.range(k..).next()?;
        let d = self.vns.get(vn.index())?;
        (d.flags & vflags::INPUT != 0 && d.size == size && d.loc == addr).then_some(vn)
    }

    /// `VarnodeBank::findCoveredInput`: the first input inside the range.
    pub fn find_covered_input(&self, size: i32, addr: Address) -> Option<VarnodeId> {
        let space = self.spaces.space_of(addr)?;
        let highest = space.highest();
        let end = addr.offset().wrapping_add(size as u64).wrapping_sub(1);
        let lo = lower(dk(INPUT_CLASS, SEQ_MIN, addr, 0));
        let hi = if end == highest {
            before(dk(
                INPUT_CLASS,
                SEQ_MIN,
                Address::new(space.id(), highest),
                1_000_000,
            ))
        } else {
            let next = Address::new(space.id(), addr.offset().wrapping_add(size as u64));
            before(dk(INPUT_CLASS, SEQ_MIN, next, 0))
        };
        safe_range(&self.def, lo, hi).find(|&vn| {
            self.vns
                .get(vn.index())
                .is_some_and(|d| d.loc.offset().wrapping_add(d.size as u64).wrapping_sub(1) <= end)
        })
    }

    /// `VarnodeBank::findCoveringInput`: the input containing the range.
    pub fn find_covering_input(&self, size: i32, addr: Address) -> Option<VarnodeId> {
        let k = dk(INPUT_CLASS, SEQ_MIN, addr, 0);
        let mut it = self.def.range(k..);
        let (_, &first) = it.next()?;
        let mut vn = first;
        if self.vns.get(vn.index())?.loc != addr
            && let Some((_, &prev)) = self.def.range(..k).next_back()
        {
            vn = prev;
        }
        let d = self.vns.get(vn.index())?;
        let covers = d.flags & vflags::INPUT != 0
            && d.loc.space() == addr.space()
            && d.loc.offset() <= addr.offset()
            && d.loc.offset().wrapping_add(d.size as u64).wrapping_sub(1)
                >= addr.offset().wrapping_add(size as u64).wrapping_sub(1);
        covers.then_some(vn)
    }

    /// `VarnodeBank::hasInputIntersection`.
    pub fn has_input_intersection(&self, size: i32, addr: Address) -> bool {
        let k = dk(INPUT_CLASS, SEQ_MIN, addr, 0);
        let check = |vn: VarnodeId| {
            self.vns.get(vn.index()).is_some_and(|d| {
                d.flags & vflags::INPUT != 0 && Self::intersects_range(d, addr, size)
            })
        };
        if let Some((_, &vn)) = self.def.range(k..).next()
            && check(vn)
        {
            return true;
        }
        if let Some((_, &vn)) = self.def.range(..k).next_back()
            && check(vn)
        {
            return true;
        }
        false
    }

    /// `VarnodeBank::overlapLoc`: from `start` (a varnode in loc order), the
    /// maximal run of varnodes overlapping it, as subranges of equal size
    /// and address. Returns the union of their flags and, per subrange, its
    /// varnodes; free varnodes are skipped.
    pub fn overlap_loc(&self, start: VarnodeId) -> IrResult<(u32, Vec<Vec<VarnodeId>>)> {
        let d = self.vnd(start)?;
        let space = d.loc.space();
        let mut max_off = d.loc.offset().wrapping_add((d.size as u64).wrapping_sub(1));
        let mut flags = d.flags;
        let mut groups = Vec::new();
        let first_key = self
            .key_parts(start)
            .map(|k| k.loc())
            .ok_or(IrError::NoSuchVarnode(start))?;
        let written_end = |size: i32, addr: Address| lk(addr, size, WRITTEN_CLASS, SEQ_MAX);
        let after = |k: LocKey| {
            self.loc
                .range((Bound::Excluded(k), Bound::Unbounded))
                .next()
                .map(|(k, _)| *k)
        };
        let end = written_end(d.size, d.loc);
        groups.push(safe_range(&self.loc, lower(first_key), through(end)).collect());
        let mut cur = after(end);
        while let Some(k) = cur {
            let Some((&gk, &gvn)) = self.loc.range(k..).next() else {
                break;
            };
            let gd = self.vnd(gvn)?;
            if gd.loc.space() != space || gd.loc.offset() > max_off {
                break;
            }
            if gd.flags & (vflags::INPUT | vflags::WRITTEN) == 0 {
                cur = Some(lk(gd.loc, gd.size.saturating_add(1), INPUT_CLASS, SEQ_MIN));
                continue;
            }
            let end_off = gd
                .loc
                .offset()
                .wrapping_add((gd.size as u64).wrapping_sub(1));
            if end_off > max_off {
                max_off = end_off;
            }
            flags |= gd.flags;
            let end = written_end(gd.size, gd.loc);
            groups.push(safe_range(&self.loc, lower(gk), through(end)).collect());
            cur = after(end);
        }
        Ok((flags, groups))
    }

    /// A cursor over loc order that survives mutation of the bank between
    /// steps (see [`LocCursor`]).
    pub fn loc_cursor(&self) -> LocCursor {
        LocCursor {
            pending: self.loc.keys().next().copied(),
        }
    }

    /// A cursor over def order.
    pub fn def_cursor(&self) -> DefCursor {
        DefCursor {
            pending: self.def.keys().next().copied(),
        }
    }
}

/// Steps through loc order as Ghidra's `vn = *iter++` loops do: each step
/// returns the current varnode and remembers its successor *at that time*,
/// so the body may create or destroy varnodes (`clearDeadVarnodes`,
/// `funcdata_varnode.cc:860`). If the remembered successor is gone, the walk
/// goes on from the first key after it.
#[derive(Clone, Copy, Debug)]
pub struct LocCursor {
    pending: Option<LocKey>,
}

impl LocCursor {
    /// The next varnode, or `None` at the end.
    pub fn next(&mut self, ssa: &Ssa) -> Option<VarnodeId> {
        let k = self.pending?;
        let (&cur, &vn) = ssa.loc.range(k..).next()?;
        self.pending = ssa
            .loc
            .range((Bound::Excluded(cur), Bound::Unbounded))
            .next()
            .map(|(k, _)| *k);
        Some(vn)
    }
}

/// [`LocCursor`] for def order.
#[derive(Clone, Copy, Debug)]
pub struct DefCursor {
    pending: Option<DefKey>,
}

impl DefCursor {
    /// The next varnode, or `None` at the end.
    pub fn next(&mut self, ssa: &Ssa) -> Option<VarnodeId> {
        let k = self.pending?;
        let (&cur, &vn) = ssa.def.range(k..).next()?;
        self.pending = ssa
            .def
            .range((Bound::Excluded(cur), Bound::Unbounded))
            .next()
            .map(|(k, _)| *k);
        Some(vn)
    }
}
