//! `PcodeOpSet`: a set of ops sorted by block, tested against covers
//! (cover.hh:34–68, cover.cc:519–654).

use super::{Cover, CoverPoint};
use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

/// Ops sorted by block index, then order (Ghidra `PcodeOpSet` after
/// `finalize`). Ghidra populates it lazily through a virtual call; here the
/// owner adds the ops and calls [`OpSet::finalize`], and the secondary
/// `affectsTest` is a closure given to [`Ssa::cover_intersect_set`].
#[derive(Clone, Debug, Default)]
pub struct OpSet {
    ops: Vec<OpId>,
    block_start: Vec<usize>,
    populated: bool,
}

impl OpSet {
    /// `addOp`.
    pub fn add_op(&mut self, op: OpId) {
        self.ops.push(op);
    }

    /// `isPopulated`.
    pub fn is_populated(&self) -> bool {
        self.populated
    }

    /// `clear`.
    pub fn clear(&mut self) {
        self.ops.clear();
        self.block_start.clear();
        self.populated = false;
    }

    /// The ops in set order.
    pub fn ops(&self) -> &[OpId] {
        &self.ops
    }

    /// `finalize`: sorts with `compareByBlock` and records where each block
    /// starts. Ties are only between an op and itself (ADR-040,
    /// `sorts.md`), so the stable sort equals Ghidra's.
    pub fn finalize(&mut self, ssa: &Ssa) {
        let key = |op: &OpId| {
            let ix = ssa
                .op_parent(*op)
                .and_then(|b| ssa.cfg.index(b))
                .unwrap_or(i32::MAX);
            (ix, ssa.op_order(*op))
        };
        self.ops.sort_by_key(key);
        self.block_start.clear();
        let mut last = i32::MIN;
        for (i, op) in self.ops.iter().enumerate() {
            let (ix, _) = key(op);
            if ix > last {
                self.block_start.push(i);
                last = ix;
            }
        }
        self.populated = true;
    }
}

impl Ssa {
    /// `Cover::intersect(PcodeOpSet, rep)`: some op of the set lies strictly
    /// inside the cover and `affects(op, rep)` says it matters.
    pub fn cover_intersect_set(
        &self,
        cover: &Cover,
        set: &OpSet,
        rep: VarnodeId,
        affects: &dyn Fn(OpId, VarnodeId) -> bool,
    ) -> bool {
        let index = |op: OpId| self.op_parent(op).and_then(|b| self.cfg.index(b));
        for (bix, b) in cover.iter() {
            for &op in &set.ops {
                if index(op) != Some(bix) {
                    continue;
                }
                let p = CoverPoint::Op(op);
                if self.cover_block_contains(&b, p)
                    && self.cover_block_boundary(&b, p) == 0
                    && affects(op, rep)
                {
                    return true;
                }
            }
        }
        false
    }
}
