//! Covers: the range of ops over which a varnode is live, per basic block
//! (Ghidra `CoverBlock`, `Cover`, `PcodeOpSet`; cover.hh, cover.cc).
//!
//! A cover point is an op or one of three marks: the beginning of the block
//! (Ghidra's pointer value 0), its end (1), and a function input (2). Points
//! compare by [`Ssa::cover_index`] (Ghidra `getUIndex`).

mod opset;

pub use opset::OpSet;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bk_pcode::OpCode;

use crate::flags::oflags;
use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

/// A cover boundary: a mark or an op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoverPoint {
    /// The beginning of the block (Ghidra 0).
    Begin,
    /// The end of the block (Ghidra 1).
    End,
    /// A function input (Ghidra 2).
    Input,
    /// An op.
    Op(OpId),
}

/// The covered range of one block (Ghidra `CoverBlock`). Empty when both
/// ends are [`CoverPoint::Begin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoverBlock {
    /// The start of the range.
    pub start: CoverPoint,
    /// The end of the range.
    pub stop: CoverPoint,
}

impl Default for CoverBlock {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl CoverBlock {
    /// The uncovered block.
    pub const EMPTY: Self = Self {
        start: CoverPoint::Begin,
        stop: CoverPoint::Begin,
    };

    /// `empty`.
    pub fn is_empty(&self) -> bool {
        *self == Self::EMPTY
    }

    /// `setAll`.
    pub fn set_all(&mut self) {
        self.start = CoverPoint::Begin;
        self.stop = CoverPoint::End;
    }

    /// `setBegin`.
    pub fn set_begin(&mut self, p: CoverPoint) {
        self.start = p;
        if self.stop == CoverPoint::Begin {
            self.stop = CoverPoint::End;
        }
    }

    /// `setEnd`.
    pub fn set_end(&mut self, p: CoverPoint) {
        self.stop = p;
    }
}

/// A varnode's cover: block index → covered range (Ghidra `Cover`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cover {
    blocks: BTreeMap<i32, CoverBlock>,
}

impl Cover {
    /// `clear`.
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    /// The blocks in index order.
    pub fn iter(&self) -> impl Iterator<Item = (i32, CoverBlock)> + '_ {
        self.blocks.iter().map(|(&k, &v)| (k, v))
    }

    /// `getCoverBlock`.
    pub fn block(&self, index: i32) -> CoverBlock {
        self.blocks
            .get(&index)
            .copied()
            .unwrap_or(CoverBlock::EMPTY)
    }

    fn entry(&mut self, index: i32) -> &mut CoverBlock {
        self.blocks.entry(index).or_default()
    }

    /// `compareTo`: by the index of the first covered block.
    pub fn compare_to(&self, other: &Self) -> i32 {
        let a = self.blocks.keys().next().copied().unwrap_or(1_000_000);
        let b = other.blocks.keys().next().copied().unwrap_or(1_000_000);
        match a.cmp(&b) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// `merge`.
    pub fn merge(&mut self, ssa: &Ssa, other: &Self) {
        for (&k, b) in &other.blocks {
            let mine = self.entry(k);
            ssa.cover_block_merge(mine, b);
        }
    }
}

impl Ssa {
    /// `CoverBlock::getUIndex`: 0 for the beginning, inputs and
    /// `MULTIEQUAL`s; `u32::MAX` for the end; an `INDIRECT` takes the order
    /// of the op it is indirect for; any other op its order.
    pub fn cover_index(&self, p: CoverPoint) -> u32 {
        match p {
            CoverPoint::Begin | CoverPoint::Input => 0,
            CoverPoint::End => u32::MAX,
            CoverPoint::Op(op) => {
                if self.op_flags(op) & oflags::MARKER != 0 {
                    match self.op_opcode(op) {
                        Some(OpCode::MultiEqual) => return 0,
                        Some(OpCode::Indirect) => {
                            if let Some(t) = self.op_input(op, 1).and_then(|v| self.op_from_iop(v))
                            {
                                return self.op_order(t);
                            }
                        }
                        _ => {}
                    }
                }
                self.op_order(op)
            }
        }
    }

    /// `CoverBlock::intersect`: 0 none, 1 at boundary points only, 2 an
    /// interval.
    pub fn cover_block_intersect(&self, a: &CoverBlock, b: &CoverBlock) -> i32 {
        if a.is_empty() || b.is_empty() {
            return 0;
        }
        let (us, ue) = (self.cover_index(a.start), self.cover_index(a.stop));
        let (vs, ve) = (self.cover_index(b.start), self.cover_index(b.stop));
        let edge = |x: bool| i32::from(x);
        if us <= ue {
            if vs <= ve {
                if ue <= vs || ve <= us {
                    return edge(us == ve || ue == vs);
                }
            } else if us >= ve && ue <= vs {
                return edge(us == ve || ue == vs);
            }
        } else if vs <= ve && vs >= ue && ve <= us {
            return edge(vs == ue || ve == us);
        }
        2
    }

    /// `CoverBlock::contain`.
    pub fn cover_block_contains(&self, b: &CoverBlock, point: CoverPoint) -> bool {
        if b.is_empty() {
            return false;
        }
        let p = self.cover_index(point);
        let (s, e) = (self.cover_index(b.start), self.cover_index(b.stop));
        if s <= e {
            p >= s && p <= e
        } else {
            p <= e || p >= s
        }
    }

    /// `CoverBlock::boundary`: 0 not on a boundary, 1 the tail, 2 the
    /// defining point.
    pub fn cover_block_boundary(&self, b: &CoverBlock, point: CoverPoint) -> i32 {
        if b.is_empty() {
            return 0;
        }
        let v = self.cover_index(point);
        if self.cover_index(b.start) == v && b.start != CoverPoint::Begin {
            return 2;
        }
        i32::from(self.cover_index(b.stop) == v)
    }

    /// `CoverBlock::merge`.
    pub fn cover_block_merge(&self, a: &mut CoverBlock, b: &CoverBlock) {
        if b.is_empty() {
            return;
        }
        if a.is_empty() {
            *a = *b;
            return;
        }
        let us = self.cover_index(a.start);
        let vs = self.cover_index(b.start);
        let internal4 = us == 0 && b.stop == CoverPoint::End;
        let internal1 = internal4 || self.cover_block_contains(b, a.start);
        let internal3 = vs == 0 && a.stop == CoverPoint::End;
        let internal2 = internal3 || self.cover_block_contains(a, b.start);
        if internal1 && internal2 && (us != vs || internal3 || internal4) {
            a.set_all();
            return;
        }
        if internal1 {
            a.start = b.start;
        } else if !internal2 {
            if us < vs {
                a.stop = b.stop;
            } else {
                a.start = b.start;
            }
            return;
        }
        if internal3 || self.cover_block_contains(b, a.stop) {
            a.stop = b.stop;
        }
    }

    fn block_index_of(&self, op: OpId) -> Option<i32> {
        self.op_parent(op).and_then(|b| self.cfg.index(b))
    }

    /// `Cover::addDefPoint`: resets `cover` to the point where `vn` is
    /// defined (block 0's input mark for an input).
    pub fn cover_add_def_point(&self, cover: &mut Cover, vn: VarnodeId) {
        cover.clear();
        if let Some(def) = self.varnode_def(vn) {
            if let Some(ix) = self.block_index_of(def) {
                let b = cover.entry(ix);
                b.set_begin(CoverPoint::Op(def));
                b.set_end(CoverPoint::Op(def));
            }
        } else if self.is_input(vn) {
            let b = cover.entry(0);
            b.set_begin(CoverPoint::Input);
            b.set_end(CoverPoint::Input);
        }
    }

    /// `Cover::addRefRecurse`, without recursion: fills `cover` backwards
    /// from the bottom of block `start` until existing cover, visiting
    /// predecessors depth first in in-edge order as Ghidra's recursion does.
    fn cover_add_ref_recurse(&self, cover: &mut Cover, start: bk_decomp_cfg::NodeId) {
        let mut stack: Vec<(bk_decomp_cfg::NodeId, usize)> = Vec::new();
        let visit = |cover: &mut Cover, bl: bk_decomp_cfg::NodeId| -> bool {
            let Some(ix) = self.cfg.index(bl) else {
                return false;
            };
            let block = cover.entry(ix);
            if block.is_empty() {
                block.set_all();
                return true;
            }
            let stop = block.stop;
            let ustart = self.cover_index(block.start);
            let ustop = self.cover_index(stop);
            if ustop != u32::MAX && ustop >= ustart {
                block.set_end(CoverPoint::End);
            }
            ustop == 0
                && block.start == CoverPoint::Begin
                && matches!(stop, CoverPoint::Op(op) if self.op_opcode(op) == Some(OpCode::MultiEqual))
        };
        let budget = (self.cfg.edge_count() + self.cfg.len() + 1).saturating_mul(4);
        let mut steps = 0usize;
        if visit(cover, start) {
            stack.push((start, 0));
        }
        while let Some(top) = stack.last_mut() {
            steps += 1;
            if steps > budget {
                break;
            }
            let (bl, i) = *top;
            let ins = self.ins(bl);
            if i >= ins.len() {
                stack.pop();
                continue;
            }
            top.1 += 1;
            if let Some(e) = ins.get(i)
                && visit(cover, e.node)
            {
                stack.push((e.node, 0));
            }
        }
    }

    /// `Cover::addRefPoint`: adds the read of `vn` by `reader` and fills in
    /// backwards; through a `MULTIEQUAL` only along the matching edges.
    pub fn cover_add_ref_point(&self, cover: &mut Cover, reader: OpId, vn: VarnodeId) {
        let Some(bl) = self.op_parent(reader) else {
            return;
        };
        let Some(ix) = self.cfg.index(bl) else {
            return;
        };
        let is_multi = self.op_opcode(reader) == Some(OpCode::MultiEqual);
        let point = CoverPoint::Op(reader);
        let block = cover.block(ix);
        if block.is_empty() {
            cover.entry(ix).set_end(point);
        } else if self.cover_block_contains(&block, point) {
            if !is_multi {
                return;
            }
        } else {
            let old_stop = block.stop;
            let start = block.start;
            cover.entry(ix).set_end(point);
            if self.cover_index(point) >= self.cover_index(start) {
                if let CoverPoint::Op(o) = old_stop
                    && self.op_opcode(o) == Some(OpCode::MultiEqual)
                    && start == CoverPoint::Begin
                {
                    for e in self.ins(bl) {
                        self.cover_add_ref_recurse(cover, e.node);
                    }
                }
                return;
            }
        }
        let ins = self.ins(bl);
        if is_multi {
            for (j, v) in self.op_inputs(reader).into_iter().enumerate() {
                if v == Some(vn)
                    && let Some(e) = ins.get(j)
                {
                    self.cover_add_ref_recurse(cover, e.node);
                }
            }
        } else {
            for e in ins {
                self.cover_add_ref_recurse(cover, e.node);
            }
        }
    }

    /// `Cover::rebuild`: the cover from `vn`'s definition to every read,
    /// following implied outputs.
    pub fn cover_rebuild(&self, cover: &mut Cover, vn: VarnodeId) {
        self.cover_add_def_point(cover, vn);
        let mut path = vec![vn];
        let mut pos = 0;
        let bound = self.vns.len() + 1;
        while let Some(&cur) = path.get(pos) {
            pos += 1;
            for op in self.readers(cur) {
                self.cover_add_ref_point(cover, op, vn);
                if let Some(out) = self.op_output(op)
                    && self.is_implied(out)
                    && path.len() < bound
                {
                    path.push(out);
                }
            }
        }
    }

    /// The cover of `vn`, rebuilt from its def-use (`updateCover` then
    /// `getCover`); `None` when `vn` has no cover (`hasCover` false).
    pub fn compute_cover(&self, vn: VarnodeId) -> Option<Cover> {
        if !self.has_cover(vn) {
            return None;
        }
        let mut c = Cover::default();
        self.cover_rebuild(&mut c, vn);
        Some(c)
    }

    /// `Cover::intersect`: 0, 1 (boundary points) or 2 (an interval).
    pub fn cover_intersect(&self, a: &Cover, b: &Cover) -> i32 {
        let mut res = 0;
        for (k, ba) in &a.blocks {
            if let Some(bb) = b.blocks.get(k) {
                match self.cover_block_intersect(ba, bb) {
                    2 => return 2,
                    1 => res = 1,
                    _ => {}
                }
            }
        }
        res
    }

    /// `Cover::intersectByBlock`.
    pub fn cover_intersect_by_block(&self, a: &Cover, blk: i32, b: &Cover) -> i32 {
        match (a.blocks.get(&blk), b.blocks.get(&blk)) {
            (Some(x), Some(y)) => self.cover_block_intersect(x, y),
            _ => 0,
        }
    }

    /// `Cover::intersectList`: the blocks whose intersection is at least
    /// `level`.
    pub fn cover_intersect_list(&self, a: &Cover, b: &Cover, level: i32) -> Vec<i32> {
        a.blocks
            .iter()
            .filter_map(|(k, x)| {
                let y = b.blocks.get(k)?;
                (self.cover_block_intersect(x, y) >= level).then_some(*k)
            })
            .collect()
    }

    /// `Cover::contain`: `max` 1 any containment, 2 interior only.
    pub fn cover_contains(&self, c: &Cover, op: OpId, max: i32) -> bool {
        let Some(ix) = self.block_index_of(op) else {
            return false;
        };
        let Some(b) = c.blocks.get(&ix) else {
            return false;
        };
        let p = CoverPoint::Op(op);
        self.cover_block_contains(b, p) && (max == 1 || self.cover_block_boundary(b, p) == 0)
    }

    /// `Cover::containVarnodeDef`: 0 not contained, 1 interior, 2 the
    /// defining points meet, 3 the cover's tail is the definition.
    pub fn cover_contain_varnode_def(&self, c: &Cover, vn: VarnodeId) -> i32 {
        let (point, blk) = match self.varnode_def(vn) {
            None => (CoverPoint::Input, Some(0)),
            Some(op) => (CoverPoint::Op(op), self.block_index_of(op)),
        };
        let Some(b) = blk.and_then(|k| c.blocks.get(&k)) else {
            return 0;
        };
        if !self.cover_block_contains(b, point) {
            return 0;
        }
        match self.cover_block_boundary(b, point) {
            0 => 1,
            2 => 2,
            _ => 3,
        }
    }

    fn point_text(&self, p: CoverPoint, out: &mut String) {
        let u = self.cover_index(p);
        if u == 0 {
            out.push_str("begin");
        } else if u == u32::MAX {
            out.push_str("end");
        } else if let CoverPoint::Op(op) = p {
            out.push_str(&self.seq_text(op));
        }
    }

    /// `Cover::print`: one line per block, `<index>: <start>-<stop>`.
    pub fn cover_text(&self, c: &Cover) -> String {
        let mut out = String::new();
        for (k, b) in &c.blocks {
            let _ = write!(out, "{k}: ");
            if b.is_empty() {
                out.push_str("empty");
            } else {
                self.point_text(b.start, &mut out);
                out.push('-');
                self.point_text(b.stop, &mut out);
            }
            out.push('\n');
        }
        out
    }

    /// `Varnode::printCover`: the varnode's cover, rebuilt.
    pub fn print_cover(&self, vn: VarnodeId) -> Option<String> {
        self.compute_cover(vn).map(|c| self.cover_text(&c))
    }
}
