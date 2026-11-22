//! `PieceNode` (op.hh:269–284, op.cc:834–918): the tree of `PIECE` ops
//! that concatenates varnodes into a structure.

use bk_pcode::OpCode;

use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

/// One node of a `CONCAT` tree: a `PIECE` op and one of its input slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PieceNode {
    /// The `PIECE` op reading this piece.
    pub op: OpId,
    /// The input slot of the piece.
    pub slot: usize,
    /// Byte offset into the structure.
    pub type_offset: i32,
    /// Whether the node is a leaf of the tree.
    pub leaf: bool,
}

impl Ssa {
    /// `PieceNode::isLeaf`: `vn`, at `rel_offset` into the value rooted at
    /// `root`, is a leaf of the tree.
    pub fn piece_is_leaf(&self, root: VarnodeId, vn: VarnodeId, rel_offset: i32) -> bool {
        if self.is_mapped(vn) && self.varnode_entry(root) != self.varnode_entry(vn) {
            return true;
        }
        let Some(def) = self.varnode_def(vn) else {
            return true;
        };
        if self.op_opcode(def) != Some(OpCode::Piece) {
            return true;
        }
        if self.lone_descend(vn).is_none() {
            return true;
        }
        if self.is_addr_tied(vn) {
            let root_addr = self.varnode_addr(root);
            let addr = root_addr.add(&self.spaces, i64::from(rel_offset));
            if self.varnode_addr(vn) != addr {
                return true;
            }
        }
        false
    }

    /// `PieceNode::findRoot`: the maximal varnode reached from `vn` forward
    /// through `PIECE`s whose output places it at its own address.
    pub fn piece_find_root(&self, mut vn: VarnodeId) -> VarnodeId {
        for _ in 0..=self.vns.len() {
            if !(self.is_proto_partial(vn) || self.is_addr_tied(vn)) {
                break;
            }
            let mut piece_op: Option<OpId> = None;
            for op in self.readers(vn) {
                if self.op_opcode(op) != Some(OpCode::Piece) {
                    continue;
                }
                let slot = self.op_slot(op, vn);
                let Some(out) = self.op_output(op) else {
                    continue;
                };
                let mut addr = self.varnode_addr(out);
                if addr.is_big_endian(&self.spaces) == (slot == 1)
                    && let Some(other) = self.op_input(op, 1 - slot.min(1))
                {
                    addr = addr.add(&self.spaces, i64::from(self.varnode_size(other)));
                }
                let addr = addr
                    .renormalize(&self.spaces, self.varnode_size(vn).max(0) as u32)
                    .unwrap_or(addr);
                if addr == self.varnode_addr(vn) {
                    match piece_op {
                        Some(p) if self.compare_order(op, p) != 0 => piece_op = Some(op),
                        Some(_) => {}
                        None => piece_op = Some(op),
                    }
                }
            }
            match piece_op.and_then(|p| self.op_output(p)) {
                Some(out) => vn = out,
                None => break,
            }
        }
        vn
    }

    /// `PieceNode::gatherPieces`: the tree under `op`, in Ghidra's order
    /// (each node, then the subtree of its piece, slot 0 before slot 1).
    pub fn piece_gather(
        &self,
        root: VarnodeId,
        op: OpId,
        base_offset: i32,
        root_offset: i32,
    ) -> Vec<PieceNode> {
        let big = self.varnode_addr(root).is_big_endian(&self.spaces);
        let mut out = Vec::new();
        // Frames: (op, base offset, next slot).
        let mut stack = vec![(op, base_offset, 0usize)];
        let bound = self.ops.len() * 2 + 2;
        while let Some(frame) = stack.last_mut() {
            if out.len() > bound {
                break;
            }
            let (cur, base, i) = *frame;
            if i >= 2 {
                stack.pop();
                continue;
            }
            frame.2 += 1;
            let Some(vn) = self.op_input(cur, i) else {
                continue;
            };
            let other = self
                .op_input(cur, 1 - i)
                .map_or(0, |o| self.varnode_size(o));
            let offset = if big == (i == 1) { base + other } else { base };
            let leaf = self.piece_is_leaf(root, vn, offset - root_offset);
            out.push(PieceNode {
                op: cur,
                slot: i,
                type_offset: offset,
                leaf,
            });
            if !leaf && let Some(def) = self.varnode_def(vn) {
                stack.push((def, offset, 0));
            }
        }
        out
    }
}
