//! Data-flow queries of `Varnode` that walk definitions: copy and piece
//! shadows, eventual constants, extension (varnode.cc:855–1132,
//! 2003–2045). Every walk is bounded by the number of varnodes, so a cycle
//! in a hostile state ends.

use bk_pcode::OpCode;
use bk_pcode::mask::calc_mask;

use crate::ids::VarnodeId;
use crate::ssa::Ssa;

impl Ssa {
    fn walk_bound(&self) -> usize {
        self.vns.len() + 1
    }

    /// Follows `COPY` definitions back to their source.
    fn copy_source(&self, mut vn: VarnodeId) -> VarnodeId {
        for _ in 0..self.walk_bound() {
            match self.varnode_def(vn) {
                Some(op) if self.op_opcode(op) == Some(OpCode::Copy) => {
                    match self.op_input(op, 0) {
                        Some(i) => vn = i,
                        None => break,
                    }
                }
                _ => break,
            }
        }
        vn
    }

    /// Whether following `COPY`s back from `vn` reaches `target`.
    fn copies_reach(&self, mut vn: VarnodeId, target: VarnodeId) -> bool {
        if vn == target {
            return true;
        }
        for _ in 0..self.walk_bound() {
            match self.varnode_def(vn) {
                Some(op) if self.op_opcode(op) == Some(OpCode::Copy) => {
                    match self.op_input(op, 0) {
                        Some(i) => vn = i,
                        None => return false,
                    }
                    if vn == target {
                        return true;
                    }
                }
                _ => return false,
            }
        }
        false
    }

    /// `isEventualConstant`: copied, extended, combined by `+ - ^ | &` or
    /// shifted/multiplied by a constant from constants, or loaded through
    /// at most `max_load` constant pointers, within `max_binary` levels of
    /// binary operations.
    pub fn is_eventual_constant(&self, vn: VarnodeId, max_binary: i32, max_load: i32) -> bool {
        // (varnode, max_binary, max_load) still to prove constant.
        let mut work = vec![(vn, max_binary, max_load)];
        let mut steps = 0usize;
        let bound = self.walk_bound().saturating_mul(4).max(64);
        while let Some((mut cur, mb, mut ml)) = work.pop() {
            loop {
                steps += 1;
                if steps > bound {
                    return false;
                }
                if self.is_constant(cur) {
                    break;
                }
                let Some(op) = self.varnode_def(cur) else {
                    return false;
                };
                let in0 = self.op_input(op, 0);
                let in1 = self.op_input(op, 1);
                match self.op_opcode(op) {
                    Some(OpCode::Load) => {
                        if ml == 0 {
                            return false;
                        }
                        ml -= 1;
                        let Some(i) = in1 else { return false };
                        cur = i;
                    }
                    Some(
                        OpCode::IntAdd
                        | OpCode::IntSub
                        | OpCode::IntXor
                        | OpCode::IntOr
                        | OpCode::IntAnd,
                    ) => {
                        if mb == 0 {
                            return false;
                        }
                        let (Some(a), Some(b)) = (in0, in1) else {
                            return false;
                        };
                        work.push((b, mb - 1, ml));
                        work.push((a, mb - 1, ml));
                        break;
                    }
                    Some(OpCode::IntZExt | OpCode::IntSExt | OpCode::Copy) => {
                        let Some(i) = in0 else { return false };
                        cur = i;
                    }
                    Some(
                        OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight | OpCode::IntMult,
                    ) => {
                        if !in1.is_some_and(|c| self.is_constant(c)) {
                            return false;
                        }
                        let Some(i) = in0 else { return false };
                        cur = i;
                    }
                    _ => return false,
                }
            }
        }
        true
    }

    /// `copyShadow`: `a` and `b` are copied from a common source.
    pub fn copy_shadow(&self, a: VarnodeId, b: VarnodeId) -> bool {
        if a == b {
            return true;
        }
        if self.copies_reach(a, b) {
            return true;
        }
        let src = self.copy_source(a);
        self.copies_reach(b, src)
    }

    /// `findSubpieceShadow`: `this` is `whole` truncated by `least_byte`
    /// bytes, through `COPY`s and at most one level of matching
    /// `MULTIEQUAL`s.
    pub fn find_subpiece_shadow(
        &self,
        this: VarnodeId,
        least_byte: i32,
        whole: VarnodeId,
        recurse: i32,
    ) -> bool {
        let vn = self.copy_source(this);
        let Some(def) = self.varnode_def(vn) else {
            if self.is_constant(vn) {
                let w = self.copy_source(whole);
                if !self.is_constant(w) {
                    return false;
                }
                let off = self
                    .varnode_offset(w)
                    .checked_shr((least_byte.max(0) as u32) * 8)
                    .unwrap_or(0)
                    & calc_mask(self.varnode_size(vn).max(0) as u32);
                return off == self.varnode_offset(vn);
            }
            return false;
        };
        match self.op_opcode(def) {
            Some(OpCode::SubPiece) => {
                let (Some(tmp), Some(c)) = (self.op_input(def, 0), self.op_input(def, 1)) else {
                    return false;
                };
                let off = self.varnode_offset(c) as i32;
                if off != least_byte || self.varnode_size(tmp) != self.varnode_size(whole) {
                    return false;
                }
                self.copies_reach(tmp, whole)
            }
            Some(OpCode::MultiEqual) => {
                if recurse + 1 > 1 {
                    return false;
                }
                let w = self.copy_source(whole);
                let Some(big) = self.varnode_def(w) else {
                    return false;
                };
                if self.op_opcode(big) != Some(OpCode::MultiEqual)
                    || self.op_parent(big) != self.op_parent(def)
                {
                    return false;
                }
                (0..self.op_num_inputs(def)).all(|i| {
                    match (self.op_input(def, i), self.op_input(big, i)) {
                        (Some(s), Some(b)) => {
                            self.find_subpiece_shadow(s, least_byte, b, recurse + 1)
                        }
                        _ => false,
                    }
                })
            }
            _ => false,
        }
    }

    /// `findPieceShadow`: `this` is formed from `piece` at `least_byte`
    /// through `PIECE`s and `COPY`s.
    pub fn find_piece_shadow(&self, this: VarnodeId, least_byte: i32, piece: VarnodeId) -> bool {
        let mut cur = this;
        let mut lb = least_byte;
        for _ in 0..self.walk_bound() {
            let vn = self.copy_source(cur);
            let Some(def) = self.varnode_def(vn) else {
                return false;
            };
            if self.op_opcode(def) != Some(OpCode::Piece) {
                return false;
            }
            let Some(mut tmp) = self.op_input(def, 1) else {
                return false;
            };
            if lb >= self.varnode_size(tmp) {
                lb -= self.varnode_size(tmp);
                match self.op_input(def, 0) {
                    Some(t) => tmp = t,
                    None => return false,
                }
            } else if self.varnode_size(piece) + lb > self.varnode_size(tmp) {
                return false;
            }
            if lb == 0 && self.varnode_size(tmp) == self.varnode_size(piece) {
                return self.copies_reach(tmp, piece);
            }
            cur = tmp;
        }
        false
    }

    /// `partialCopyShadow`: one of `this` and `other` is a `PIECE` or
    /// `SUBPIECE` of the other at relative offset `rel_off`.
    pub fn partial_copy_shadow(&self, this: VarnodeId, other: VarnodeId, rel_off: i32) -> bool {
        let (ts, os) = (self.varnode_size(this), self.varnode_size(other));
        let (small, big, rel) = match ts.cmp(&os) {
            std::cmp::Ordering::Less => (this, other, rel_off),
            std::cmp::Ordering::Greater => (other, this, -rel_off),
            std::cmp::Ordering::Equal => return false,
        };
        if rel < 0 || rel + self.varnode_size(small) > self.varnode_size(big) {
            return false;
        }
        let big_endian = self.varnode_addr(this).is_big_endian(&self.spaces);
        let least = if big_endian {
            (self.varnode_size(big) - self.varnode_size(small)) - rel
        } else {
            rel
        };
        self.find_subpiece_shadow(small, least, big, 0) || self.find_piece_shadow(big, least, small)
    }

    /// `isZeroExtended`: the bytes above `base_size` are known zero.
    pub fn is_zero_extended(&self, vn: VarnodeId, base_size: i32) -> bool {
        let size = self.varnode_size(vn);
        if base_size >= size {
            return false;
        }
        if size > 8 {
            let Some(def) = self.varnode_def(vn) else {
                return false;
            };
            if self.op_opcode(def) != Some(OpCode::IntZExt) {
                return false;
            }
            return self
                .op_input(def, 0)
                .is_some_and(|i| self.varnode_size(i) <= base_size);
        }
        self.varnode_nzm(vn)
            .checked_shr(8 * base_size.max(0) as u32)
            .unwrap_or(0)
            == 0
    }

    /// `contiguous_test`: `hi` and `lo` are the high and low `SUBPIECE`s of
    /// one whole.
    pub fn contiguous_test(&self, hi: VarnodeId, lo: VarnodeId) -> bool {
        if self.is_input(hi) || self.is_input(lo) {
            return false;
        }
        let (Some(op1), Some(op2)) = (self.varnode_def(hi), self.varnode_def(lo)) else {
            return false;
        };
        if self.op_opcode(op1) != Some(OpCode::SubPiece)
            || self.op_opcode(op2) != Some(OpCode::SubPiece)
        {
            return false;
        }
        let whole = self.op_input(op1, 0);
        if whole.is_none() || self.op_input(op2, 0) != whole {
            return false;
        }
        let c2 = self.op_input(op2, 1).map_or(1, |c| self.varnode_offset(c));
        let c1 = self.op_input(op1, 1).map_or(0, |c| self.varnode_offset(c));
        c2 == 0 && c1 == self.varnode_size(lo) as u64
    }

    /// `findContiguousWhole`: the whole a `contiguous_test` pair came from.
    pub fn find_contiguous_whole(&self, hi: VarnodeId) -> Option<VarnodeId> {
        let def = self.varnode_def(hi)?;
        if self.op_opcode(def) == Some(OpCode::SubPiece) {
            return self.op_input(def, 0);
        }
        None
    }
}
