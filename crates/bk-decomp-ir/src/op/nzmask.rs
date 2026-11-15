//! `PcodeOp::getNZMaskLocal`, `collapse`, `executeSimple` and
//! `collapseConstantSymbol` (op.cc:467–801): the parts of op evaluation that
//! need only the op, its inputs and `bk-pcode`'s arithmetic.

use bk_core::bits::{coveringmask, leastsigbit_set, mostsigbit_set, pcode_left, pcode_right, popcount};
use bk_pcode::mask::{calc_mask, sign_extend};
use bk_pcode::{FloatFormats, OpCode};

use crate::error::{IrError, IrResult};
use bk_decomp_cfg::edge_labels;

use crate::flags::oflags;
use crate::ids::{OpId, VarnodeId};
use crate::ssa::Ssa;

impl Ssa {
    fn nzm_in(&self, op: OpId, slot: usize) -> u64 {
        self.op_input(op, slot).map_or(u64::MAX, |v| self.varnode_nzm(v))
    }

    fn size_in(&self, op: OpId, slot: usize) -> i32 {
        self.op_input(op, slot).map_or(0, |v| self.varnode_size(v))
    }

    fn const_in(&self, op: OpId, slot: usize) -> Option<u64> {
        self.op_input(op, slot)
            .filter(|&v| self.is_constant(v))
            .map(|v| self.varnode_offset(v))
    }

    /// `getNZMaskLocal`: the bits of the output that may be non-zero, from
    /// the inputs' masks; `cliploop` leaves out `MULTIEQUAL` inputs along
    /// loop edges. The op must have an output.
    pub fn nz_mask_local(&self, op: OpId, cliploop: bool) -> u64 {
        let size = self
            .op_output(op)
            .map_or(8, |o| self.varnode_size(o))
            .max(0) as u32;
        let full = calc_mask(size);
        let Some(opc) = self.op_opcode(op) else {
            return full;
        };
        match opc {
            OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntSLess
            | OpCode::IntSLessEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntCarry
            | OpCode::IntSCarry
            | OpCode::IntSBorrow
            | OpCode::BoolNegate
            | OpCode::BoolXor
            | OpCode::BoolAnd
            | OpCode::BoolOr
            | OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual
            | OpCode::FloatNan => 1,
            OpCode::Copy | OpCode::IntZExt => self.nzm_in(op, 0),
            OpCode::IntSExt => sign_extend(
                self.nzm_in(op, 0),
                self.size_in(op, 0).max(0) as u32,
                size,
            ),
            OpCode::IntXor | OpCode::IntOr => {
                let r = self.nzm_in(op, 0);
                if r == full { r } else { r | self.nzm_in(op, 1) }
            }
            OpCode::IntAnd => {
                let r = self.nzm_in(op, 0);
                if r == 0 { r } else { r & self.nzm_in(op, 1) }
            }
            OpCode::IntLeft => match self.const_in(op, 1) {
                None => full,
                Some(sa) => pcode_left(self.nzm_in(op, 0), sa as u32) & full,
            },
            OpCode::IntRight => match self.const_in(op, 1) {
                None => full,
                Some(sa) => {
                    let sa = sa as u32;
                    let sz1 = self.size_in(op, 0).max(0) as u32;
                    let mut r = pcode_right(self.nzm_in(op, 0), sa);
                    if sz1 > 8 {
                        if sa >= 8 * sz1 {
                            r = 0;
                        } else if sa >= 64 {
                            r = calc_mask(sz1 - 8).checked_shr(sa - 64).unwrap_or(0);
                        } else {
                            r |= u64::MAX.checked_shl(64 - sa).unwrap_or(0);
                        }
                    }
                    r
                }
            },
            OpCode::IntSRight => match self.const_in(op, 1) {
                Some(sa) if size <= 8 => {
                    let sa = sa as u32;
                    let r = self.nzm_in(op, 0);
                    if r & (full ^ (full >> 1)) == 0 {
                        pcode_right(r, sa)
                    } else {
                        pcode_right(r, sa) | (pcode_right(full, sa) ^ full)
                    }
                }
                _ => full,
            },
            OpCode::IntDiv => {
                let mut r = coveringmask(self.nzm_in(op, 0));
                if self.const_in(op, 1).is_some() {
                    let sa = mostsigbit_set(self.nzm_in(op, 1));
                    if sa != -1 {
                        r = pcode_right(r, sa as u32);
                    }
                }
                r
            }
            OpCode::IntRem => coveringmask(self.nzm_in(op, 1).wrapping_sub(1)),
            OpCode::PopCount => coveringmask(popcount(self.nzm_in(op, 0)) as u64) & full,
            OpCode::LzCount => coveringmask((self.size_in(op, 0) as u64).wrapping_mul(8)) & full,
            OpCode::SubPiece => {
                let mut r = self.nzm_in(op, 0);
                let sz1 = self.const_in(op, 1).unwrap_or(0) as u32;
                if self.size_in(op, 0) <= 8 {
                    r = if sz1 < 8 { r >> (8 * sz1) } else { 0 };
                } else if sz1 < 8 {
                    r >>= 8 * sz1;
                    if sz1 > 0 {
                        r |= full.checked_shl(8 * (8 - sz1)).unwrap_or(0);
                    }
                } else {
                    r = full;
                }
                r & full
            }
            OpCode::Piece => {
                let sa = self.size_in(op, 1).max(0) as u32;
                let r = if sa < 8 { self.nzm_in(op, 0) << (8 * sa) } else { 0 };
                r | self.nzm_in(op, 1)
            }
            OpCode::IntMult => {
                if size > 8 {
                    return full;
                }
                let val = self.nzm_in(op, 0);
                let other = self.nzm_in(op, 1);
                let (s1, s2) = (mostsigbit_set(val), mostsigbit_set(other));
                if s1 == -1 || s2 == -1 {
                    return 0;
                }
                let (l1, l2) = (leastsigbit_set(val), leastsigbit_set(other));
                let sa = l1 + l2;
                if sa >= 8 * size as i32 {
                    return 0;
                }
                let (w1, w2) = (s1 - l1 + 1, s2 - l2 + 1);
                let mut total = w1 + w2;
                if w1 == 1 || w2 == 1 {
                    total -= 1;
                }
                let mut r = full;
                if total < 8 * size as i32 {
                    r >>= (8 * size as i32 - total) as u32;
                }
                (r << sa as u32) & full
            }
            OpCode::IntAdd => {
                let mut r = self.nzm_in(op, 0);
                if r != full {
                    let other = self.nzm_in(op, 1);
                    if other & r == 0 {
                        r |= other;
                    } else {
                        r |= other;
                        r |= r << 1;
                    }
                    r &= full;
                }
                r
            }
            OpCode::MultiEqual => {
                let ins = self.op_inputs(op);
                if ins.is_empty() {
                    return full;
                }
                let parent = self.op_parent(op);
                let in_edges = parent.map(|p| self.ins(p)).unwrap_or_default();
                let mut r = 0;
                for (i, v) in ins.iter().enumerate() {
                    if cliploop
                        && in_edges
                            .get(i)
                            .is_some_and(|e| e.label & edge_labels::LOOP != 0)
                    {
                        continue;
                    }
                    r |= v.map_or(u64::MAX, |v| self.varnode_nzm(v));
                }
                r
            }
            OpCode::Call | OpCode::CallInd | OpCode::CPoolRef => {
                if self.op_is_calculated_bool(op) { 1 } else { full }
            }
            _ => full,
        }
    }

    /// `collapse`: the constant an op with constant inputs produces, and
    /// whether an input carried a symbol (unary and binary ops only).
    pub fn op_collapse(&self, op: OpId, formats: &FloatFormats) -> IrResult<(u64, bool)> {
        let (Some(opc), Some(out), Some(in0)) =
            (self.op_opcode(op), self.op_output(op), self.op_input(op, 0))
        else {
            return Err(IrError::InvalidCollapse(op));
        };
        let mut marked = self.varnode_entry(in0).is_some();
        let out_size = self.varnode_size(out).max(0) as u32;
        let in_size = self.varnode_size(in0).max(0) as u32;
        match self.op_eval_type(op) {
            oflags::UNARY => bk_pcode::behavior::evaluate_unary(
                opc,
                out_size,
                in_size,
                self.varnode_offset(in0),
                formats,
            )
            .map(|v| (v, marked))
            .map_err(IrError::from),
            oflags::BINARY => {
                let in1 = self.op_input(op, 1).ok_or(IrError::InvalidCollapse(op))?;
                marked |= self.varnode_entry(in1).is_some();
                bk_pcode::behavior::evaluate_binary(
                    opc,
                    out_size,
                    in_size,
                    self.varnode_offset(in0),
                    self.varnode_offset(in1),
                    formats,
                )
                .map(|v| (v, marked))
                .map_err(IrError::from)
            }
            _ => Err(IrError::InvalidCollapse(op)),
        }
    }

    /// `executeSimple`: the op (unary, binary or ternary) on the given input
    /// values; `None` on an evaluation error.
    pub fn op_execute_simple(&self, op: OpId, inputs: &[u64], formats: &FloatFormats) -> Option<u64> {
        let opc = self.op_opcode(op)?;
        let out_size = self.op_output(op).map_or(0, |o| self.varnode_size(o)).max(0) as u32;
        let in_size = self.size_in(op, 0).max(0) as u32;
        let v = |i: usize| inputs.get(i).copied().unwrap_or(0);
        let r = match self.op_eval_type(op) {
            oflags::UNARY => bk_pcode::behavior::evaluate_unary(opc, out_size, in_size, v(0), formats),
            oflags::BINARY => {
                bk_pcode::behavior::evaluate_binary(opc, out_size, in_size, v(0), v(1), formats)
            }
            oflags::TERNARY => {
                bk_pcode::behavior::evaluate_ternary(opc, out_size, in_size, v(0), v(1), v(2))
            }
            _ => return None,
        };
        r.ok()
    }

    /// `collapseConstantSymbol`'s choice: the input whose symbol a collapsed
    /// constant may inherit (`copySymbolIfValid` then decides, which needs
    /// D06's equate symbols).
    pub fn collapse_symbol_source(&self, op: OpId) -> Option<VarnodeId> {
        let in0 = self.op_input(op, 0)?;
        let src = match self.op_opcode(op)? {
            OpCode::SubPiece => {
                if self.const_in(op, 1) != Some(0) {
                    return None;
                }
                in0
            }
            OpCode::Copy
            | OpCode::IntZExt
            | OpCode::IntNegate
            | OpCode::Int2Comp
            | OpCode::IntLeft
            | OpCode::IntRight
            | OpCode::IntSRight => in0,
            OpCode::IntAdd | OpCode::IntMult | OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor => {
                if self.varnode_entry(in0).is_none() {
                    self.op_input(op, 1)?
                } else {
                    in0
                }
            }
            _ => return None,
        };
        self.varnode_entry(src).is_some().then_some(src)
    }
}
