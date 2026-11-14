//! Bit ranges (`PcodeCompile::createBitRange`, `assignBitRange`,
//! `buildTruncatedVarnode`, `pcodecompile.cc` 702-916).

use bk_pcode::OpCode;
use bk_sla::{ConstTpl, HandleSelect};
use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::Ident;

use super::expr::ExprTree;
use super::sizes::force_size;
use super::{Builder, Stop, SymbolResolver};
use crate::template::{Op, Vn};

/// `(2 << (bits - 1)) - 1` with x86 shift semantics (the count taken modulo
/// 64), which is what Ghidra's C++ computes where the shift is undefined.
fn low_mask(bits: u32) -> u64 {
    2_u64.wrapping_shl(bits.wrapping_sub(1)).wrapping_sub(1)
}

impl<R: SymbolResolver> Builder<'_, R> {
    /// `buildTruncatedVarnode`: the bytes of `base` that a byte-aligned bit
    /// range selects, if they can be expressed as a varnode.
    pub(crate) fn truncated_varnode(
        &self,
        base: &Vn,
        bit_offset: u32,
        bits: u32,
    ) -> Result<Option<Vn>, Stop> {
        let byte_offset = bit_offset / 8;
        let num_bytes = bits / 8;
        let mut full = 0_u64;
        if let ConstTpl::Real(size) = base.size {
            full = size;
            if full == 0 {
                return Ok(None);
            }
            if u64::from(byte_offset) + u64::from(num_bytes) > full {
                return Err(Stop::Fatal("Requested bit range out of bounds".to_owned()));
            }
        }
        if !bit_offset.is_multiple_of(8) || !bits.is_multiple_of(8) {
            return Ok(None);
        }
        let offset = match base.offset {
            ConstTpl::Handle { index, .. } => ConstTpl::Handle {
                index,
                select: HandleSelect::OffsetPlus,
                plus: u64::from(byte_offset),
            },
            ConstTpl::Real(off) => {
                if !matches!(base.size, ConstTpl::Real(_)) {
                    return Err(Stop::Fatal(
                        "Could not construct requested bit range".to_owned(),
                    ));
                }
                let plus = if self.env.default_big_endian() {
                    full.wrapping_sub(u64::from(byte_offset) + u64::from(num_bytes))
                } else {
                    u64::from(byte_offset)
                };
                ConstTpl::Real(off.wrapping_add(plus))
            }
            _ => return Ok(None),
        };
        Ok(Some(Vn::new(
            base.space,
            offset,
            ConstTpl::Real(u64::from(num_bytes)),
        )))
    }

    /// `createBitRange`: the value of bits `[bit_offset, bit_offset + bits)`
    /// of `vn` (the varnode of the symbol `sym`).
    pub(crate) fn create_bit_range(
        &mut self,
        sym: Ident,
        mut vn: Vn,
        mut bit_offset: u32,
        bits: u32,
    ) -> Result<ExprTree, Stop> {
        let mut message = None;
        if bits == 0 {
            message = Some("Size of bitrange is zero".to_owned());
        }
        let final_size = bits.div_ceil(8);
        let mut trunc_shift = 0;
        let mut mask_needed = !bits.is_multiple_of(8);
        let mut trunc_needed = true;

        if message.is_none()
            && bit_offset == 0
            && !mask_needed
            && matches!(vn.space, ConstTpl::Handle { .. })
            && vn.is_zero_size()
        {
            vn.size = ConstTpl::Real(u64::from(final_size));
            return Ok(ExprTree::leaf(vn));
        }
        if message.is_none()
            && let Some(truncated) = self.truncated_varnode(&vn, bit_offset, bits)?
        {
            return Ok(ExprTree::leaf(truncated));
        }
        if let ConstTpl::Real(size) = vn.size {
            let in_size = size as u32;
            if in_size > 0 {
                trunc_needed = final_size < in_size;
                let in_bits = in_size.wrapping_mul(8);
                if bit_offset >= in_bits || bit_offset.wrapping_add(bits) > in_bits {
                    message = Some("Bitrange is bad".to_owned());
                }
                if mask_needed && bit_offset.wrapping_add(bits) == in_bits {
                    mask_needed = false;
                }
            }
        }
        let mask = low_mask(bits);
        if trunc_needed && bit_offset.is_multiple_of(8) {
            trunc_shift = bit_offset / 8;
            bit_offset = 0;
        }
        if bit_offset == 0 && !trunc_needed && !mask_needed {
            message = Some("Superfluous bitrange".to_owned());
        }
        if mask_needed && final_size > 8 {
            message = Some(format!(
                "Illegal masked bitrange producing varnode larger than 64 bits: {}",
                self.name(sym)
            ));
        }
        let mut tree = ExprTree::leaf(vn);
        if let Some(message) = message {
            let at = self.resolver.location_of(self.name(sym));
            self.error_at(at, message);
            return Ok(tree);
        }
        if bit_offset != 0 {
            self.append_op(OpCode::IntRight, &mut tree, u64::from(bit_offset), 4);
        }
        if trunc_needed {
            self.append_op(OpCode::SubPiece, &mut tree, u64::from(trunc_shift), 4);
        }
        if mask_needed {
            self.append_op(OpCode::IntAnd, &mut tree, mask, u64::from(final_size));
        }
        if let Some(out) = tree.out.as_mut() {
            force_size(out, ConstTpl::Real(u64::from(final_size)), &mut tree.ops)
                .map_err(|e| Stop::Fatal(e.to_string()))?;
        }
        Ok(tree)
    }

    /// `assignBitRange`: stores the value of `rhs` into bits
    /// `[bit_offset, bit_offset + bits)` of `vn`, keeping the other bits.
    pub(crate) fn assign_bit_range(
        &mut self,
        vn: Vn,
        bit_offset: u32,
        bits: u32,
        mut rhs: ExprTree,
        span: Span,
    ) -> Result<Vec<Op>, Stop> {
        let mut message = None;
        if bits == 0 {
            message = Some("Size of bitrange is zero");
        }
        let small_size = bits.div_ceil(8);
        let shift_needed = bit_offset != 0;
        let mut zext_needed = true;
        let mask = !(low_mask(bits).wrapping_shl(bit_offset));
        if let ConstTpl::Real(size) = vn.size {
            let sym_size = size as u32;
            if sym_size > 0 {
                zext_needed = sym_size > small_size;
            }
            let sym_bits = sym_size.wrapping_mul(8);
            if bit_offset >= sym_bits || bit_offset.wrapping_add(bits) > sym_bits {
                message = Some("Assigned bitrange is bad");
            } else if bit_offset == 0 && bits == sym_bits {
                message = Some("Assigning to bitrange is superfluous");
            }
        }
        if let Some(message) = message {
            self.error(Some(span), message);
            return Ok(rhs.ops);
        }
        if let Some(out) = rhs.out.as_mut() {
            force_size(out, ConstTpl::Real(u64::from(small_size)), &mut rhs.ops)
                .map_err(|e| Stop::Fatal(e.to_string()))?;
        }
        let mut late = None;
        let ops = if let Some(final_out) = self.truncated_varnode(&vn, bit_offset, bits)? {
            let input = rhs.out.take().unwrap_or_else(|| Vn::constant(0, 0));
            rhs.ops.push(Op {
                opcode: OpCode::Copy,
                output: Some(final_out),
                inputs: vec![input],
            });
            rhs.ops
        } else {
            if u64::from(bit_offset) + u64::from(bits) > 64 {
                late = Some("Assigned bitrange extends past first 64 bits");
            }
            let mut res = ExprTree::leaf(vn);
            self.append_op(OpCode::IntAnd, &mut res, mask, 0);
            if zext_needed {
                rhs = self.create_op1(OpCode::IntZExt, rhs);
            }
            if shift_needed {
                self.append_op(OpCode::IntLeft, &mut rhs, u64::from(bit_offset), 4);
            }
            let mut ops = res.ops;
            ops.append(&mut rhs.ops);
            let a = res.out.unwrap_or_else(|| Vn::constant(0, 0));
            let b = rhs.out.unwrap_or_else(|| Vn::constant(0, 0));
            ops.push(Op {
                opcode: OpCode::IntOr,
                output: Some(Vn {
                    unnamed: false,
                    ..vn
                }),
                inputs: vec![a, b],
            });
            ops
        };
        if let Some(message) = late {
            self.error(Some(span), message);
        }
        Ok(ops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_follow_x86_shift_semantics() {
        assert_eq!(low_mask(1), 1);
        assert_eq!(low_mask(8), 0xff);
        assert_eq!(low_mask(64), u64::MAX);
        // 2 << 64 is 2 << 0 on x86.
        assert_eq!(low_mask(65), 1);
    }
}
