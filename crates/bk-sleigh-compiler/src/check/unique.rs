//! The crossbuild shift of unique offsets (`checkUniqueAllocation`,
//! `insertCrossBuildRegion`, `shiftUniqueVn`, `shiftUniqueHandle`,
//! inventory 9.9).

use bk_sla::{ConstTpl, HandleTpl};

use crate::compiler::Compiler;
use crate::template::{Tpl, Vn, is_unique_space};

/// Bit position of the region inserted into unique offsets.
const POSITION: u32 = 8;
/// Number of bits inserted.
const BITS: u32 = 8;

/// `insertCrossBuildRegion`: 8 zero bits inserted at bit 8.
pub(crate) fn insert_region(offset: u64) -> u64 {
    let upper = (offset >> POSITION) << (POSITION + BITS);
    let lower = offset & ((1 << POSITION) - 1);
    upper | lower
}

fn shift_vn(vn: &mut Vn) {
    if is_unique_space(&vn.space)
        && let ConstTpl::Real(off) = vn.offset
    {
        vn.offset = ConstTpl::Real(insert_region(off));
    }
}

fn shift_handle(hand: &mut HandleTpl) {
    if is_unique_space(&hand.space)
        && matches!(hand.ptr_space, ConstTpl::Real(_))
        && let ConstTpl::Real(off) = hand.ptr_offset
    {
        hand.ptr_offset = ConstTpl::Real(insert_region(off));
    } else if is_unique_space(&hand.ptr_space)
        && let ConstTpl::Real(off) = hand.ptr_offset
    {
        hand.ptr_offset = ConstTpl::Real(insert_region(off));
    }
    if is_unique_space(&hand.temp_space)
        && let ConstTpl::Real(off) = hand.temp_offset
    {
        hand.temp_offset = ConstTpl::Real(insert_region(off));
    }
}

fn shift_tpl(tpl: &mut Tpl) {
    if let Some(hand) = tpl.result.as_mut() {
        shift_handle(hand);
    }
    for op in &mut tpl.ops {
        if let Some(out) = op.output.as_mut() {
            shift_vn(out);
        }
        for input in &mut op.inputs {
            shift_vn(input);
        }
    }
}

impl Compiler<'_> {
    /// `checkUniqueAllocation`: with any `crossbuild`, every unique offset
    /// in every template gets room for the instruction address bits.
    pub(crate) fn shift_unique_offsets(&mut self) {
        if !self.crossbuild {
            return;
        }
        for ctor in &mut self.ctors {
            if let Some(tpl) = ctor.main.as_mut() {
                shift_tpl(tpl);
            }
            for tpl in ctor.named.iter_mut().flatten() {
                shift_tpl(tpl);
            }
        }
        let base = self.unique_base.wrapping_add(1 << POSITION);
        self.unique_base = base.wrapping_shl(BITS);
    }
}

#[cfg(test)]
mod tests {
    use super::insert_region;

    #[test]
    fn region_is_inserted_at_bit_8() {
        assert_eq!(insert_region(0x12), 0x12);
        assert_eq!(insert_region(0x1234), 0x12_0034);
        assert_eq!(insert_region(0x100), 0x1_0000);
    }
}
