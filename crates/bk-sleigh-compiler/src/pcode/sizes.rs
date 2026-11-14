//! Size inference for templates (`PcodeCompile::force_size`, `matchSize`,
//! `fillinZero`, `propagateSize`, `pcodecompile.cc` 119-317).

use bk_pcode::OpCode;
use bk_sla::ConstTpl;

use crate::template::{Op, Vn, const_eq, is_zero};

/// `force_size` failed: a temporary is used with two different sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeMismatch;

impl std::fmt::Display for SizeMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Localtemp size mismatch")
    }
}

/// Forces `size` on `vn` if its size is unknown; if `vn` is a temporary,
/// every other occurrence of the same temporary in `ops` gets it too.
/// `vn` must not be one of the varnodes of `ops`; use [`force_size_at`] for
/// those.
pub fn force_size(vn: &mut Vn, size: ConstTpl, ops: &mut [Op]) -> Result<(), SizeMismatch> {
    if !is_zero(&vn.size) {
        return Ok(());
    }
    vn.size = size;
    if !vn.is_local_temp() {
        return Ok(());
    }
    spread(vn.offset, size, ops)
}

/// [`force_size`] on the varnode in `slot` (−1 = output) of `ops[op]`.
pub(crate) fn force_size_at(
    ops: &mut [Op],
    op: usize,
    slot: i32,
    size: ConstTpl,
) -> Result<(), SizeMismatch> {
    let Some(vn) = ops.get_mut(op).and_then(|o| o.slot_mut(slot)) else {
        return Ok(());
    };
    if !is_zero(&vn.size) {
        return Ok(());
    }
    vn.size = size;
    if !vn.is_local_temp() {
        return Ok(());
    }
    let offset = vn.offset;
    spread(offset, size, ops)
}

fn spread(offset: ConstTpl, size: ConstTpl, ops: &mut [Op]) -> Result<(), SizeMismatch> {
    for op in ops.iter_mut() {
        if let Some(out) = op.output.as_mut() {
            set_if_same(out, offset, size)?;
        }
        for input in &mut op.inputs {
            set_if_same(input, offset, size)?;
        }
    }
    Ok(())
}

fn set_if_same(vn: &mut Vn, offset: ConstTpl, size: ConstTpl) -> Result<(), SizeMismatch> {
    if vn.is_local_temp() && const_eq(&vn.offset, &offset) {
        if let (ConstTpl::Real(want), ConstTpl::Real(have)) = (size, vn.size)
            && have != 0
            && have != want
        {
            return Err(SizeMismatch);
        }
        vn.size = size;
    }
    Ok(())
}

/// `matchSize`: forces onto `slot` of `ops[op]` the size of the output (unless
/// `inputs_only`) or else of the first sized input.
fn match_size(ops: &mut [Op], op: usize, slot: i32, inputs_only: bool) -> Result<(), SizeMismatch> {
    let Some(o) = ops.get(op) else { return Ok(()) };
    let mut found = None;
    if !inputs_only
        && let Some(out) = &o.output
        && !out.is_zero_size()
    {
        found = Some(out.size);
    }
    if found.is_none() {
        found = o.inputs.iter().find(|i| !i.is_zero_size()).map(|i| i.size);
    }
    match found {
        Some(size) => force_size_at(ops, op, slot, size),
        None => Ok(()),
    }
}

fn zero_at(ops: &[Op], op: usize, slot: i32) -> bool {
    ops.get(op)
        .and_then(|o| o.slot(slot))
        .is_some_and(Vn::is_zero_size)
}

fn size_at(ops: &[Op], op: usize, slot: i32) -> Option<ConstTpl> {
    ops.get(op).and_then(|o| o.slot(slot)).map(|v| v.size)
}

/// `fillinZero`: infers the unknown sizes of one op from its other varnodes.
fn fill_in_zero(ops: &mut [Op], op: usize) -> Result<(), SizeMismatch> {
    let Some(o) = ops.get(op) else { return Ok(()) };
    let inputs = o.inputs.len() as i32;
    let has_output = o.output.is_some();
    match o.opcode {
        OpCode::Copy
        | OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::Int2Comp
        | OpCode::IntNegate
        | OpCode::IntXor
        | OpCode::IntAnd
        | OpCode::IntOr
        | OpCode::IntMult
        | OpCode::IntDiv
        | OpCode::IntSDiv
        | OpCode::IntRem
        | OpCode::IntSRem
        | OpCode::FloatAdd
        | OpCode::FloatDiv
        | OpCode::FloatMult
        | OpCode::FloatSub
        | OpCode::FloatNeg
        | OpCode::FloatAbs
        | OpCode::FloatSqrt
        | OpCode::FloatCeil
        | OpCode::FloatFloor
        | OpCode::FloatRound => {
            if has_output && zero_at(ops, op, -1) {
                match_size(ops, op, -1, false)?;
            }
            for i in 0..inputs {
                if zero_at(ops, op, i) {
                    match_size(ops, op, i, false)?;
                }
            }
        }
        OpCode::IntEqual
        | OpCode::IntNotEqual
        | OpCode::IntSLess
        | OpCode::IntSLessEqual
        | OpCode::IntLess
        | OpCode::IntLessEqual
        | OpCode::IntCarry
        | OpCode::IntSCarry
        | OpCode::IntSBorrow
        | OpCode::FloatEqual
        | OpCode::FloatNotEqual
        | OpCode::FloatLess
        | OpCode::FloatLessEqual
        | OpCode::FloatNan
        | OpCode::BoolNegate
        | OpCode::BoolXor
        | OpCode::BoolAnd
        | OpCode::BoolOr => {
            if zero_at(ops, op, -1) {
                force_size_at(ops, op, -1, ConstTpl::Real(1))?;
            }
            for i in 0..inputs {
                if zero_at(ops, op, i) {
                    match_size(ops, op, i, true)?;
                }
            }
        }
        OpCode::IntLeft | OpCode::IntRight | OpCode::IntSRight => {
            if zero_at(ops, op, -1) {
                if !zero_at(ops, op, 0)
                    && let Some(size) = size_at(ops, op, 0)
                {
                    force_size_at(ops, op, -1, size)?;
                }
            } else if zero_at(ops, op, 0)
                && let Some(size) = size_at(ops, op, -1)
            {
                force_size_at(ops, op, 0, size)?;
            }
            // Falls through to the SUBPIECE rule, as in Ghidra.
            if zero_at(ops, op, 1) {
                force_size_at(ops, op, 1, ConstTpl::Real(4))?;
            }
        }
        OpCode::SubPiece => {
            if zero_at(ops, op, 1) {
                force_size_at(ops, op, 1, ConstTpl::Real(4))?;
            }
        }
        OpCode::CPoolRef => {
            if zero_at(ops, op, -1)
                && !zero_at(ops, op, 0)
                && let Some(size) = size_at(ops, op, 0)
            {
                force_size_at(ops, op, -1, size)?;
            }
            if zero_at(ops, op, 0)
                && !zero_at(ops, op, -1)
                && let Some(size) = size_at(ops, op, -1)
            {
                force_size_at(ops, op, 0, size)?;
            }
            for i in 1..inputs {
                if zero_at(ops, op, i) {
                    force_size_at(ops, op, i, ConstTpl::Real(8))?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `propagateSize`: fills in unknown sizes until nothing changes. Returns
/// whether every size is known. Terminates because each round that does not
/// stop removes at least one op from the work list (spec 4.5).
pub fn propagate_size(ops: &mut [Op]) -> Result<bool, SizeMismatch> {
    let mut zero = Vec::new();
    for i in 0..ops.len() {
        if ops.get(i).is_some_and(Op::is_zero_size) {
            fill_in_zero(ops, i)?;
            if ops.get(i).is_some_and(Op::is_zero_size) {
                zero.push(i);
            }
        }
    }
    let mut last = zero.len() + 1;
    let mut next = Vec::new();
    while zero.len() < last {
        last = zero.len();
        next.clear();
        for &i in &zero {
            fill_in_zero(ops, i)?;
            if ops.get(i).is_some_and(Op::is_zero_size) {
                next.push(i);
            }
        }
        std::mem::swap(&mut zero, &mut next);
    }
    Ok(last == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::UNIQUE_SPACE;

    fn temp(offset: u64, size: u64) -> Vn {
        Vn::new(
            ConstTpl::Space(UNIQUE_SPACE),
            ConstTpl::Real(offset),
            ConstTpl::Real(size),
        )
    }

    fn reg(size: u64) -> Vn {
        Vn::new(ConstTpl::Space(3), ConstTpl::Real(0), ConstTpl::Real(size))
    }

    #[test]
    fn sizes_flow_through_temporaries() {
        // t1 = r4 + 1; t2 = t1 == 0
        let mut ops = vec![
            Op {
                opcode: OpCode::IntAdd,
                output: Some(temp(0, 0)),
                inputs: vec![reg(4), Vn::constant(1, 0)],
            },
            Op {
                opcode: OpCode::IntEqual,
                output: Some(temp(0x100, 0)),
                inputs: vec![temp(0, 0), Vn::constant(0, 0)],
            },
        ];
        assert_eq!(propagate_size(&mut ops), Ok(true));
        assert_eq!(ops[0].output.unwrap().size, ConstTpl::Real(4));
        assert_eq!(ops[1].inputs[0].size, ConstTpl::Real(4));
        assert_eq!(ops[1].inputs[1].size, ConstTpl::Real(4));
        assert_eq!(ops[1].output.unwrap().size, ConstTpl::Real(1));
    }

    #[test]
    fn unresolved_and_mismatched_sizes() {
        let mut ops = vec![Op {
            opcode: OpCode::Copy,
            output: Some(temp(0, 0)),
            inputs: vec![Vn::constant(1, 0)],
        }];
        assert_eq!(propagate_size(&mut ops), Ok(false));
        let mut ops = vec![
            Op {
                opcode: OpCode::Copy,
                output: Some(temp(0, 0)),
                inputs: vec![reg(4)],
            },
            Op {
                opcode: OpCode::Copy,
                output: Some(reg(2)),
                inputs: vec![temp(0, 2)],
            },
        ];
        assert_eq!(propagate_size(&mut ops), Err(SizeMismatch));
    }
}
