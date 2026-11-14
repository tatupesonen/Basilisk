//! The decoder's op buffer (Ghidra `PcodeCacher`): ops and varnodes of one
//! instruction in two reused vectors, label positions and label
//! references, relative-branch resolution and emission.

use bk_core::{Address, VarnodeData};
use bk_pcode::OpCode;

use super::error::{LiftError, LiftLimit};
use crate::emit::PcodeEmit;

/// The most ops one instruction may produce (ADR-009).
pub(crate) const MAX_OPS: usize = 1 << 16;

/// The most varnodes one op may have (Ghidra `MAX_ALLOCATION`).
pub(crate) const MAX_VARNODES_PER_OP: usize = 4096;

/// A label that was never placed.
const UNPLACED: u32 = u32::MAX;

/// One op: its opcode, output slot and input run in the varnode vector.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawOp {
    pub(crate) opcode: OpCode,
    pub(crate) output: Option<u32>,
    pub(crate) inputs: u32,
    pub(crate) num_inputs: u32,
}

/// A varnode holding a label number, and the index of the op that uses it.
#[derive(Clone, Copy, Debug)]
struct LabelRef {
    varnode: u32,
    op: u32,
}

/// Ops and varnodes of the instruction being built.
#[derive(Clone, Debug, Default)]
pub(crate) struct OpBuffer {
    pub(crate) ops: Vec<RawOp>,
    pub(crate) vars: Vec<VarnodeData>,
    labels: Vec<u32>,
    refs: Vec<LabelRef>,
}

impl OpBuffer {
    pub(crate) fn clear(&mut self) {
        self.ops.clear();
        self.vars.clear();
        self.labels.clear();
        self.refs.clear();
    }

    /// Reserves `n` varnodes and returns the index of the first.
    pub(crate) fn alloc(&mut self, n: usize, address: Address) -> Result<u32, LiftError> {
        if n > MAX_VARNODES_PER_OP {
            return Err(LiftError::TooManyVarnodes { address });
        }
        let start = self.vars.len();
        self.vars.resize(start + n, VarnodeData::NONE);
        Ok(start as u32)
    }

    pub(crate) fn set(&mut self, slot: u32, vn: VarnodeData) {
        if let Some(v) = self.vars.get_mut(slot as usize) {
            *v = vn;
        }
    }

    pub(crate) fn get(&self, slot: u32) -> VarnodeData {
        self.vars
            .get(slot as usize)
            .copied()
            .unwrap_or(VarnodeData::NONE)
    }

    /// Appends an op and returns its index.
    pub(crate) fn push(&mut self, op: RawOp, address: Address) -> Result<u32, LiftError> {
        if self.ops.len() >= MAX_OPS {
            return Err(LiftError::Limit {
                address,
                limit: LiftLimit::Ops,
            });
        }
        self.ops.push(op);
        Ok(self.ops.len() as u32 - 1)
    }

    /// The index the next op will get.
    pub(crate) fn next_index(&self) -> u32 {
        self.ops.len() as u32
    }

    /// Records that label `id` is at the next op (Ghidra `addLabel`).
    pub(crate) fn place_label(&mut self, id: u32, address: Address) -> Result<(), LiftError> {
        let slot = id as usize;
        if slot >= MAX_OPS {
            return Err(LiftError::MissingLabel { address });
        }
        if self.labels.len() <= slot {
            self.labels.resize(slot + 1, UNPLACED);
        }
        let at = self.next_index();
        if let Some(label) = self.labels.get_mut(slot) {
            *label = at;
        }
        Ok(())
    }

    /// Remembers that varnode `slot` holds a label for the next op (Ghidra
    /// `addLabelRef`).
    pub(crate) fn add_label_ref(&mut self, slot: u32) {
        let op = self.next_index();
        self.refs.push(LabelRef { varnode: slot, op });
    }

    /// Replaces every label reference by the op-count displacement to its
    /// label, masked to the varnode's size (Ghidra `resolveRelatives`).
    pub(crate) fn resolve_relatives(&mut self, address: Address) -> Result<(), LiftError> {
        for r in &self.refs {
            let Some(vn) = self.vars.get_mut(r.varnode as usize) else {
                continue;
            };
            // Ghidra `resolveRelatives`: `uint4 id = ptr->offset`.
            let id = super::build::label_number(vn.offset);
            let at = usize::try_from(id)
                .ok()
                .and_then(|id| self.labels.get(id))
                .copied()
                .filter(|&at| at != UNPLACED)
                .ok_or(LiftError::MissingLabel { address })?;
            vn.offset = u64::from(at).wrapping_sub(u64::from(r.op)) & calc_mask(vn.size);
        }
        Ok(())
    }

    /// Hands every op to `emit` at `addr`.
    pub(crate) fn emit<E: PcodeEmit + ?Sized>(&self, addr: Address, emit: &mut E) {
        for op in &self.ops {
            let output = op.output.map(|slot| self.get(slot));
            let start = op.inputs as usize;
            let inputs = self
                .vars
                .get(start..start + op.num_inputs as usize)
                .unwrap_or_default();
            emit.op(addr, op.opcode, output, inputs);
        }
    }
}

/// Ghidra `calc_mask`: the mask of `size` bytes, all bits from 8 bytes up.
pub(crate) const fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(7), 0x00ff_ffff_ffff_ffff);
        assert_eq!(calc_mask(8), u64::MAX);
        assert_eq!(calc_mask(u32::MAX), u64::MAX);
    }

    #[test]
    fn label_refs_resolve_backward_and_forward() {
        let a = Address::INVALID;
        let mut buf = OpBuffer::default();
        buf.place_label(0, a).unwrap();
        let slot = buf.alloc(1, a).unwrap();
        buf.set(slot, VarnodeData::new(bk_core::SpaceId::new(0), 0, 1));
        buf.add_label_ref(slot);
        let op = RawOp {
            opcode: OpCode::Branch,
            output: None,
            inputs: slot,
            num_inputs: 1,
        };
        buf.push(op, a).unwrap();
        let fwd = buf.alloc(1, a).unwrap();
        buf.set(fwd, VarnodeData::new(bk_core::SpaceId::new(0), 1, 2));
        buf.add_label_ref(fwd);
        buf.push(RawOp { inputs: fwd, ..op }, a).unwrap();
        buf.push(op, a).unwrap();
        buf.place_label(1, a).unwrap();
        buf.resolve_relatives(a).unwrap();
        assert_eq!(buf.get(slot).offset, 0);
        assert_eq!(buf.get(fwd).offset, 2);
        let missing = buf.alloc(1, a).unwrap();
        buf.set(missing, VarnodeData::new(bk_core::SpaceId::new(0), 7, 4));
        buf.add_label_ref(missing);
        assert!(matches!(
            buf.resolve_relatives(a),
            Err(LiftError::MissingLabel { .. })
        ));
    }
}
