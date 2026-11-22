//! A small function for the unit tests: spaces like a 32-bit little-endian
//! processor (`ram`, `register`, `unique`, `fspec`, `iop`, `join`), and
//! blocks wired as the test asks.

use std::sync::Arc;

use bk_core::{Address, Space, SpaceId, SpaceManager};
use bk_decomp_cfg::NodeId;
use bk_pcode::OpCode;

use crate::ids::{OpId, VarnodeId};
use crate::mutate::env::TableEnv;
use crate::ssa::Ssa;

/// The `unique` space's analysis base (Ghidra's `getUniqueStart(ANALYSIS)`
/// is `0x10000000` for most processors).
pub(crate) const UNIQ_BASE: u32 = 0x1000_0000;

/// The fixture's spaces and IR.
pub(crate) struct Fx {
    pub(crate) ssa: Ssa,
    pub(crate) env: TableEnv,
    pub(crate) ram: SpaceId,
    pub(crate) reg: SpaceId,
    pub(crate) blocks: Vec<NodeId>,
}

pub(crate) fn spaces() -> SpaceManager {
    let mut m = SpaceManager::new();
    let all = [
        Space::constant(),
        Space::processor("ram", false, 4, 1, 1, true, 0, 0).unwrap(),
        Space::processor("register", false, 4, 1, 2, false, 0, 0).unwrap(),
        Space::unique(3, false).unwrap(),
        Space::fspec(4).unwrap(),
        Space::iop(5).unwrap(),
        Space::join(6, false).unwrap(),
    ];
    for s in all {
        m.insert_space(s).unwrap();
    }
    let ram = m.space_by_name("ram").unwrap().id();
    m.set_default_code_space(ram).unwrap();
    m
}

/// A function with `n` blocks in a chain (0 → 1 → … → n-1).
pub(crate) fn fx(n: usize) -> Fx {
    let m = spaces();
    let ram = m.space_by_name("ram").unwrap().id();
    let reg = m.space_by_name("register").unwrap().id();
    let mut ssa = Ssa::new(Arc::new(m), UNIQ_BASE).unwrap();
    let blocks: Vec<NodeId> = (0..n).map(|_| ssa.add_block(0).unwrap()).collect();
    for (i, &b) in blocks.iter().enumerate() {
        ssa.cfg_mut().set_index(b, i as i32).unwrap();
    }
    for w in blocks.windows(2) {
        ssa.cfg_mut().add_edge(w[0], w[1]).unwrap();
    }
    Fx {
        ssa,
        env: TableEnv::default(),
        ram,
        reg,
        blocks,
    }
}

impl Fx {
    pub(crate) fn ram(&self, off: u64) -> Address {
        Address::new(self.ram, off)
    }

    pub(crate) fn reg(&self, off: u64) -> Address {
        Address::new(self.reg, off)
    }

    /// A new op at `ram:pc` with the opcode and `n` empty input slots.
    pub(crate) fn op(&mut self, opc: OpCode, n: usize, pc: u64) -> OpId {
        let op = self.ssa.new_op(n, self.ram(pc)).unwrap();
        self.ssa.op_set_opcode(op, opc).unwrap();
        op
    }

    /// A free register varnode.
    pub(crate) fn regvn(&mut self, off: u64, size: i32) -> VarnodeId {
        let a = self.reg(off);
        self.ssa.new_varnode(&mut self.env, size, a, None).unwrap()
    }

    /// A constant.
    pub(crate) fn cst(&mut self, size: i32, val: u64) -> VarnodeId {
        self.ssa.new_constant(&mut self.env, size, val).unwrap()
    }

    /// `out = opc(ins…)` at `ram:pc`, inserted at the end of block `b`;
    /// `out` is a register at `out_off` of size 4 (or none).
    pub(crate) fn emit(
        &mut self,
        b: usize,
        opc: OpCode,
        pc: u64,
        out_off: Option<u64>,
        ins: &[VarnodeId],
    ) -> OpId {
        let op = self.op(opc, ins.len(), pc);
        for (slot, &v) in ins.iter().enumerate() {
            self.ssa.op_set_input(&mut self.env, op, v, slot).unwrap();
        }
        if let Some(off) = out_off {
            let a = self.reg(off);
            self.ssa.new_varnode_out(&mut self.env, 4, a, op).unwrap();
        }
        let blk = self.blocks[b];
        self.ssa.op_insert(op, blk, None).unwrap();
        op
    }

    /// Asserts that the state is consistent.
    pub(crate) fn ok(&self) {
        let bad = self.ssa.invariant_violations();
        assert!(bad.is_empty(), "{bad:#?}");
    }
}
