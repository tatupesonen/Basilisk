//! The packed records of varnodes, ops and basic blocks. Every field is
//! private to the crate: structure changes only through the mutation
//! interface of [`Ssa`](crate::Ssa).

use bk_core::{Address, RangeList};

use crate::cover::Cover;
use crate::ids::{NONE, OpId, VarnodeId};
use crate::list::ListHead;
use crate::pool::IdList;

/// One varnode (Ghidra `Varnode`, varnode.hh:136–157). Pointers are ids;
/// the reader list is inline for up to three readers.
#[derive(Clone, Debug)]
pub(crate) struct VarnodeData {
    /// `flags` (`vflags`).
    pub(crate) flags: u32,
    /// `addlflags` (`vaddl`).
    pub(crate) addl: u16,
    /// `mergegroup`.
    pub(crate) merge_group: i16,
    /// `size`.
    pub(crate) size: i32,
    /// `create_index`.
    pub(crate) create_index: u32,
    /// `loc`; for `iop` varnodes the offset is the `OpId`, for `fspec`
    /// varnodes the `CallSpecId`, for space constants the space index.
    pub(crate) loc: Address,
    /// `def` (an `OpId`, or `NONE`).
    pub(crate) def: u32,
    /// `high` (a `HighId`, or `NONE`).
    pub(crate) high: u32,
    /// `type` (a `TypeId`'s raw value, or `NONE`).
    pub(crate) ty: u32,
    /// `mapentry` (an index into the function's entry table, or `NONE`).
    pub(crate) entry: u32,
    /// `consumed`.
    pub(crate) consumed: u64,
    /// `nzm`.
    pub(crate) nzm: u64,
    /// `descend`, in order.
    pub(crate) readers: IdList,
    /// `cover`, built on demand.
    pub(crate) cover: Option<Box<Cover>>,
}

impl VarnodeData {
    pub(crate) fn def(&self) -> Option<OpId> {
        OpId::from_packed(self.def)
    }
}

/// What kind of offset a varnode carries, and whether it is still alive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VState {
    /// Destroyed (`VarnodeBank::destroy`, or merged away by `xref`).
    pub(crate) destroyed: bool,
    /// A `LOAD`/`STORE` space constant: the offset is a space index.
    pub(crate) space_const: bool,
}

/// Which tree of the op bank holds an op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tree {
    /// `optree`.
    Main,
    /// `alttree`, the quarantined `INDIRECT`s.
    Alt,
    /// Retired: in neither tree (`deadandgone`).
    Retired,
}

/// One p-code op (Ghidra `PcodeOp`, op.hh:124–133). 64 bytes; its list
/// links live in a parallel array.
#[derive(Clone, Debug)]
pub(crate) struct OpData {
    /// `start.pc`.
    pub(crate) pc: Address,
    /// `start.uniq`.
    pub(crate) time: u32,
    /// `start.order`.
    pub(crate) order: u32,
    /// `flags` (`oflags`).
    pub(crate) flags: u32,
    /// `addlflags` (`oaddl`).
    pub(crate) addl: u32,
    /// `parent` (a block's node index, or `NONE`).
    pub(crate) parent: u32,
    /// `output` (a `VarnodeId`, or `NONE`).
    pub(crate) output: u32,
    /// `inrefs`; an empty slot is `NONE`.
    pub(crate) inputs: IdList,
    /// The opcode's value (0: none yet).
    pub(crate) opcode: u8,
    /// The tree it is in.
    pub(crate) tree: Tree,
}

impl OpData {
    pub(crate) fn output(&self) -> Option<VarnodeId> {
        VarnodeId::from_packed(self.output)
    }

    pub(crate) fn parent_raw(&self) -> Option<u32> {
        (self.parent != NONE).then_some(self.parent)
    }

    pub(crate) fn opcode(&self) -> Option<bk_pcode::OpCode> {
        bk_pcode::OpCode::from_u8(self.opcode)
    }
}

/// The op half of a basic block (Ghidra `BlockBasic::op`, `cover`).
#[derive(Clone, Debug, Default)]
pub(crate) struct BasicData {
    /// Whether this node index is a basic block of the function.
    pub(crate) present: bool,
    /// The ops in order.
    pub(crate) ops: ListHead,
    /// The original address ranges (`RangeList cover`).
    pub(crate) cover: RangeList,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_small() {
        assert!(size_of::<OpData>() <= 64, "op {}", size_of::<OpData>());
        assert!(
            size_of::<VarnodeData>() <= 96,
            "varnode {}",
            size_of::<VarnodeData>()
        );
    }
}
