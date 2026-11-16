//! Errors of the IR. Where Ghidra throws a `LowlevelError` the message is
//! Ghidra's; where Ghidra assumes (a slot in range, a reader present, an op
//! alive) the error names the method and the ids.

use crate::ids::{OpId, VarnodeId};

/// An error of an IR query or mutation. A mutation that returns an error
/// has changed nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IrError {
    /// The varnode id was never allocated.
    #[error("no varnode {0}")]
    NoSuchVarnode(VarnodeId),
    /// The varnode was destroyed.
    #[error("varnode {0} was destroyed")]
    DestroyedVarnode(VarnodeId),
    /// The op id was never allocated.
    #[error("no op {0}")]
    NoSuchOp(OpId),
    /// The op was retired (`PcodeOpBank::destroy`).
    #[error("op {0} was retired")]
    RetiredOp(OpId),
    /// The block does not exist or is not a basic block of this function.
    #[error("no basic block {0}")]
    NoSuchBlock(u32),
    /// An input slot outside the op's inputs.
    #[error("{method}: op {op} has no input slot {slot}")]
    NoSuchSlot {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
        /// The slot.
        slot: usize,
    },
    /// An input slot holds no varnode where one is needed.
    #[error("{method}: input slot {slot} of op {op} is empty")]
    EmptySlot {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
        /// The slot.
        slot: usize,
    },
    /// The op has no opcode yet.
    #[error("{method}: op {op} has no opcode")]
    NoOpcode {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
    },
    /// The op is in no basic block where it must be in one.
    #[error("{method}: op {op} is not in a basic block")]
    NotInBlock {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
    },
    /// The op is already in a basic block (or alive) where it must not be.
    #[error("{method}: op {op} is already in a basic block")]
    AlreadyInBlock {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
    },
    /// The varnode has no defining op where one is needed.
    #[error("{method}: varnode {vn} is not written")]
    NotWritten {
        /// The method.
        method: &'static str,
        /// The varnode.
        vn: VarnodeId,
    },
    /// Ghidra `addDescend`: a free varnode that is not a space base may have
    /// one reader only.
    #[error("Free varnode has multiple descendants")]
    FreeMultipleDescendants(VarnodeId),
    /// `eraseDescend` of an op that does not read the varnode (Ghidra walks
    /// off the list).
    #[error("eraseDescend: op {op} does not read varnode {vn}")]
    NotADescendant {
        /// The varnode.
        vn: VarnodeId,
        /// The op.
        op: OpId,
    },
    /// Ghidra `VarnodeBank::setInput`.
    #[error("Making input out of varnode which is not free")]
    InputNotFree(VarnodeId),
    /// Ghidra `VarnodeBank::setInput`.
    #[error("Making input out of constant varnode")]
    InputConstant(VarnodeId),
    /// Ghidra `VarnodeBank::setDef`; `at` is the op's address as Ghidra
    /// prints it (shortcut and raw offset).
    #[error("Defining varnode which is not free at {at}")]
    DefineNotFree {
        /// The varnode.
        vn: VarnodeId,
        /// The op's address.
        at: String,
    },
    /// Ghidra `Varnode::setDef`.
    #[error("Assignment to constant at {at}")]
    AssignToConstant {
        /// The varnode.
        vn: VarnodeId,
        /// The op's address.
        at: String,
    },
    /// Ghidra `VarnodeBank::destroy`.
    #[error("Deleting integrated varnode")]
    IntegratedVarnode(VarnodeId),
    /// Ghidra `PcodeOpBank::destroy`.
    #[error("Deleting integrated op")]
    IntegratedOp(OpId),
    /// Ghidra `opMarkHalt`.
    #[error("Only RETURN pcode ops can be marked as halt")]
    HaltNotReturn(OpId),
    /// Ghidra `opMarkHalt`.
    #[error("Bad halt flag")]
    BadHaltFlag(OpId),
    /// Ghidra `insertAfterDead`.
    #[error("Dead move called on ops which aren't dead")]
    DeadMove(OpId),
    /// Ghidra `setInputVarnode`.
    #[error("Overlapping input varnodes")]
    OverlappingInputs(VarnodeId),
    /// Ghidra `markIndirectCreation`.
    #[error("Indirect creation not properly formed")]
    IndirectCreation(OpId),
    /// A sequence number already names another op (Ghidra's map would
    /// silently replace it).
    #[error("sequence number of op {existing} given to a new op")]
    DuplicateSeqNum {
        /// The op that has it.
        existing: OpId,
    },
    /// The op is not of the kind the method needs.
    #[error("{method}: op {op} is not {what}")]
    WrongOp {
        /// The method.
        method: &'static str,
        /// The op.
        op: OpId,
        /// What it should be.
        what: &'static str,
    },
    /// An `iop` varnode does not name a live op.
    #[error("varnode {0} does not name an op")]
    NotAnOpReference(VarnodeId),
    /// An `iop` address must name an op of the function (Ghidra's offset is
    /// a live `PcodeOp*`, `newVarnodeIop`, `funcdata_varnode.cc:190`).
    #[error("iop address {offset:#x} names no op of the function")]
    IopNamesNoOp {
        /// The offset (an op id).
        offset: u64,
    },
    /// The function has no basic block 0 where one is needed.
    #[error("{0}: the function has no basic blocks")]
    NoBlocks(&'static str),
    /// A flag bit that only the mutation methods may change (`input`,
    /// `written`, `insert`, `constant`, `annotation`).
    #[error("{method}: bits {bits:#x} of varnode {vn} change only through the mutation methods")]
    StructuralFlags {
        /// The method.
        method: &'static str,
        /// The varnode.
        vn: VarnodeId,
        /// The refused bits.
        bits: u32,
    },
    /// Ghidra `beginDef`/`endDef(written, addr)`: written varnodes are not
    /// contiguous by address in def order.
    #[error("Cannot get contiguous written AND addressed")]
    WrittenByAddress,
    /// An op with more input slots than the IR stores (65,535).
    #[error("an op may have at most 65535 inputs, not {0}")]
    TooManyInputs(usize),
    /// A count or size beyond the IR's limits.
    #[error("{what} limit of {limit} reached")]
    Limit {
        /// What overflowed.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// A space the IR needs is missing from the space manager.
    #[error("the space manager has no {0} space")]
    MissingSpace(&'static str),
    /// Ghidra `collapse`: the op is not a unary or binary op with an
    /// output and inputs.
    #[error("Invalid constant collapse")]
    InvalidCollapse(OpId),
    /// The arithmetic of an op failed.
    #[error(transparent)]
    Eval(#[from] bk_pcode::EvalError),
    /// The block graph refused an edit.
    #[error(transparent)]
    Cfg(#[from] bk_decomp_cfg::CfgError),
}

/// A result of the IR.
pub type IrResult<T> = Result<T, IrError>;
