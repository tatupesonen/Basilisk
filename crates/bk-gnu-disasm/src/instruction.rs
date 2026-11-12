//! One disassembled instruction.

use bk_binutils_sys::Step;

/// What kind of instruction binutils says it is (`enum dis_insn_type` of
/// `include/dis-asm.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InstructionKind {
    /// Not a valid instruction.
    NonInstruction,
    /// Not a branch.
    NonBranch,
    /// Unconditional branch.
    Branch,
    /// Conditional branch.
    ConditionalBranch,
    /// Jump to subroutine.
    Call,
    /// Conditional jump to subroutine.
    ConditionalCall,
    /// Data reference.
    DataReference,
    /// Two data references.
    TwoDataReferences,
    /// A value this version does not know.
    Other(u8),
}

impl InstructionKind {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::NonInstruction,
            1 => Self::NonBranch,
            2 => Self::Branch,
            3 => Self::ConditionalBranch,
            4 => Self::Call,
            5 => Self::ConditionalCall,
            6 => Self::DataReference,
            7 => Self::TwoDataReferences,
            other => Self::Other(other),
        }
    }
}

/// The extra information a target may report about an instruction
/// (`insn_info_valid` and the fields it guards); what `gdis` prints on its
/// `Info:` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstructionInfo {
    /// The kind of instruction.
    pub kind: InstructionKind,
    /// Instructions that execute before a branch takes effect.
    pub branch_delay_insns: u8,
    /// Size in bytes of the data referenced, if known.
    pub data_size: u8,
    /// Branch or data target, zero when unknown.
    pub target: u64,
    /// Second data target.
    pub target2: u64,
}

/// One instruction as binutils disassembled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Its address.
    pub address: u64,
    /// Its length in bytes (octets), always at least one. It may exceed
    /// the bytes that were left when a target reports a length it could not
    /// fully read; see [`Instruction::read_fault`].
    pub length: usize,
    /// The text exactly as binutils printed it, with its tabs (bytes that
    /// are not UTF-8 replaced).
    pub text: String,
    /// The text was longer than `bk_binutils_sys::TEXT_CAPACITY` and was
    /// cut.
    pub text_truncated: bool,
    /// Information about the instruction, when the target reports it.
    pub info: Option<InstructionInfo>,
    /// The first address outside the bytes given that the disassembler
    /// tried to read while decoding this instruction, if any. x86, for
    /// one, then prints the first byte as `.byte`.
    pub read_fault: Option<u64>,
}

impl Instruction {
    pub(crate) fn from_step(address: u64, length: usize, step: &Step<'_>) -> Self {
        Self {
            address,
            length,
            text: String::from_utf8_lossy(step.text).into_owned(),
            text_truncated: step.text_truncated,
            info: step.info_valid.then(|| InstructionInfo {
                kind: InstructionKind::from_raw(step.insn_type),
                branch_delay_insns: step.branch_delay_insns,
                data_size: step.data_size,
                target: step.target,
                target2: step.target2,
            }),
            read_fault: step.read_fault,
        }
    }

    /// The text as Ghidra shows it: tabs replaced by spaces, surrounding
    /// white space removed (`GnuDisassembledInstruction`).
    pub fn ghidra_text(&self) -> String {
        self.text.replace('\t', " ").trim().to_owned()
    }
}
