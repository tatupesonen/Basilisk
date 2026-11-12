//! What `pcodedump` reports: instructions, their p-code and decode errors.
//!
//! Opcodes and address spaces are plain names here. This crate depends on no
//! other basilisk crate, so the consumer maps them to its own types.

/// One run of `pcodedump`: a linear sweep over a byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeDump {
    /// The language the bytes were decoded as, for example `x86:LE:64:default`.
    pub language: String,
    /// Name of the address space the bytes were placed in (the language's
    /// default code space).
    pub space: String,
    /// Byte offset of the first input byte in that space.
    pub base: u64,
    /// Number of input bytes.
    pub byte_count: u64,
    /// Instructions and decode errors, in address order.
    pub records: Vec<DumpRecord>,
}

impl PcodeDump {
    /// The decoded instructions, skipping decode errors.
    pub fn instructions(&self) -> impl Iterator<Item = &DumpInstruction> {
        self.records.iter().filter_map(|record| match record {
            DumpRecord::Instruction(instruction) => Some(instruction),
            DumpRecord::Error(_) => None,
        })
    }

    /// The positions that did not decode.
    pub fn errors(&self) -> impl Iterator<Item = &DumpError> {
        self.records.iter().filter_map(|record| match record {
            DumpRecord::Error(error) => Some(error),
            DumpRecord::Instruction(_) => None,
        })
    }
}

/// One position of the sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpRecord {
    /// The bytes at this position are an instruction.
    Instruction(DumpInstruction),
    /// They are not; decoding resumed one byte later (or stopped, for
    /// [`DumpErrorKind::Truncated`]).
    Error(DumpError),
}

/// One disassembled instruction and its p-code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpInstruction {
    /// Byte offset of the instruction in the code space.
    pub address: u64,
    /// Length of the instruction itself in bytes. The sweep advances by this.
    pub length: u32,
    /// Number of bytes the p-code accounts for: the instruction plus any
    /// delay-slot instructions folded into it. Equal to `length` otherwise.
    pub flow_length: u32,
    /// The instruction's `length` bytes.
    pub bytes: Vec<u8>,
    /// The mnemonic as SLEIGH prints it.
    pub mnemonic: String,
    /// The operand text as SLEIGH prints it; may be empty.
    pub body: String,
    /// The p-code ops, in order. Empty when `lift_error` is set (and for
    /// instructions that genuinely have no p-code).
    pub pcode: Vec<DumpOp>,
    /// Why the instruction, though it disassembles, produced no p-code.
    pub lift_error: Option<LiftError>,
}

/// One p-code op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpOp {
    /// The opcode's name as Ghidra's `get_opname` gives it: `COPY`,
    /// `INT_ADD`, `CALLOTHER`, …
    pub opcode: String,
    /// The output varnode, if the op has one.
    pub output: Option<DumpVarnode>,
    /// The input varnodes, in order.
    pub inputs: Vec<DumpVarnode>,
}

/// One varnode: a size-byte location at an offset in an address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpVarnode {
    /// Name of the address space: `register`, `ram`, `unique`, `const`, …
    pub space: String,
    /// Offset within the space; the value itself for a constant.
    ///
    /// The first input of `LOAD` and `STORE` is a constant that identifies
    /// an address space. Ghidra's engine holds a host pointer there; the
    /// dump replaces it with the space's index in the language's space table
    /// and gives the space's name in `name`.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
    /// The register that is exactly this location, when there is one; for a
    /// space-identifying constant, the name of the space it identifies.
    pub name: Option<String>,
}

/// Why an instruction that disassembles has no p-code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftError {
    /// What kind of failure it was.
    pub kind: LiftErrorKind,
    /// The engine's message.
    pub message: String,
}

/// The ways lifting an instruction can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LiftErrorKind {
    /// The specification marks the instruction's semantics `unimpl`.
    Unimplemented,
    /// Bytes the p-code needs (a delay-slot instruction) do not decode.
    BadData,
    /// Any other error from the engine.
    Other,
}

/// A position that is not an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpError {
    /// Byte offset of the position in the code space.
    pub address: u64,
    /// Number of bytes the record covers: 1, or everything that was left for
    /// [`DumpErrorKind::Truncated`].
    pub length: u32,
    /// Those bytes.
    pub bytes: Vec<u8>,
    /// What kind of failure it was.
    pub kind: DumpErrorKind,
    /// The engine's message.
    pub message: String,
}

/// The ways a position can fail to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DumpErrorKind {
    /// No instruction pattern matches the bytes.
    BadData,
    /// An instruction starts here but needs bytes past the end of the
    /// input. Always the last record.
    Truncated,
    /// Any other error from the engine.
    Other,
}
