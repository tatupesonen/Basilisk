//! Disassembling a block of bytes, as `gdis` does for each request.

use crate::{Disassembler, Error, Instruction};

/// The instructions of a block, in order, and why disassembly stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The instructions decoded.
    pub instructions: Vec<Instruction>,
    /// Why disassembly stopped.
    pub end: BlockEnd,
}

/// Why [`Disassembler::block`] stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockEnd {
    /// Every byte was disassembled (the last instruction may report a
    /// length past the end; see [`Instruction::length`]).
    Complete,
    /// No instruction could be decoded at `offset`: binutils returned zero
    /// or a negative length there (`gdis` would loop forever or step
    /// backwards).
    NoInstruction {
        /// Offset into the block.
        offset: usize,
        /// What binutils returned.
        returned: i32,
        /// The first address outside the block it tried to read.
        read_fault: Option<u64>,
    },
    /// An error at `offset`, after the instructions before it.
    Failed {
        /// Offset into the block.
        offset: usize,
        /// The error.
        error: Error,
    },
}

impl Disassembler {
    /// Disassembles `bytes`, the bytes at `address` onwards, from the start
    /// until they are used up or no instruction can be decoded.
    ///
    /// The instructions of one block see each other's sequence state (an
    /// ARM `it` makes the next instructions conditional); every call starts
    /// afresh. Results equal `gdis`' for every input within its limits (64
    /// instructions, 128 bytes), which this does not have.
    pub fn block(&mut self, bytes: &[u8], address: u64) -> Result<Block, Error> {
        let mut request = self.raw().request(bytes, address)?;
        let mut instructions = Vec::new();
        let mut offset = 0usize;
        let end = loop {
            if offset >= bytes.len() {
                break BlockEnd::Complete;
            }
            let step = match request.step(offset) {
                Ok(step) => step,
                Err(raw) => {
                    break BlockEnd::Failed {
                        offset,
                        error: raw.into(),
                    };
                }
            };
            match usize::try_from(step.length) {
                Ok(length) if length > 0 => {
                    let at = address.wrapping_add(offset as u64);
                    instructions.push(Instruction::from_step(at, length, &step));
                    offset = offset.saturating_add(length);
                }
                _ => {
                    break BlockEnd::NoInstruction {
                        offset,
                        returned: step.length,
                        read_fault: step.read_fault,
                    };
                }
            }
        };
        Ok(Block { instructions, end })
    }
}
