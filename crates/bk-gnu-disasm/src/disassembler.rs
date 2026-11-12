//! A disassembler for one architecture, byte order and option string.

use bk_binutils_sys::RawDisassembler;

use crate::{Architecture, Error, Instruction};

/// Byte order of the code to disassemble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

/// Bytes after an instruction's start handed to binutils by
/// [`Disassembler::instruction_at`] at first: more than any instruction of
/// any target needs. The whole slice is used when binutils reads past them.
const WINDOW_AFTER: usize = 256;
/// Bytes before the instruction handed along for context (ARM's IT scan).
const WINDOW_BEFORE: usize = 64;

/// binutils' disassembler for one architecture, byte order and option
/// string: what one running `gdis` is in Ghidra.
///
/// Creating one is cheap. See the crate documentation for threads and for
/// the state that carries between instructions.
#[derive(Debug)]
pub struct Disassembler {
    raw: RawDisassembler,
    architecture: Architecture,
    endian: Endian,
    options: Option<String>,
}

impl Disassembler {
    /// Creates a disassembler. `options` is a disassembler option string
    /// as `objdump -M` takes it (for example `intel`, or
    /// `force-thumb,reg-names-raw`).
    pub fn new(
        architecture: &Architecture,
        endian: Endian,
        options: Option<&str>,
    ) -> Result<Self, Error> {
        let raw = RawDisassembler::new(
            architecture.arch(),
            architecture.mach(),
            endian == Endian::Big,
            options,
        )?;
        Ok(Self {
            raw,
            architecture: architecture.clone(),
            endian,
            options: options.map(str::to_owned),
        })
    }

    /// The architecture.
    pub fn architecture(&self) -> &Architecture {
        &self.architecture
    }

    /// The byte order.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// The option string, as given.
    pub fn options(&self) -> Option<&str> {
        self.options.as_deref()
    }

    /// Disassembles the instruction at the start of `bytes`, which are the
    /// bytes at `address` onwards.
    pub fn instruction(&mut self, bytes: &[u8], address: u64) -> Result<Instruction, Error> {
        self.instruction_at(bytes, address, 0)
    }

    /// Disassembles the instruction `offset` bytes into `bytes`, which are
    /// the bytes at `base` onwards. Up to 64 bytes before `offset` serve as
    /// context for targets that look back (ARM finds an enclosing IT block
    /// in them); decoding otherwise starts afresh, as after a jump.
    ///
    /// Only a window around the instruction is handed to binutils (64 bytes
    /// before, 256 after, or the whole slice if binutils reads past those),
    /// so calling this for every instruction of a large slice is not
    /// quadratic.
    pub fn instruction_at(
        &mut self,
        bytes: &[u8],
        base: u64,
        offset: usize,
    ) -> Result<Instruction, Error> {
        let len = bytes.len();
        if offset >= len {
            return Err(Error::OffsetOutOfRange { offset, len });
        }
        let start = offset.saturating_sub(WINDOW_BEFORE);
        let end = offset.saturating_add(WINDOW_AFTER).min(len);
        let window = bytes.get(start..end).unwrap_or(bytes);
        let window_base = base.wrapping_add(start as u64);
        let mut result = self.decode_one(window, window_base, offset - start);
        let fault = match &result {
            Ok(insn) => insn.read_fault,
            Err(Error::NoInstruction { read_fault, .. }) => *read_fault,
            Err(_) => None,
        };
        if let Some(fault) = fault {
            // Relative to the window's start; a read before the window wraps
            // to a huge value.
            let past_window = fault.wrapping_sub(window_base);
            if past_window >= window.len() as u64 && past_window < (len - start) as u64 {
                // It read past the window into bytes that were given.
                return self.decode_one(bytes, base, offset);
            }
            if start > 0 && fault.wrapping_sub(base) < start as u64 {
                // A look back before the window, into bytes that were given:
                // not a read outside them.
                match &mut result {
                    Ok(insn) => insn.read_fault = None,
                    Err(Error::NoInstruction { read_fault, .. }) => *read_fault = None,
                    Err(_) => {}
                }
            }
        }
        result
    }

    fn decode_one(&mut self, bytes: &[u8], base: u64, offset: usize) -> Result<Instruction, Error> {
        let address = base.wrapping_add(offset as u64);
        let mut request = self.raw.request(bytes, base)?;
        let step = request.step(offset)?;
        match usize::try_from(step.length) {
            Ok(length) if length > 0 => Ok(Instruction::from_step(address, length, &step)),
            _ => Err(Error::NoInstruction {
                address,
                returned: step.length,
                read_fault: step.read_fault,
            }),
        }
    }

    /// The raw disassembler, for `block`.
    pub(crate) fn raw(&mut self) -> &mut RawDisassembler {
        &mut self.raw
    }
}
