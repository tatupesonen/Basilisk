//! GNU binutils' disassembly, in process.
//!
//! Ghidra can show GNU's disassembly of an instruction beside its own, to
//! check a processor specification. It runs `gdis`
//! (`GPL/GnuDisassembler/src/gdis/c/disasm_1.c`), a small C program over
//! binutils' libopcodes, through `GNUExternalDisassembler`
//! (`Ghidra/Extensions/SleighDevTools`). This crate offers the same as a
//! library over `bk-binutils-sys`, which builds binutils 2.41 into the
//! binary:
//!
//! * [`Architecture`]: a GNU architecture name as Ghidra's `.ldefs` files
//!   give it (`external_name tool="gnu"`), or the numeric
//!   `0x<arch>:0x<mach>` form;
//! * [`Disassembler`]: one architecture, byte order and option string;
//!   [`Disassembler::instruction`] and [`Disassembler::block`] produce
//!   [`Instruction`]s with the text and the information `gdis` reports;
//! * [`gdis_config`]: the `.gdis` files that choose options by
//!   context-register value.
//!
//! # Threads
//!
//! binutils' disassemblers keep static state, so every call into them is
//! serialised by one process-wide lock in `bk-binutils-sys`. Disassemblers
//! are `Send` and may be used from any thread; calls take turns.
//!
//! # State between calls
//!
//! A disassembler created with given options behaves the same whatever was
//! created before it. Where binutils can apply options only once per
//! process (ARC, `LoongArch`, VAX, RISC-V's `priv-spec`), creating a
//! disassembler that disagrees with the first is refused with
//! [`Error::Raw`] holding `RawError::OptionsConflict`.
//!
//! Some targets carry *sequence* state from one instruction to the next.
//! ARM's IT and VPT blocks are the main case (an instruction inside an `it`
//! block is conditional): that state lives for one call. The instructions
//! of one [`Disassembler::block`] see each other, and every call starts
//! fresh (binutils keeps it in statics for the whole process; a patch in
//! `bk-binutils-sys` resets it). To decode an instruction in the context of
//! the bytes before it, give those bytes and an offset to
//! [`Disassembler::instruction_at`]: ARM scans back through them for an
//! enclosing IT block, as it does after a jump. Other targets that look at
//! the previous instruction (`MicroBlaze`'s `imm` prefix) remember only its
//! address and read it again from the bytes given, so they too see only
//! the bytes of the current call.
//!
//! # Hostile input
//!
//! The bytes may come from a hostile binary. binutils reads only the bytes
//! given, writes only to the crate's own buffers, and an `abort()`,
//! `exit()` or failed assertion inside it becomes an error
//! ([`RawError::Aborted`]); the architecture family is then not used again
//! in the process ([`RawError::Quarantined`]). A memory-safety bug or an
//! endless loop inside binutils is not contained: the fuzz target and the
//! sanitizer runs look for those.
//!
//! On platforms where binutils is not built (Windows, for now) every
//! operation fails with `RawError::Unavailable`; see [`is_available`].

mod arch;
mod block;
mod disassembler;
mod error;
pub mod gdis_config;
mod instruction;

pub use arch::Architecture;
pub use bk_binutils_sys::{BINUTILS_VERSION, RawError};
pub use block::{Block, BlockEnd};
pub use disassembler::{Disassembler, Endian};
pub use error::Error;
pub use instruction::{Instruction, InstructionInfo, InstructionKind};

/// Whether binutils is built into this binary; when `false`, every
/// operation fails with `RawError::Unavailable`.
pub fn is_available() -> bool {
    bk_binutils_sys::is_available()
}
