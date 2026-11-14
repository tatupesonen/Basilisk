//! GNU binutils' disassemblers, built into Basilisk.
//!
//! This crate compiles the part of binutils 2.41 that disassembles —
//! libopcodes with every target, the architecture tables of libbfd and a few
//! files of libiberty, vendored under `vendor/binutils-2.41` — together with
//! a small C shim (`shim/`), links them statically, and wraps the shim in
//! the handful of safe functions below. It is the base of `bk-gnu-disasm`,
//! which offers what Ghidra's `gdis` program and `GNUExternalDisassembler`
//! do (`GPL/GnuDisassembler`, `Ghidra/Extensions/SleighDevTools`).
//!
//! It is the one crate of the workspace that contains C code and `unsafe`
//! (ADR-019). What the interface guarantees to safe callers:
//!
//! * **Serialised.** libopcodes keeps static state, so every call into it is
//!   made under one process-wide lock. The types here are `Send`; using them
//!   from several threads is sound, and calls simply take turns.
//! * **Bounded reads.** The disassembler can read only the bytes of the
//!   current [`Request`]; a read outside them is refused and reported.
//!   binutils works on a private copy of those bytes (one target, C-SKY,
//!   rewrites instruction bytes in place).
//! * **Bounded writes.** Instruction text is written into a fixed buffer of
//!   [`TEXT_CAPACITY`] bytes with a running bound; overlong text is cut and
//!   flagged, never overrun.
//! * **No process exit.** `abort()`, `exit()` and failed assertions inside
//!   binutils end the call in progress and surface as [`RawError::Aborted`].
//!
//! What it cannot guarantee is listed in `docs/features/gnu-disasm.md`: a
//! memory-safety bug or an endless loop inside binutils' C code is not
//! contained (the fuzz target looks for those).
//!
//! On targets that are neither Unix-like nor Windows, where the C is not
//! built (WebAssembly, bare metal), the crate
//! still compiles: [`is_available`] returns `false` and every operation
//! returns [`RawError::Unavailable`].

// All `unsafe` of the crate, and of the workspace, is in this one module.
#[cfg(bk_binutils_built)]
#[expect(
    unsafe_code,
    reason = "FFI to the vendored binutils (ADR-019); listed no-miri in unsafe-crates.txt (ADR-020)"
)]
mod real;
#[cfg(bk_binutils_built)]
use real as imp;

#[cfg(not(bk_binutils_built))]
mod stub;
#[cfg(not(bk_binutils_built))]
use stub as imp;

pub use imp::{RawDisassembler, Request};

/// The binutils release whose disassemblers are built in (the one Ghidra's
/// `GnuDisassembler` module names).
pub const BINUTILS_VERSION: &str = "2.41";

/// Size in bytes of the buffer one instruction's text is written to,
/// including a terminating NUL. Longer text is cut ([`Step::text_truncated`]).
pub const TEXT_CAPACITY: usize = 1024;

/// Whether binutils was built into this binary. When `false`, every other
/// function of this crate returns [`RawError::Unavailable`].
pub fn is_available() -> bool {
    cfg!(bk_binutils_built)
}

/// An error from the binutils shim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RawError {
    /// binutils is not built on this platform.
    #[error("GNU disassembly is not available on this platform: binutils is not built into it")]
    Unavailable,
    /// libopcodes has no disassembler for the architecture.
    #[error("binutils has no disassembler for architecture {arch:#x}, machine {mach:#x}")]
    NoDisassembler {
        /// BFD architecture number (`enum bfd_architecture`).
        arch: u32,
        /// BFD machine number.
        mach: u64,
    },
    /// An allocation inside the shim failed.
    #[error("out of memory in the binutils shim")]
    OutOfMemory,
    /// binutils called `abort()` or `exit()`, or an assertion in it failed.
    /// The call was abandoned and the process carries on; the architecture's
    /// family is quarantined from then on ([`RawError::Quarantined`]).
    #[error("binutils gave up: {message}")]
    Aborted {
        /// What binutils reported, when it reported anything.
        message: String,
    },
    /// A string handed to binutils contains a NUL byte.
    #[error("{what} contains a NUL byte at byte {position}")]
    EmbeddedNul {
        /// Which string.
        what: &'static str,
        /// Where the NUL is.
        position: usize,
    },
    /// The architecture's disassembler applies options only once per
    /// process (ARC, `LoongArch`, VAX; RISC-V's `priv-spec`), and an earlier
    /// disassembler of it was created with different ones. Creating this one
    /// would silently give it the earlier one's options.
    #[error(
        "binutils' disassembler for architecture {arch:#x} takes its options once per process, \
         and was already given different ones"
    )]
    OptionsConflict {
        /// BFD architecture number.
        arch: u32,
    },
    /// binutils aborted inside this architecture's disassembler earlier in
    /// this process. Its static state may be half-updated, so the family is
    /// no longer used (other architectures are unaffected).
    #[error(
        "binutils' disassembler for architecture {arch:#x} gave up earlier in this process \
         and is no longer used"
    )]
    Quarantined {
        /// BFD architecture number.
        arch: u32,
    },
    /// [`Request::step`] was asked for an offset outside the request's bytes.
    #[error("offset {offset} is outside the request's {len} bytes")]
    OffsetOutOfRange {
        /// The offset asked for.
        offset: usize,
        /// Number of bytes in the request.
        len: usize,
    },
    /// A disassembler was created, or a request started, on a thread that
    /// still has a [`Request`] open. Drop that request first.
    #[error("a request is still open on this thread; finish it before starting another")]
    RequestInProgress,
    /// The shim rejected its arguments; a bug in this crate.
    #[error("internal error: the binutils shim rejected its arguments")]
    Internal,
}

/// An architecture as BFD knows it (`bfd_arch_info_type`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchInfo {
    /// BFD architecture number (`enum bfd_architecture` of binutils 2.41).
    pub arch: u32,
    /// BFD machine number within the architecture.
    pub mach: u64,
    /// Bits in a word.
    pub bits_per_word: u32,
    /// Bits in an address.
    pub bits_per_address: u32,
    /// Family name, e.g. `i386`.
    pub family: String,
    /// Printable name, e.g. `i386:x86-64`; what [`architecture_names`] lists.
    pub printable_name: String,
}

/// What the disassembler reported for one instruction.
///
/// Borrows the request's text buffer, so it must be dropped (or copied from)
/// before the next [`Request::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// The disassembler's return value: the number of bytes the instruction
    /// occupies, or zero or a negative number when it could not decode one.
    pub length: i32,
    /// The text the disassembler printed, exactly as printed (it may contain
    /// tabs, and is not guaranteed to be UTF-8).
    pub text: &'a [u8],
    /// The text was longer than [`TEXT_CAPACITY`] and was cut.
    pub text_truncated: bool,
    /// The address of the first read outside the request's bytes that the
    /// disassembler attempted, if it attempted one.
    pub read_fault: Option<u64>,
    /// Whether the target filled in the fields below (`insn_info_valid`).
    pub info_valid: bool,
    /// Instructions that still execute before a branch takes effect.
    pub branch_delay_insns: u8,
    /// Size in bytes of the data the instruction references.
    pub data_size: u8,
    /// `enum dis_insn_type`: 0 not an instruction, 1 not a branch, 2 branch,
    /// 3 conditional branch, 4 call, 5 conditional call, 6 data reference,
    /// 7 two data references.
    pub insn_type: u8,
    /// Branch or data-reference target, zero when unknown.
    pub target: u64,
    /// Second data-reference target.
    pub target2: u64,
}

/// The printable names of every architecture binutils knows
/// (`bfd_arch_list`), in BFD's order.
pub fn architecture_names() -> Result<Vec<String>, RawError> {
    imp::architecture_names()
}

/// Looks an architecture up by name as `bfd_scan_arch` does. `Ok(None)`
/// means binutils knows no architecture of that name.
pub fn scan_architecture(name: &str) -> Result<Option<ArchInfo>, RawError> {
    imp::scan_architecture(name)
}
