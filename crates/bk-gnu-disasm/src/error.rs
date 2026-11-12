//! Errors of disassembly.

use bk_binutils_sys::RawError;

/// An error from creating a disassembler or disassembling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// binutils 2.41 knows no architecture of this name.
    #[error("binutils {} knows no architecture {name:?}; known: {}", bk_binutils_sys::BINUTILS_VERSION, .available.join(", "))]
    UnknownArchitecture {
        /// The name asked for.
        name: String,
        /// Every name binutils lists.
        available: Vec<String>,
    },
    /// binutils lists the architecture but cannot look it up by that name
    /// (`tms320c3x`, `tms320c4x`: their scan function accepts `c3x`, `tic4x`
    /// and similar, not the names it prints). `gdis` crashes on these.
    #[error(
        "binutils lists architecture {name:?} but cannot look it up by that name; \
         try one of its aliases or the numeric form 0x<arch>:0x<mach>"
    )]
    UnresolvableArchitecture {
        /// The name asked for.
        name: String,
    },
    /// A numeric architecture (`0x<arch>:0x<mach>`) that does not parse.
    #[error("{text:?} is not a numeric architecture of the form 0x<arch>:0x<mach>")]
    BadNumericArchitecture {
        /// The text given.
        text: String,
    },
    /// No instruction could be decoded at this address: the disassembler
    /// returned zero or a negative length (typically because the
    /// instruction runs past the end of the bytes given).
    #[error("no instruction at {address:#x} (binutils returned {returned}{})", fault_text(*.read_fault))]
    NoInstruction {
        /// Address of the attempted instruction.
        address: u64,
        /// What the disassembler returned.
        returned: i32,
        /// The first address outside the bytes given that it tried to read.
        read_fault: Option<u64>,
    },
    /// An offset outside the bytes given.
    #[error("offset {offset} is outside the {len} bytes given")]
    OffsetOutOfRange {
        /// The offset asked for.
        offset: usize,
        /// Number of bytes given.
        len: usize,
    },
    /// From the binutils layer: unavailable on this platform, no
    /// disassembler, binutils aborted, options in conflict, and the like.
    #[error(transparent)]
    Raw(#[from] RawError),
}

fn fault_text(fault: Option<u64>) -> String {
    fault.map_or_else(String::new, |a| {
        format!("; it tried to read {a:#x}, outside the bytes given")
    })
}
