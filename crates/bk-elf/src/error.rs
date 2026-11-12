//! Fatal errors: the cases in which Ghidra's `ElfHeader` constructor throws
//! `ElfException` and no ELF file comes out.

use bk_bin::BinError;

/// Why a file could not be parsed as ELF at all.
///
/// Everything else that can be wrong with a file is a
/// [`Diagnostic`](crate::Diagnostic) next to a parsed result.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ElfError {
    /// The file does not start with `\x7fELF`.
    #[error("Not a valid ELF executable.")]
    NotElf,

    /// The file has the magic number but is shorter than the smallest part
    /// of the header needed to continue.
    #[error("Not enough bytes to be a valid ELF executable.")]
    TooShort {
        /// Length of the file.
        len: u64,
    },

    /// `e_ident[EI_CLASS]` is neither 32-bit nor 64-bit.
    #[error("Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x{class:x})")]
    UnsupportedClass {
        /// The class byte.
        class: u8,
    },

    /// `e_phentsize` is wrong and there are no section headers to fall back on.
    #[error("Unsupported e_phentsize value (program header size): {actual} (expected {expected})")]
    UnsupportedProgramHeaderSize {
        /// The size in the file.
        actual: u16,
        /// The size the class requires.
        expected: u16,
    },

    /// `e_shentsize` is wrong and there are no program headers to fall back on.
    #[error("Unsupported e_shentsize value (section header size): {actual} (expected {expected})")]
    UnsupportedSectionHeaderSize {
        /// The size in the file.
        actual: u16,
        /// The size the class requires.
        expected: u16,
    },

    /// The provider failed while the header was read (an I/O error, not a
    /// short file: short files are zero-padded).
    #[error("error reading the ELF header: {0}")]
    Read(#[from] BinError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_match_ghidra() {
        assert_eq!(ElfError::NotElf.to_string(), "Not a valid ELF executable.");
        assert_eq!(
            ElfError::TooShort { len: 5 }.to_string(),
            "Not enough bytes to be a valid ELF executable."
        );
        assert_eq!(
            ElfError::UnsupportedClass { class: 3 }.to_string(),
            "Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x3)"
        );
        assert_eq!(
            ElfError::UnsupportedProgramHeaderSize {
                actual: 57,
                expected: 56
            }
            .to_string(),
            "Unsupported e_phentsize value (program header size): 57 (expected 56)"
        );
        assert_eq!(
            ElfError::UnsupportedSectionHeaderSize {
                actual: 1,
                expected: 40
            }
            .to_string(),
            "Unsupported e_shentsize value (section header size): 1 (expected 40)"
        );
    }
}
