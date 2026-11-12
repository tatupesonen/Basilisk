//! Informational sections: `.gnu_debuglink`, `.gnu_debugaltlink`,
//! `.comment`.

use bk_bin::{BinaryReader, Endian};

use crate::note::hex;

/// `.gnu_debuglink` (Ghidra's `GnuDebugLink`): the file holding the debug
/// information, and its CRC-32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuDebugLink {
    /// Length of the file name with its terminator and padding to 4 bytes.
    pub filename_len: u32,
    /// The debug file's name.
    pub filename: String,
    /// CRC-32 of the debug file.
    pub crc: u32,
}

impl GnuDebugLink {
    /// The section this item lives in.
    pub const SECTION_NAME: &'static str = ".gnu_debuglink";

    /// Reads the section's bytes; `None` when they end early, as in Ghidra.
    pub fn read(data: &[u8], endian: Endian) -> Option<Self> {
        let mut r = BinaryReader::from_slice(data, endian);
        let filename = r.read_ascii().ok()?;
        r.align(4);
        let filename_len = u32::try_from(r.position()).ok()?;
        let crc = r.read_u32().ok()?;
        Some(Self {
            filename_len,
            filename,
            crc,
        })
    }
}

/// `.gnu_debugaltlink` (Ghidra's `GnuDebugAltLink`): the supplementary
/// debug file and its build id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuDebugAltLink {
    /// Length of the file name with its terminator.
    pub filename_len: u32,
    /// The supplementary file's name.
    pub filename: String,
    /// Its build id: the rest of the section.
    pub hash: Vec<u8>,
}

impl GnuDebugAltLink {
    /// The section this item lives in.
    pub const SECTION_NAME: &'static str = ".gnu_debugaltlink";

    /// The most bytes of hash Ghidra accepts.
    pub const MAX_HASH_LEN: usize = 1024;

    /// Reads the section's bytes; `None` when the name is unterminated or
    /// the hash is longer than 1024 bytes, as in Ghidra.
    pub fn read(data: &[u8]) -> Option<Self> {
        let mut r = BinaryReader::from_slice(data, Endian::Little);
        let filename = r.read_ascii().ok()?;
        let filename_len = u32::try_from(r.position()).ok()?;
        let hash = data.get(r.position() as usize..)?;
        if hash.len() > Self::MAX_HASH_LEN {
            return None;
        }
        Some(Self {
            filename_len,
            filename,
            hash: hash.to_vec(),
        })
    }

    /// The hash as lowercase hex.
    pub fn hash_hex(&self) -> String {
        hex(&self.hash, "")
    }
}

/// `.comment` (Ghidra's `ElfComment`): the NUL-terminated strings the
/// toolchain left, with the length each takes in the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfComment {
    /// The strings, decoded as UTF-8.
    pub strings: Vec<String>,
    /// Bytes each string takes, its terminator included.
    pub lengths: Vec<u32>,
}

impl ElfComment {
    /// The section this item lives in.
    pub const SECTION_NAME: &'static str = ".comment";

    /// Reads the section's bytes; `None` when the last string is not
    /// terminated, as in Ghidra.
    pub fn read(data: &[u8]) -> Option<Self> {
        let mut r = BinaryReader::from_slice(data, Endian::Little);
        let (mut strings, mut lengths) = (Vec::new(), Vec::new());
        while r.has_next() {
            let start = r.position();
            strings.push(r.read_utf8().ok()?);
            lengths.push(u32::try_from(r.position() - start).ok()?);
        }
        Some(Self { strings, lengths })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_link() {
        let mut data = b"lib.so.debug\0\0\0\0".to_vec();
        data.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        let link = GnuDebugLink::read(&data, Endian::Big).unwrap();
        assert_eq!(
            link,
            GnuDebugLink {
                filename_len: 16,
                filename: "lib.so.debug".into(),
                crc: 0x1234_5678
            }
        );
        assert_eq!(GnuDebugLink::read(&data[..17], Endian::Big), None);
    }

    #[test]
    fn debug_alt_link() {
        let link = GnuDebugAltLink::read(b"/x/alt.debug\0\x01\x02\xff").unwrap();
        assert_eq!((link.filename_len, link.hash_hex()), (13, "0102ff".into()));
        let mut long = b"a\0".to_vec();
        long.resize(2 + 1025, 7);
        assert_eq!(GnuDebugAltLink::read(&long), None);
        assert_eq!(GnuDebugAltLink::read(b"unterminated"), None);
    }

    #[test]
    fn comment() {
        let c = ElfComment::read(b"GCC: 13\0\0clang\0").unwrap();
        assert_eq!(c.strings, ["GCC: 13", "", "clang"]);
        assert_eq!(c.lengths, [8, 1, 6]);
        assert_eq!(ElfComment::read(b"GCC\0x"), None);
    }
}
