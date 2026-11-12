//! String tables.

use std::borrow::Cow;

use bk_bin::BinaryReader;

use crate::diag::{Diagnostic, DiagnosticKind};
use crate::limits::is_negative;

/// A string table: where it is and how long it is (Ghidra's
/// `ElfStringTable`). Strings are read from the file on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTable {
    /// Index of the `SHT_STRTAB` section this table was found through, or
    /// `None` for the dynamic string table located through `DT_STRTAB`.
    pub section: Option<u32>,
    /// File offset of the table.
    pub file_offset: u64,
    /// Address of the table in the loaded image (prelink-adjusted), or 0.
    pub address: u64,
    /// Length of the table in bytes.
    pub length: u64,
}

/// Java's `String.trim()`: strips characters up to U+0020 from both ends.
pub(crate) fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// Decodes a string's bytes as UTF-8 (malformed input becomes U+FFFD) and
/// trims it the way Ghidra does, borrowing when nothing had to change.
pub(crate) fn decode_trimmed(bytes: Cow<'_, [u8]>) -> Cow<'_, str> {
    match bytes {
        Cow::Borrowed(bytes) => match String::from_utf8_lossy(bytes) {
            Cow::Borrowed(text) => Cow::Borrowed(java_trim(text)),
            Cow::Owned(text) => Cow::Owned(java_trim(&text).to_owned()),
        },
        Cow::Owned(bytes) => Cow::Owned(java_trim(&String::from_utf8_lossy(&bytes)).to_owned()),
    }
}

impl StringTable {
    /// Reads the string at `string_offset` (Ghidra's `readString`).
    ///
    /// The offset must lie inside the table; the string itself is read up to
    /// its terminator even if that lies past the table's end, or up to the
    /// end of the file. It is decoded as UTF-8 and trimmed of leading and
    /// trailing whitespace and control characters.
    ///
    /// `reader` must be the file's zero-padding reader. On failure the
    /// result is the diagnostic Ghidra logs.
    pub(crate) fn read<'a>(
        &self,
        reader: &BinaryReader<'a>,
        string_offset: u64,
    ) -> Result<Cow<'a, str>, Diagnostic> {
        let failure = || {
            Diagnostic::new(
                DiagnosticKind::StringRead,
                format!(
                    "Failed to read Elf String at offset 0x{string_offset:x} within String Table \
                     at offset 0x{:x}",
                    self.file_offset
                ),
            )
        };
        if is_negative(self.file_offset) || string_offset >= self.length {
            return Err(failure());
        }
        let position = self
            .file_offset
            .checked_add(string_offset)
            .ok_or_else(failure)?;
        reader
            .read_terminated_bytes_at(position, 1)
            .map(decode_trimmed)
            .map_err(|_| failure())
    }
}

#[cfg(test)]
mod tests {
    use bk_bin::{Endian, MemoryProvider, UnlimitedProvider};

    use super::*;

    fn table(offset: u64, length: u64) -> StringTable {
        StringTable {
            section: None,
            file_offset: offset,
            address: 0,
            length,
        }
    }

    #[test]
    fn reads_and_trims() {
        let memory = MemoryProvider::new(b"xx\0main\0  spaced \t\0\xff\xfe\0end".to_vec());
        let unlimited = UnlimitedProvider::new(&memory);
        let reader = BinaryReader::new(&unlimited, Endian::Little);
        let t = table(2, 28);
        assert_eq!(t.read(&reader, 0).unwrap(), "");
        assert_eq!(t.read(&reader, 1).unwrap(), "main");
        assert!(matches!(t.read(&reader, 1).unwrap(), Cow::Borrowed(_)));
        assert_eq!(t.read(&reader, 6).unwrap(), "spaced");
        assert_eq!(t.read(&reader, 17).unwrap(), "\u{fffd}\u{fffd}");
        // The last string has no terminator: the zero padding ends it.
        assert_eq!(t.read(&reader, 20).unwrap(), "end");
    }

    #[test]
    fn offset_outside_the_table_fails_with_ghidra_message() {
        let memory = MemoryProvider::new(b"\0abc\0def\0".to_vec());
        let unlimited = UnlimitedProvider::new(&memory);
        let reader = BinaryReader::new(&unlimited, Endian::Little);
        let t = table(0, 5);
        assert_eq!(t.read(&reader, 4).unwrap(), "");
        let err = t.read(&reader, 5).unwrap_err();
        assert_eq!(err.kind, DiagnosticKind::StringRead);
        assert_eq!(
            err.message,
            "Failed to read Elf String at offset 0x5 within String Table at offset 0x0"
        );
        // A string that starts inside the table may run past its end.
        assert_eq!(table(0, 3).read(&reader, 1).unwrap(), "abc");
        assert!(table(u64::MAX, 5).read(&reader, 1).is_err());
        assert!(table(u64::MAX - 1, 5).read(&reader, 3).is_err());
        assert!(table(0, 0).read(&reader, 0).is_err());
    }

    #[test]
    fn java_trim_semantics() {
        assert_eq!(java_trim(" \t\x01ab c\n\0"), "ab c");
        assert_eq!(
            java_trim("\u{a0}x\u{a0}"),
            "\u{a0}x\u{a0}",
            "NBSP is above U+0020"
        );
        assert_eq!(java_trim(""), "");
        assert_eq!(decode_trimmed(Cow::Owned(b" a ".to_vec())), "a");
        assert_eq!(decode_trimmed(Cow::Borrowed(b" \xff ")), "\u{fffd}");
    }
}
