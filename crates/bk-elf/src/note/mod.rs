//! ELF notes and the informational sections Ghidra's loader reads
//! (`ghidra.app.util.bin.format.elf.info`): `ElfNote`, `NoteAbiTag`,
//! `NoteGnuBuildId`, `NoteGnuProperty`, `GnuDebugLink`, `GnuDebugAltLink`
//! and `ElfComment`.
//!
//! Ghidra reads these from the loaded program's memory; here they are read
//! from bytes (a section's or a segment's data), in the byte order the
//! caller gives — the file's data byte order for
//! [`ElfFile`](crate::ElfFile)'s conveniences.

mod gnu;
mod info;

use bk_bin::{BinError, BinaryReader, Endian};

pub use gnu::{NoteAbiTag, NoteGnuBuildId, NoteGnuProperty, PropertyElement};
pub use info::{ElfComment, GnuDebugAltLink, GnuDebugLink};

/// The longest note name Ghidra reads.
pub const MAX_NAME_LEN: u32 = 1024;
/// The longest note description Ghidra reads.
pub const MAX_DESC_LEN: u32 = 1024 * 1024;

/// Why a note or informational item could not be read (Ghidra's
/// `IOException` messages).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NoteError {
    /// A name or description length above Ghidra's limits.
    #[error("Invalid Note lengths: {name_len}, {desc_len}")]
    InvalidLengths {
        /// `n_namesz`.
        name_len: u64,
        /// `n_descsz`.
        desc_len: u64,
    },
    /// A note that is not what its section says it is.
    #[error("Invalid {section} values: {name}, {desc_len}")]
    InvalidContent {
        /// The section the note was read from.
        section: &'static str,
        /// The note's name.
        name: String,
        /// The length of its description.
        desc_len: usize,
    },
    /// The data ended or a value was out of range.
    #[error("{0}")]
    Read(#[from] BinError),
}

/// One note (`Elf_Nhdr` with its name and description; Ghidra's `ElfNote`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfNote {
    /// Length of the name field including its padding to 4 bytes.
    pub name_len: u32,
    /// The name, read as ASCII without trailing NULs (`GNU` for GNU notes).
    pub name: String,
    /// `n_type`.
    pub vendor_type: u32,
    /// The description bytes.
    pub description: Vec<u8>,
}

impl ElfNote {
    /// Reads a note at the reader's position (Ghidra's `ElfNote.read`). The
    /// reader is left after the description, which is not padded.
    pub fn read(reader: &mut BinaryReader<'_>) -> Result<Self, NoteError> {
        let name_len = reader.read_u32_count()?;
        let desc_len = reader.read_u32_count()?;
        let vendor_type = reader.read_u32()?;
        // Both are below 2³¹ (read_u32_count).
        let (name_len, desc_len) = (name_len as u32, desc_len as u32);
        if name_len > MAX_NAME_LEN || desc_len > MAX_DESC_LEN {
            return Err(NoteError::InvalidLengths {
                name_len: name_len.into(),
                desc_len: desc_len.into(),
            });
        }
        let name = reader.read_ascii_fixed(name_len as usize)?;
        let padding = reader.align(4) as u32;
        let description = reader.read_bytes(desc_len as usize)?.into_owned();
        Ok(Self {
            name_len: name_len + padding,
            name,
            vendor_type,
            description,
        })
    }

    /// True for a note named `GNU`.
    pub fn is_gnu(&self) -> bool {
        self.name == "GNU"
    }

    /// A reader over the description.
    pub fn description_reader(&self, endian: Endian) -> BinaryReader<'_> {
        BinaryReader::from_slice(&self.description, endian)
    }

    /// The description as lowercase hex digits (Ghidra's
    /// `getDescriptionAsHexString`).
    pub fn description_hex(&self) -> String {
        hex(&self.description, "")
    }

    /// Ghidra's `getNoteTypeName` for a plain note: `name, type`.
    pub fn type_name(&self) -> String {
        format!("{}, {}", self.name, self.vendor_type as i32)
    }
}

/// Bytes as lowercase hex pairs joined by `delimiter` (Ghidra's
/// `NumericUtilities.convertBytesToString`).
pub(crate) fn hex(bytes: &[u8], delimiter: &str) -> String {
    let mut out = String::with_capacity(bytes.len() * (2 + delimiter.len()));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(delimiter);
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Iterator over the notes in a `PT_NOTE` segment or `SHT_NOTE` section:
/// each note is followed by padding to 4 bytes, as Ghidra's loader reads
/// them (`markupPtNote`). Iteration stops after the first error.
#[derive(Debug, Clone)]
pub struct NoteIter<'a> {
    reader: BinaryReader<'a>,
    failed: bool,
}

impl<'a> NoteIter<'a> {
    /// Iterates the notes in `data`.
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Self {
            reader: BinaryReader::from_slice(data, endian),
            failed: false,
        }
    }
}

impl Iterator for NoteIter<'_> {
    type Item = Result<ElfNote, NoteError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || !self.reader.has_next() {
            return None;
        }
        let note = ElfNote::read(&mut self.reader);
        match &note {
            Ok(_) => {
                self.reader.align(4);
            }
            Err(_) => self.failed = true,
        }
        Some(note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(name: &[u8], ty: u32, desc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(name);
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(desc);
        out
    }

    #[test]
    fn reads_consecutive_notes_with_unpadded_descriptions() {
        let mut data = note(b"GNU\0", 3, &[1, 2, 3, 4, 5]);
        data.resize(data.len().next_multiple_of(4), 0);
        data.extend_from_slice(&note(b"Go\0", 4, b"abcd"));
        let notes: Vec<_> = NoteIter::new(&data, Endian::Little).collect();
        assert_eq!(notes.len(), 2);
        let first = notes[0].as_ref().unwrap();
        assert!(first.is_gnu());
        assert_eq!((first.name_len, first.vendor_type), (4, 3));
        assert_eq!(first.description, [1, 2, 3, 4, 5]);
        assert_eq!(first.description_hex(), "0102030405");
        assert_eq!(first.type_name(), "GNU, 3");
        let second = notes[1].as_ref().unwrap();
        assert_eq!((second.name.as_str(), second.name_len), ("Go", 4));
    }

    #[test]
    fn rejects_insane_lengths_and_stops() {
        let mut data = Vec::new();
        for v in [1025u32, 0, 1] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(&note(b"GNU\0", 1, b"x"));
        let notes: Vec<_> = NoteIter::new(&data, Endian::Little).collect();
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].as_ref().unwrap_err().to_string(),
            "Invalid Note lengths: 1025, 0"
        );
        let mut data = Vec::new();
        for v in [4u32, 0x80_0000, 1] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        assert!(matches!(
            ElfNote::read(&mut BinaryReader::from_slice(&data, Endian::Little)),
            Err(NoteError::InvalidLengths { .. })
        ));
        // A description running past the data.
        let data = note(b"GNU\0", 1, b"abcdef");
        let cut = &data[..data.len() - 2];
        assert!(matches!(
            ElfNote::read(&mut BinaryReader::from_slice(cut, Endian::Little)),
            Err(NoteError::Read(_))
        ));
    }
}
