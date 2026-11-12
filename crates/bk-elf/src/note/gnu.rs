//! GNU notes: `.note.ABI-tag`, `.note.gnu.build-id`, `.note.gnu.property`.

use bk_bin::Endian;

use crate::note::{ElfNote, NoteError, hex};

/// `.note.ABI-tag` (Ghidra's `NoteAbiTag`): the OS and the oldest kernel
/// the file runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteAbiTag {
    /// The note it was read from.
    pub note: ElfNote,
    /// 0 for Linux.
    pub abi_type: u32,
    /// Major, minor and patch level of the required kernel.
    pub required_kernel_version: [u32; 3],
}

impl NoteAbiTag {
    /// The section this note lives in.
    pub const SECTION_NAME: &'static str = ".note.ABI-tag";

    /// Interprets `note` (Ghidra's `NoteAbiTag.read`): it must be a GNU note
    /// with at least 16 bytes of description.
    pub fn from_note(note: ElfNote, endian: Endian) -> Result<Self, NoteError> {
        if !note.is_gnu() || note.description.len() < 16 {
            return Err(NoteError::InvalidContent {
                section: Self::SECTION_NAME,
                name: note.name,
                desc_len: note.description.len(),
            });
        }
        let r = note.description_reader(endian);
        let abi_type = r.read_u32_at(0)?;
        let required_kernel_version = [r.read_u32_at(4)?, r.read_u32_at(8)?, r.read_u32_at(12)?];
        Ok(Self {
            note,
            abi_type,
            required_kernel_version,
        })
    }

    /// `Linux`, or `Unknown(<n>)`.
    pub fn abi_type_string(&self) -> String {
        match self.abi_type {
            0 => "Linux".to_owned(),
            other => format!("Unknown({})", other as i32),
        }
    }

    /// Ghidra's `getRequiredKernelVersion`, e.g. `Linux 3.2.0`.
    pub fn required_kernel_version_string(&self) -> String {
        let [a, b, c] = self.required_kernel_version.map(|v| v as i32);
        format!("{} {a}.{b}.{c}", self.abi_type_string())
    }
}

/// `.note.gnu.build-id` (Ghidra's `NoteGnuBuildId`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteGnuBuildId {
    /// The note it was read from; its description is the build id.
    pub note: ElfNote,
}

impl NoteGnuBuildId {
    /// The section this note lives in.
    pub const SECTION_NAME: &'static str = ".note.gnu.build-id";

    /// Interprets `note`: it must be a GNU note with a non-empty description.
    pub fn from_note(note: ElfNote) -> Result<Self, NoteError> {
        if !note.is_gnu() || note.description.is_empty() {
            return Err(NoteError::InvalidContent {
                section: Self::SECTION_NAME,
                name: note.name,
                desc_len: note.description.len(),
            });
        }
        Ok(Self { note })
    }

    /// The build id bytes.
    pub fn id(&self) -> &[u8] {
        &self.note.description
    }

    /// The build id as lowercase hex.
    pub fn id_hex(&self) -> String {
        self.note.description_hex()
    }
}

/// One property of a `.note.gnu.property` note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyElement {
    /// `pr_type`.
    pub pr_type: u32,
    /// Ghidra's name for the type: `stack_size`, `no_copy_on_protected`,
    /// `processor opt 0x…`, `app opt 0x…` or `unknown opt 0x…`.
    pub type_name: String,
    /// The value as Ghidra shows it.
    pub value: String,
    /// `pr_datasz`.
    pub length: u32,
}

/// `.note.gnu.property` (Ghidra's `NoteGnuProperty`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteGnuProperty {
    /// The note it was read from.
    pub note: ElfNote,
    /// The properties, in order.
    pub elements: Vec<PropertyElement>,
}

const GNU_PROPERTY_STACK_SIZE: u32 = 1;
const GNU_PROPERTY_NO_COPY_ON_PROTECTED: u32 = 2;

impl NoteGnuProperty {
    /// The section this note lives in.
    pub const SECTION_NAME: &'static str = ".note.gnu.property";

    /// Decodes the properties of `note`; `pointer_size` is 4 or 8 (the
    /// alignment of each property and the size of `stack_size`).
    pub fn from_note(note: ElfNote, endian: Endian, pointer_size: u64) -> Result<Self, NoteError> {
        let mut elements = Vec::new();
        let mut r = note.description_reader(endian);
        while r.has_next() {
            let pr_type = r.read_u32()?;
            let length = r.read_u32_count()? as u32;
            let start = r.position();
            let (type_name, value) = match pr_type {
                GNU_PROPERTY_STACK_SIZE => {
                    let size = r.read_uint(pointer_size as usize)?;
                    ("stack_size".to_owned(), format!("{size} (0x{size:08x})"))
                }
                GNU_PROPERTY_NO_COPY_ON_PROTECTED => {
                    ("no_copy_on_protected".to_owned(), "set".to_owned())
                }
                other => {
                    let name = match other {
                        0xc000_0000..=0xdfff_ffff => format!("processor opt 0x{other:08x}"),
                        0xe000_0000..=0xffff_ffff => format!("app opt 0x{other:08x}"),
                        _ => format!("unknown opt 0x{other:08x}"),
                    };
                    let value = if length > 0 {
                        hex(&r.read_bytes(length as usize)?, " ")
                    } else {
                        "???".to_owned()
                    };
                    (name, value)
                }
            };
            r.set_position(start.saturating_add(u64::from(length)));
            r.align(pointer_size);
            elements.push(PropertyElement {
                pr_type,
                type_name,
                value,
                length,
            });
        }
        Ok(Self { note, elements })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gnu(desc: Vec<u8>) -> ElfNote {
        ElfNote {
            name_len: 4,
            name: "GNU".into(),
            vendor_type: 1,
            description: desc,
        }
    }

    #[test]
    fn abi_tag() {
        let desc: Vec<u8> = [0u32, 3, 2, 0]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();
        let tag = NoteAbiTag::from_note(gnu(desc), Endian::Big).unwrap();
        assert_eq!(tag.required_kernel_version_string(), "Linux 3.2.0");
        let error = NoteAbiTag::from_note(gnu(vec![0; 8]), Endian::Big).unwrap_err();
        assert_eq!(error.to_string(), "Invalid .note.ABI-tag values: GNU, 8");
    }

    #[test]
    fn build_id() {
        let id = NoteGnuBuildId::from_note(gnu(vec![0xde, 0xad, 0x0b])).unwrap();
        assert_eq!(id.id_hex(), "dead0b");
        assert!(NoteGnuBuildId::from_note(gnu(vec![])).is_err());
    }

    #[test]
    fn properties() {
        let mut desc = Vec::new();
        for v in [1u32, 8] {
            desc.extend_from_slice(&v.to_le_bytes());
        }
        desc.extend_from_slice(&0x10_0000u64.to_le_bytes());
        for v in [0xc000_0002u32, 4, 3, 0] {
            desc.extend_from_slice(&v.to_le_bytes());
        }
        for v in [2u32, 0] {
            desc.extend_from_slice(&v.to_le_bytes());
        }
        let p = NoteGnuProperty::from_note(gnu(desc), Endian::Little, 8).unwrap();
        let shown: Vec<_> = p
            .elements
            .iter()
            .map(|e| (e.type_name.as_str(), e.value.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                ("stack_size", "1048576 (0x00100000)"),
                ("processor opt 0xc0000002", "03 00 00 00"),
                ("no_copy_on_protected", "set"),
            ]
        );
    }
}
