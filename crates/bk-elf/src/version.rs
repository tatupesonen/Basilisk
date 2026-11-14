//! GNU symbol versioning: `.gnu.version` (`SHT_GNU_versym`),
//! `.gnu.version_d` (`SHT_GNU_verdef`) and `.gnu.version_r`
//! (`SHT_GNU_verneed`) — Ghidra's `GnuVerdef`, `GnuVerdaux`, `GnuVerneed`
//! and `GnuVernaux`.
//!
//! Ghidra's parser leaves these alone (`parseGNU_d` and `parseGNU_r` are
//! empty); its loader reads the structures to mark them up. Here they are
//! decoded on demand from a section's bytes. The linked lists are followed
//! through their `next` offsets, bounded by the declared counts and by the
//! size of the section, so a looping or overlong chain ends.

use bk_bin::{BinaryReader, Endian};

/// Size of a `Elf_Verdef` entry.
pub const VERDEF_SIZE: u64 = 20;
/// Size of a `Elf_Verdaux` entry.
pub const VERDAUX_SIZE: u64 = 8;
/// Size of a `Elf_Verneed` entry.
pub const VERNEED_SIZE: u64 = 16;
/// Size of a `Elf_Vernaux` entry.
pub const VERNAUX_SIZE: u64 = 16;

/// `.gnu.version` value: the symbol is local.
pub const VER_NDX_LOCAL: u16 = 0;
/// `.gnu.version` value: the symbol is global and unversioned.
pub const VER_NDX_GLOBAL: u16 = 1;
/// `.gnu.version` bit: the symbol is hidden (not the default version).
pub const VERSYM_HIDDEN: u16 = 0x8000;
/// `vd_flags` bit: the definition is the file's own version.
pub const VER_FLG_BASE: u16 = 1;
/// `vd_flags` / `vna_flags` bit: weak version.
pub const VER_FLG_WEAK: u16 = 2;

/// A version definition (`Elf_Verdef`, Ghidra's `GnuVerdef`) with its
/// auxiliary entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDefinition {
    /// Offset of the entry in the section.
    pub offset: u64,
    /// Structure version (1).
    pub vd_version: u16,
    /// `VER_FLG_…` flags.
    pub vd_flags: u16,
    /// Version index, as used in `.gnu.version`.
    pub vd_ndx: u16,
    /// Number of auxiliary entries.
    pub vd_cnt: u16,
    /// Hash of the version name.
    pub vd_hash: u32,
    /// Offset of the first auxiliary entry, from this entry.
    pub vd_aux: u32,
    /// Offset of the next definition, from this entry; 0 ends the list.
    pub vd_next: u32,
    /// The auxiliary entries that could be read: the version's name first,
    /// then the names of the versions it inherits from.
    pub aux: Vec<VersionDefinitionAux>,
}

/// An auxiliary version definition entry (`Elf_Verdaux`, `GnuVerdaux`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionDefinitionAux {
    /// Offset of the entry in the section.
    pub offset: u64,
    /// Offset of the name in the linked string table.
    pub vda_name: u32,
    /// Offset of the next entry, from this one; 0 ends the list.
    pub vda_next: u32,
}

/// A version requirement (`Elf_Verneed`, Ghidra's `GnuVerneed`) with its
/// auxiliary entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNeed {
    /// Offset of the entry in the section.
    pub offset: u64,
    /// Structure version (1).
    pub vn_version: u16,
    /// Number of auxiliary entries.
    pub vn_cnt: u16,
    /// Offset of the needed file's name in the linked string table.
    pub vn_file: u32,
    /// Offset of the first auxiliary entry, from this entry.
    pub vn_aux: u32,
    /// Offset of the next requirement, from this entry; 0 ends the list.
    pub vn_next: u32,
    /// The auxiliary entries that could be read: one per version needed
    /// from the file.
    pub aux: Vec<VersionNeedAux>,
}

/// An auxiliary version requirement entry (`Elf_Vernaux`, `GnuVernaux`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionNeedAux {
    /// Offset of the entry in the section.
    pub offset: u64,
    /// Hash of the version name.
    pub vna_hash: u32,
    /// `VER_FLG_…` flags.
    pub vna_flags: u16,
    /// Version index, as used in `.gnu.version`.
    pub vna_other: u16,
    /// Offset of the version name in the linked string table.
    pub vna_name: u32,
    /// Offset of the next entry, from this one; 0 ends the list.
    pub vna_next: u32,
}

/// Follows a `next`-linked list in `data`: at most `count` entries, each
/// `size` bytes wholly inside `data`, and never more than fit in `data`.
#[derive(Debug, Clone, Copy)]
struct Chain<'a> {
    reader: BinaryReader<'a>,
    offset: u64,
    left: u64,
    size: u64,
}

impl<'a> Chain<'a> {
    fn new(data: &'a [u8], endian: Endian, start: u64, count: u64, size: u64) -> Self {
        let fit = data.len() as u64 / size;
        Self {
            reader: BinaryReader::from_slice(data, endian),
            offset: start,
            left: count.min(fit),
            size,
        }
    }

    /// The offset of the next entry and a reader at it, if there is one.
    fn next_entry(&mut self) -> Option<(u64, BinaryReader<'a>)> {
        if self.left == 0 || !self.reader.is_valid_range(self.offset, self.size) {
            return None;
        }
        self.left -= 1;
        Some((self.offset, self.reader.at(self.offset)))
    }

    /// Moves to the entry `next` bytes after `from`; a `next` of 0 ends the
    /// list.
    fn advance(&mut self, from: u64, next: u32) {
        match from.checked_add(u64::from(next)) {
            Some(offset) if next != 0 => self.offset = offset,
            _ => self.left = 0,
        }
    }
}

/// Iterator over the version definitions in the bytes of a
/// `.gnu.version_d` section.
#[derive(Debug, Clone)]
pub struct VersionDefinitionIter<'a> {
    data: &'a [u8],
    endian: Endian,
    chain: Chain<'a>,
}

impl<'a> VersionDefinitionIter<'a> {
    /// Iterates the definitions in `data` (the section's bytes), at most
    /// `count` of them (the section's `sh_info` or `DT_VERDEFNUM`).
    pub fn new(data: &'a [u8], endian: Endian, count: u64) -> Self {
        Self {
            data,
            endian,
            chain: Chain::new(data, endian, 0, count, VERDEF_SIZE),
        }
    }
}

impl Iterator for VersionDefinitionIter<'_> {
    type Item = VersionDefinition;

    fn next(&mut self) -> Option<VersionDefinition> {
        let (offset, mut r) = self.chain.next_entry()?;
        let mut def = VersionDefinition {
            offset,
            vd_version: r.read_u16().ok()?,
            vd_flags: r.read_u16().ok()?,
            vd_ndx: r.read_u16().ok()?,
            vd_cnt: r.read_u16().ok()?,
            vd_hash: r.read_u32().ok()?,
            vd_aux: r.read_u32().ok()?,
            vd_next: r.read_u32().ok()?,
            aux: Vec::new(),
        };
        self.chain.advance(offset, def.vd_next);
        if let Some(start) = offset.checked_add(u64::from(def.vd_aux)) {
            let count = def.vd_cnt.into();
            let mut aux = Chain::new(self.data, self.endian, start, count, VERDAUX_SIZE);
            while let Some((at, mut r)) = aux.next_entry() {
                let (Ok(vda_name), Ok(vda_next)) = (r.read_u32(), r.read_u32()) else {
                    break;
                };
                def.aux.push(VersionDefinitionAux {
                    offset: at,
                    vda_name,
                    vda_next,
                });
                aux.advance(at, vda_next);
            }
        }
        Some(def)
    }
}

/// Iterator over the version requirements in the bytes of a
/// `.gnu.version_r` section.
#[derive(Debug, Clone)]
pub struct VersionNeedIter<'a> {
    data: &'a [u8],
    endian: Endian,
    chain: Chain<'a>,
}

impl<'a> VersionNeedIter<'a> {
    /// Iterates the requirements in `data` (the section's bytes), at most
    /// `count` of them (the section's `sh_info` or `DT_VERNEEDNUM`).
    pub fn new(data: &'a [u8], endian: Endian, count: u64) -> Self {
        Self {
            data,
            endian,
            chain: Chain::new(data, endian, 0, count, VERNEED_SIZE),
        }
    }
}

impl Iterator for VersionNeedIter<'_> {
    type Item = VersionNeed;

    fn next(&mut self) -> Option<VersionNeed> {
        let (offset, mut r) = self.chain.next_entry()?;
        let mut need = VersionNeed {
            offset,
            vn_version: r.read_u16().ok()?,
            vn_cnt: r.read_u16().ok()?,
            vn_file: r.read_u32().ok()?,
            vn_aux: r.read_u32().ok()?,
            vn_next: r.read_u32().ok()?,
            aux: Vec::new(),
        };
        self.chain.advance(offset, need.vn_next);
        if let Some(start) = offset.checked_add(u64::from(need.vn_aux)) {
            let count = need.vn_cnt.into();
            let mut aux = Chain::new(self.data, self.endian, start, count, VERNAUX_SIZE);
            while let Some((at, mut r)) = aux.next_entry() {
                let (Ok(vna_hash), Ok(vna_flags), Ok(vna_other), Ok(vna_name), Ok(vna_next)) = (
                    r.read_u32(),
                    r.read_u16(),
                    r.read_u16(),
                    r.read_u32(),
                    r.read_u32(),
                ) else {
                    break;
                };
                need.aux.push(VersionNeedAux {
                    offset: at,
                    vna_hash,
                    vna_flags,
                    vna_other,
                    vna_name,
                    vna_next,
                });
                aux.advance(at, vna_next);
            }
        }
        Some(need)
    }
}

/// The version indexes of `.gnu.version`: one 16-bit value per dynamic
/// symbol, in the bytes of the section.
pub fn symbol_versions(data: &[u8], endian: Endian) -> impl Iterator<Item = u16> + '_ {
    let (pairs, _odd_byte) = data.as_chunks::<2>();
    pairs.iter().map(move |&pair| match endian {
        Endian::Little => u16::from_le_bytes(pair),
        Endian::Big => u16::from_be_bytes(pair),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looping_chains_end() {
        // A chain cannot point backwards; one whose `next` offsets run past
        // the section, or whose count is larger than the section holds, ends
        // at the section's end.
        let mut data = Vec::new();
        for v in [1u16, 1, 1, 5] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0x1234u32, 20, 0xffff_ffec] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let defs: Vec<_> = VersionDefinitionIter::new(&data, Endian::Little, 1000).collect();
        // 28 bytes hold one definition; the aux list is cut by the section.
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].aux.len(), 1);
        assert_eq!(defs[0].aux[0].vda_name, 7);
    }

    #[test]
    fn versym_values() {
        let v: Vec<u16> = symbol_versions(&[0, 0, 1, 0, 2, 0x80, 9], Endian::Little).collect();
        assert_eq!(v, [0, 1, 0x8002]);
    }
}
