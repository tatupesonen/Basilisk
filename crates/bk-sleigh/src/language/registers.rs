//! The register table of a language (Ghidra `SleighBase::varnode_xref` and
//! its queries `getRegister`, `getRegisterName`, `getExactRegisterName`,
//! `getAllRegisters`).

use std::collections::{BTreeMap, HashMap};

use bk_core::{RegisterLookup, SpaceId, VarnodeData};

/// A register's location, ordered as Ghidra orders `VarnodeData`: by space
/// index, then offset, then **larger sizes first**.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    space: u32,
    offset: u64,
    size: u32,
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .cmp(&other.space)
            .then(self.offset.cmp(&other.offset))
            .then(other.size.cmp(&self.size))
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Every register symbol of a language: lookup by name, by exact location,
/// and "the register containing these bytes".
#[derive(Clone, Debug, Default)]
pub struct RegisterTable {
    by_location: BTreeMap<Key, Box<str>>,
    by_name: HashMap<Box<str>, VarnodeData>,
}

/// Two registers at the same location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Duplicate {
    pub(crate) first: String,
    pub(crate) second: String,
}

impl RegisterTable {
    /// Adds a register; registering a second name at the same location is an
    /// error naming both (the table keeps the first).
    pub(crate) fn insert(
        &mut self,
        name: &str,
        space: SpaceId,
        offset: u64,
        size: u32,
    ) -> Result<(), Duplicate> {
        let key = Key {
            space: space.index(),
            offset,
            size,
        };
        if let Some(existing) = self.by_location.get(&key) {
            return Err(Duplicate {
                first: existing.to_string(),
                second: name.to_owned(),
            });
        }
        self.by_location.insert(key, name.into());
        self.by_name
            .insert(name.into(), VarnodeData::new(space, offset, size));
        Ok(())
    }

    /// The number of registers.
    pub fn len(&self) -> usize {
        self.by_location.len()
    }

    /// Whether there are no registers.
    pub fn is_empty(&self) -> bool {
        self.by_location.is_empty()
    }

    /// Every register with its location, ordered as Ghidra orders them
    /// (Ghidra `getAllRegisters`).
    pub fn all(&self) -> impl Iterator<Item = (VarnodeData, &str)> {
        self.by_location.iter().map(|(key, name)| {
            (
                VarnodeData::new(SpaceId::new(key.space), key.offset, key.size),
                &**name,
            )
        })
    }
}

impl RegisterLookup for RegisterTable {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.by_name.get(name).copied()
    }

    /// Ghidra `getRegisterName`: the last entry not after (space, offset,
    /// size); if it does not reach the end of the bytes, the entries before
    /// it **with the same offset**. A containing register that starts at a
    /// lower offset than that first candidate is not found.
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let key = Key {
            space: space.index(),
            offset,
            size,
        };
        let end = offset.wrapping_add(u64::from(size));
        let mut entries = self.by_location.range(..=key).rev();
        let (first, name) = entries.next()?;
        if first.space != key.space {
            return None;
        }
        let reaches = |entry: &Key| entry.offset.wrapping_add(u64::from(entry.size)) >= end;
        if reaches(first) {
            return Some(name);
        }
        for (entry, name) in entries {
            if entry.space != key.space || entry.offset != first.offset {
                return None;
            }
            if reaches(entry) {
                return Some(name);
            }
        }
        None
    }

    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.by_location
            .get(&Key {
                space: space.index(),
                offset,
                size,
            })
            .map(|name| &**name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RegisterTable {
        let reg = SpaceId::new(4);
        let mut t = RegisterTable::default();
        t.insert("RAX", reg, 0, 8).unwrap();
        t.insert("EAX", reg, 0, 4).unwrap();
        t.insert("AX", reg, 0, 2).unwrap();
        t.insert("AL", reg, 0, 1).unwrap();
        t.insert("AH", reg, 1, 1).unwrap();
        t.insert("RCX", reg, 8, 8).unwrap();
        t
    }

    #[test]
    fn containing_register_follows_ghidra_quirk() {
        let t = table();
        let reg = SpaceId::new(4);
        assert_eq!(t.register_name(reg, 0, 1), Some("AL"));
        assert_eq!(t.register_name(reg, 0, 3), Some("EAX"));
        assert_eq!(t.register_name(reg, 0, 8), Some("RAX"));
        assert_eq!(t.register_name(reg, 1, 1), Some("AH"));
        // For bytes 1..3 the candidate is AL (offset 0), and the walk back
        // over offset 0 finds EAX.
        assert_eq!(t.register_name(reg, 1, 2), Some("EAX"));
        // For byte 2 the candidate is AH (offset 1); RAX contains it but
        // starts at a lower offset than AH, so Ghidra does not find it.
        assert_eq!(t.register_name(reg, 2, 1), None);
        assert_eq!(t.register_name(reg, 9, 2), Some("RCX"));
        assert_eq!(t.register_name(SpaceId::new(3), 0, 1), None);
        assert_eq!(t.register_name(SpaceId::new(5), 0, 1), None);
        assert_eq!(t.exact_register_name(reg, 0, 2), Some("AX"));
        assert_eq!(t.exact_register_name(reg, 0, 3), None);
        assert_eq!(t.register("AH"), Some(VarnodeData::new(reg, 1, 1)));
        assert_eq!(t.register("BH"), None);
        let names: Vec<&str> = t.all().map(|(_, name)| name).collect();
        assert_eq!(names, ["RAX", "EAX", "AX", "AL", "AH", "RCX"]);
    }

    #[test]
    fn duplicates_name_both() {
        let mut t = table();
        let err = t.insert("ALIAS", SpaceId::new(4), 0, 4).unwrap_err();
        assert_eq!(err.first, "EAX");
        assert_eq!(err.second, "ALIAS");
        assert_eq!(t.len(), 6);
        assert!(!t.is_empty());
    }
}
