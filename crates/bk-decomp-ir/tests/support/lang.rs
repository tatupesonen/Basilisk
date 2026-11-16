//! Register and user-op tables of the languages the checked-in dumps use,
//! generated from the reference build's languages by `tests/lang_tables.rs`
//! (`tests/data/lang/<language id>.txt.gz`), so the S tests print registers
//! without the spec root.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use bk_core::{RegisterLookup, SpaceId, SpaceManager, VarnodeData};

/// Ghidra's `VarnodeData` order: space index, offset, larger sizes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key(u32, u64, u32);

impl Ord for Key {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.0
            .cmp(&o.0)
            .then(self.1.cmp(&o.1))
            .then(o.2.cmp(&self.2))
    }
}
impl PartialOrd for Key {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// A language's registers (`SleighBase::varnode_xref`) with Ghidra's
/// `getRegisterName`.
#[derive(Debug, Default)]
pub(crate) struct RegTable {
    by_loc: BTreeMap<Key, String>,
    by_name: std::collections::HashMap<String, VarnodeData>,
}

impl RegisterLookup for RegTable {
    fn register(&self, name: &str) -> Option<VarnodeData> {
        self.by_name.get(name).copied()
    }
    fn register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        let key = Key(space.index(), offset, size);
        let end = offset.wrapping_add(u64::from(size));
        let mut it = self.by_loc.range(..=key).rev();
        let (first, name) = it.next()?;
        if first.0 != key.0 {
            return None;
        }
        let reaches = |k: &Key| k.1.wrapping_add(u64::from(k.2)) >= end;
        if reaches(first) {
            return Some(name);
        }
        for (k, name) in it {
            if k.0 != key.0 || k.1 != first.1 {
                return None;
            }
            if reaches(k) {
                return Some(name);
            }
        }
        None
    }
    fn exact_register_name(&self, space: SpaceId, offset: u64, size: u32) -> Option<&str> {
        self.by_loc
            .get(&Key(space.index(), offset, size))
            .map(String::as_str)
    }
}

/// A language's tables as read from `tests/data/lang`.
#[derive(Debug, Default)]
pub(crate) struct LangTables {
    /// `(name, space name, offset, size)`.
    pub(crate) registers: Vec<(String, String, u64, u32)>,
    /// User-op names by index.
    pub(crate) userops: Vec<Option<String>>,
}

impl LangTables {
    /// The file for a language id (`x86:LE:64:default`).
    pub(crate) fn path(language: &str) -> PathBuf {
        bk_testkit::workspace_root()
            .join("crates/bk-decomp-ir/tests/data/lang")
            .join(format!("{}.txt.gz", language.replace(':', "_")))
    }

    /// Parses the table text.
    pub(crate) fn parse(text: &str) -> Self {
        let mut t = Self::default();
        for l in text.lines() {
            let f: Vec<&str> = l.split('\t').collect();
            match f.as_slice() {
                ["R", name, space, off, size] => t.registers.push((
                    (*name).to_owned(),
                    (*space).to_owned(),
                    u64::from_str_radix(off.trim_start_matches("0x"), 16).unwrap(),
                    size.parse().unwrap(),
                )),
                ["U", index, name] => {
                    let i: usize = index.parse().unwrap();
                    if t.userops.len() <= i {
                        t.userops.resize(i + 1, None);
                    }
                    t.userops[i] = Some((*name).to_owned());
                }
                _ => panic!("bad table line {l}"),
            }
        }
        t
    }

    /// The table text.
    pub(crate) fn write(&self) -> String {
        let mut s = String::new();
        for (n, sp, off, size) in &self.registers {
            let _ = writeln!(s, "R\t{n}\t{sp}\t{off:#x}\t{size}");
        }
        for (i, n) in self.userops.iter().enumerate() {
            if let Some(n) = n {
                let _ = writeln!(s, "U\t{i}\t{n}");
            }
        }
        s
    }

    /// Reads the table of `language`, if checked in.
    pub(crate) fn load(language: &str) -> Option<Self> {
        let text = bk_testkit::oracle::read_text(&Self::path(language)).ok()?;
        Some(Self::parse(&text))
    }

    /// The registers resolved against a space manager.
    pub(crate) fn reg_table(&self, spaces: &SpaceManager) -> RegTable {
        let mut t = RegTable::default();
        for (n, sp, off, size) in &self.registers {
            let Some(s) = spaces.space_by_name(sp) else {
                continue;
            };
            t.by_loc
                .entry(Key(s.id().index(), *off, *size))
                .or_insert_with(|| n.clone());
            t.by_name
                .insert(n.clone(), VarnodeData::new(s.id(), *off, *size));
        }
        t
    }
}

/// The language id of a dump's architecture id (`x86:LE:64:default:gcc`).
pub(crate) fn language_of(arch: &str) -> String {
    arch.rsplit_once(':').map_or(arch, |(l, _)| l).to_owned()
}
