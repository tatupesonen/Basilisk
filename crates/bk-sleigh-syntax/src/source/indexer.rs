//! Source-file indices as Ghidra's `SourceFileIndexer` assigns them.

use rustc_hash::FxBuildHasher;
use string_interner::backend::StringBackend;
use string_interner::symbol::SymbolU32;
use string_interner::{StringInterner, Symbol as _};

/// Assigns a stable index to each source file name, in order of first use.
///
/// The counterpart of Ghidra's `SourceFileIndexer`: the SLEIGH compiler
/// records, for every constructor, the index of the file that defines it,
/// and writes the table of names once.
#[derive(Clone, Debug)]
pub struct SourceFileIndexer {
    names: StringInterner<StringBackend<SymbolU32>, FxBuildHasher>,
}

impl Default for SourceFileIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceFileIndexer {
    /// An empty index.
    pub fn new() -> Self {
        Self {
            names: StringInterner::with_hasher(FxBuildHasher),
        }
    }

    /// The index of `filename`, adding it if it is new.
    pub fn index(&mut self, filename: &str) -> u32 {
        self.names.get_or_intern(filename).to_usize() as u32
    }

    /// The index of `filename`, if it has one.
    pub fn get_index(&self, filename: &str) -> Option<u32> {
        self.names.get(filename).map(|s| s.to_usize() as u32)
    }

    /// The file name with the given index.
    pub fn file_name(&self, index: u32) -> Option<&str> {
        self.names
            .resolve(SymbolU32::try_from_usize(index as usize)?)
    }

    /// Number of indexed files.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether no file has been indexed.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// File names in index order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|(_, name)| name)
    }
}
