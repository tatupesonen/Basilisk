//! The version-2 records of `@scope` (`bkstate 2`): what rebuilding the
//! function's `ScopeInternal` exactly needs beyond its symbols and entries —
//! the scope's ids and children, the category slots, the multi-entry set,
//! each space's entry map (record list with subsorts, fragment multiset),
//! whose orders follow insertion history (`rangemap.hh`), and the order of
//! the dynamic entry list.

use super::codec::{Codec, Dec, Hex, List, Opt, Text, record};
use super::ids::{EntryRef, SymbolRef};

/// A category slot: a symbol, or `null` for a slot left empty.
pub(crate) struct Slot;

impl Codec for Slot {
    type Value = Option<SymbolRef>;
    fn parse(text: &str) -> Option<Self::Value> {
        if text == "null" {
            Some(None)
        } else {
            SymbolRef::parse(text).map(Some)
        }
    }
    fn write(value: &Self::Value, out: &mut String) {
        match value {
            Some(s) => SymbolRef::write(s, out),
            None => out.push_str("null"),
        }
    }
}

record! {
    /// `I`: the scope's identity.
    ScopeIdRecord = "I" {
        /// `Scope::uniqueId`, the scope's Ghidra id.
        ghidra_id: u64 = Hex<u64>,
        /// `ScopeInternal::nextUniqueId`: the counter the next symbol id is made from.
        next_unique_id: u64 = Hex<u64>,
        /// `Scope::displayName`.
        display_name: String = Text,
        /// The parent scope's Ghidra id.
        parent: Option<u64> = Opt<Hex<u64>>,
        /// The child scopes' Ghidra ids, in id order (`ScopeMap`).
        children: Vec<u64> = List<Hex<u64>>,
    }
}

record! {
    /// `C`: one category's symbol slots, in `catindex` order.
    CategoryRecord = "C" {
        /// The category (0 `function_parameter`, 1 `equate`, …).
        category: i32 = Dec<i32>,
        /// The slots; `None` for an empty slot (Ghidra leaves them, GHIDRA-BUGS 35).
        slots: Vec<Option<SymbolRef>> = List<Slot>,
    }
}

record! {
    /// `E`: `multiEntrySet`, in its order (name, then dedup).
    MultiEntryRecord = "E" {
        /// The symbols.
        symbols: Vec<SymbolRef> = List<SymbolRef>,
    }
}

record! {
    /// `R`: one record of a space's entry map, in record-list order.
    EntryMapRecord = "R" {
        /// The address space.
        space: String = Text,
        /// The entry.
        entry: EntryRef = EntryRef,
        /// The record's first offset.
        first: u64 = Hex<u64>,
        /// The record's last offset.
        last: u64 = Hex<u64>,
        /// The subsort's use index, as computed at insertion (absent if the
        /// record had no fragment, which Ghidra never leaves).
        use_index: Option<i32> = Opt<Dec<i32>>,
        /// The subsort's use offset.
        use_offset: Option<u64> = Opt<Hex<u64>>,
    }
}

record! {
    /// `F`: one fragment of a space's entry map, in multiset order.
    FragmentRecord = "F" {
        /// The address space.
        space: String = Text,
        /// The fragment's first offset.
        first: u64 = Hex<u64>,
        /// The fragment's last offset.
        last: u64 = Hex<u64>,
        /// The entry of the record it belongs to.
        entry: EntryRef = EntryRef,
    }
}

record! {
    /// `Q`: the dynamic entry list, in list order.
    DynamicListRecord = "Q" {
        /// The entries.
        entries: Vec<EntryRef> = List<EntryRef>,
    }
}

/// The version-2 part of `@scope`, present when the dump has a local scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeOrders {
    /// `I`.
    pub identity: ScopeIdRecord,
    /// `C`, one per category slot vector, in category order.
    pub categories: Vec<CategoryRecord>,
    /// `E`.
    pub multi_entry: MultiEntryRecord,
    /// `R`, grouped by space in space-index order.
    pub records: Vec<EntryMapRecord>,
    /// `F`, grouped by space in space-index order.
    pub fragments: Vec<FragmentRecord>,
    /// `Q`.
    pub dynamic: DynamicListRecord,
}

impl ScopeOrders {
    /// The number of records.
    pub(crate) fn len(&self) -> usize {
        3 + self.categories.len() + self.records.len() + self.fragments.len()
    }

    /// Append the records.
    pub(crate) fn write(&self, out: &mut String) {
        self.identity.write(out);
        for r in &self.categories {
            r.write(out);
        }
        self.multi_entry.write(out);
        for r in &self.records {
            r.write(out);
        }
        for r in &self.fragments {
            r.write(out);
        }
        self.dynamic.write(out);
    }
}
