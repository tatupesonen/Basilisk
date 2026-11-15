//! State dumps (format `bkstate 1`, `docs/features/decomp-oracle.md` 4.4):
//! what `bk dump state` writes — the complete state of one function at one
//! point of Ghidra's pipeline, every object named by a reproducible key.
//!
//! A dump is a header, eighteen sections in a fixed order (each `@<name>`
//! followed by its record count) and an `END` record carrying the number of
//! lines before it. [`StateDump::parse`] checks all of that and every field;
//! [`StateDump::write`] gives back any accepted text byte for byte.

mod codec;
pub mod ids;
mod program;
pub mod records;
pub mod scope;
mod sections;
mod write;

pub use ids::{
    BlockRef, CallRef, EntryRef, EntryStorage, HighRef, IndexPair, JumpRef, OracleRange, SeqNum,
    SymbolRef, TypeRef, VarnodeId, VarnodeOffset,
};
pub use records::*;
pub use scope::{
    CategoryRecord, DynamicListRecord, EntryMapRecord, FragmentRecord, MultiEntryRecord,
    ScopeIdRecord, ScopeOrders,
};
pub use sections::{
    ActionLineRecord, ActiveGroup, BlockEntry, CallSpecEntry, FunctionSection, HeritageSection,
    JumpTableEntry, ProtoGroup, ScopeSection, StateDump, SymbolEntryGroup,
};

#[cfg(test)]
mod tests;
