//! The decompiler's symbol and scope database and the program services
//! around it.
//!
//! Ghidra: `Ghidra/Features/Decompiler/src/decompile/cpp/database.hh`/`.cc`
//! (`SymbolEntry`, `Symbol` and its subclasses, `Scope`, `ScopeInternal`,
//! `Database`), `rangemap.hh`, `partmap.hh` (through `bk-context`),
//! `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*.*`, the named
//! variables and XML of `globalcontext.*`, `override.*`, and the host
//! classes `*_ghidra.*`. Specification: `docs/features/decomp-symbols.md`.

pub mod arch;
pub mod codec;
pub mod comment;
pub mod context;
pub mod cpool;
pub mod database;
pub mod entrymap;
pub mod error;
pub mod flags;
pub mod host;
pub mod ids;
pub mod image;
pub mod model;
pub mod overlay;
pub mod overrides;
pub mod print;
pub mod scope;
pub mod strings;

pub use context::ContextNames;
pub use database::{ArchEnv, Database, RegisterNames};
pub use error::{DataUnavail, HostError, Result, SymbolError};
pub use flags::VarnodeFlags;
pub use ids::{EntryId, ScopeId, SymbolId};
pub use model::{EntryData, EntryKind, ScopeData, ScopeKind, SymbolData, SymbolKind};
pub use scope::add::{ConflictFacts, ID_BASE};
pub use scope::names::VarnodeFacts;
pub use scope::query::Found;
