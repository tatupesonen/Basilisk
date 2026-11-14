//! The decompiler's symbol and scope database and the program services
//! around it.
//!
//! Ghidra: `Ghidra/Features/Decompiler/src/decompile/cpp/database.hh`/`.cc`
//! (`SymbolEntry`, `Symbol` and its subclasses, `Scope`, `ScopeInternal`,
//! `Database`), `rangemap.hh`, `partmap.hh` (through `bk-context`),
//! `comment.*`, `stringmanage.*`, `cpool.*`, `loadimage*.*`, the named
//! variables and XML of `globalcontext.*`, `override.*`, and the host
//! classes `*_ghidra.*`. Specification: `docs/features/decomp-symbols.md`.

pub mod entrymap;
