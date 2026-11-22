//! The host trait: everything the decompiler asks the program database
//! (spec 4.19, 5.4), and the cache layer it is used through.
//!
//! Ghidra answers every service twice: from in-memory tables (the standalone
//! console and the data tests — here the [`Database`](crate::Database) and
//! the internal services themselves) and from the Java program through the
//! `*_ghidra` classes, which cache what they receive. [`ProgramHost`] carries
//! the same questions as typed values, plus ADR-025 3d (function summaries,
//! "does this call return") and 3f (provenance on every name and type).
//! [`cache`] is the layer a host is used through; [`test::ScriptedHost`]
//! answers from tables and records every call.

pub mod cache;
mod services;
pub mod test;

use bk_core::{Address, Provenance, Range, RangeList};
use bk_cspec::FunctionSummary;
use bk_decomp_types::TypeId;
use bk_decomp_types::xml::TypeSource;

use crate::comment::Comment;
use crate::cpool::CPoolRecord;
use crate::error::{DataUnavail, HostError};
use crate::flags::VarnodeFlags;

/// The kind of a symbol a host reports.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostSymbolKind {
    /// A data symbol of a type.
    Data {
        /// Its type.
        ty: TypeId,
    },
    /// A function.
    Function,
    /// A code label.
    Label,
    /// An external reference to the function at `ref_addr`.
    ExternRef {
        /// The placeholder address of the function.
        ref_addr: Address,
    },
}

/// One storage location of a reported symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntry {
    /// The address (invalid for an unassigned symbol).
    pub addr: Address,
    /// The code addresses where it holds (empty: everywhere).
    pub use_limit: RangeList,
}

/// A symbol as a host reports it (the content of Ghidra's `<mapsym>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolRecord {
    /// The kind and its data.
    pub kind: HostSymbolKind,
    /// The name.
    pub name: String,
    /// The program's id of the symbol (0: none).
    pub id: u64,
    /// `namelock`, `typelock`, `readonly`, `volatil` as reported.
    pub flags: VarnodeFlags,
    /// The storage.
    pub entries: Vec<HostEntry>,
}

/// A reported symbol with its scope and provenance (ADR-025 3f).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSymbol {
    /// The Ghidra id of the symbol's scope (0: the global scope).
    pub scope: u64,
    /// The symbol.
    pub record: SymbolRecord,
    /// Who named it.
    pub name_provenance: Provenance,
    /// Who typed it.
    pub type_provenance: Provenance,
}

/// The answer to an address query (Ghidra `getMappedSymbolsXML`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostReply {
    /// No symbol, but a range with these properties (a `<hole>`).
    Hole {
        /// The range.
        range: Range,
        /// Whether it is read-only.
        readonly: bool,
        /// Whether it is volatile.
        volatile: bool,
    },
    /// A symbol.
    Symbol(HostSymbol),
    /// Nothing at all.
    Nothing,
}

/// One namespace of a path (Ghidra's `<val id label>name</val>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNamespace {
    /// The namespace's id.
    pub id: u64,
    /// Its name.
    pub name: String,
    /// Its display name, if different.
    pub label: Option<String>,
}

/// A string the host read (Ghidra `getStringData`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostString {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Whether they were cut at the limit.
    pub truncated: bool,
}

/// What the decompiler asks the program (spec 5.4). Object-safe; every
/// answer is owned; errors are typed values.
pub trait ProgramHost: Send + Sync {
    /// Ghidra `getMappedSymbolsXML`: the symbol or hole at `addr`.
    fn mapped_symbol(&self, addr: Address) -> Result<HostReply, HostError>;
    /// Ghidra `getExternalRef`: the function an external reference at
    /// `addr` refers to.
    fn external_ref(&self, addr: Address) -> Result<Option<HostSymbol>, HostError>;
    /// Ghidra `getNamespacePath`: the namespaces from the global scope down
    /// to the one of id `scope` (the root excluded).
    fn namespace_path(&self, scope: u64) -> Result<Vec<HostNamespace>, HostError>;
    /// Ghidra `isNameUsed`.
    fn is_name_used(&self, name: &str, start: u64, stop: u64) -> Result<bool, HostError>;
    /// Ghidra `getCodeLabel`.
    fn code_label(&self, addr: Address) -> Result<Option<(String, Provenance)>, HostError>;
    /// Ghidra `getComments`: the comments of a function of the types in
    /// `mask`.
    fn comments(&self, function: Address, mask: u32) -> Result<Vec<Comment>, HostError>;
    /// Ghidra `getBytes`.
    fn bytes(&self, addr: Address, buf: &mut [u8]) -> Result<(), DataUnavail>;
    /// Ghidra `getStringData`: up to `max_bytes` of the string at `addr` of
    /// character type `char_type` (`None`: not a string).
    fn string_data(
        &self,
        addr: Address,
        char_type: TypeId,
        max_bytes: usize,
    ) -> Result<Option<HostString>, HostError>;
    /// Ghidra `getCPoolRef`.
    fn cpool_record(&self, refs: &[u64]) -> Result<Option<CPoolRecord>, HostError>;
    /// Ghidra `getTrackedRegisters`: the tracked set at `addr`.
    fn tracked_registers(&self, addr: Address) -> Result<Vec<bk_context::TrackedValue>, HostError>;
    /// Ghidra `getDataType` (`TypeFactoryGhidra::findById`): the XML
    /// definition of a type and who supplied it.
    fn data_type(&self, name: &str, id: u64, size: i32) -> Option<(String, Provenance)> {
        let _ = (name, id, size);
        None
    }
    /// ADR-025 3d: what the program knows of a callee (`None`: no opinion).
    fn function_summary(&self, callee: Address) -> Option<FunctionSummary> {
        let _ = callee;
        None
    }
    /// ADR-025 3d: whether the call at `call_site` returns (`None`: no
    /// opinion; the engine uses the callee's prototype and flow overrides).
    fn call_returns(&self, call_site: Address, callee: Option<Address>) -> Option<bool> {
        let _ = (call_site, callee);
        None
    }
}

/// A host's types as `bk-decomp-types`' [`TypeSource`].
pub struct HostTypes(pub std::sync::Arc<dyn ProgramHost>);

impl std::fmt::Debug for HostTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostTypes")
    }
}

impl TypeSource for HostTypes {
    fn definition(&self, name: &str, id: u64, size: i32) -> Option<(String, Provenance)> {
        self.0.data_type(name, id, size)
    }
}

/// Ghidra `ArchitectureGhidra::isDynamicSymbolName`: `FUN_`/`DAT_` names
/// ending in four hex digits, assumed unused.
pub fn is_dynamic_symbol_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 8 || b.get(3) != Some(&b'_') {
        return false;
    }
    if !(b.starts_with(b"FUN") || b.starts_with(b"DAT")) {
        return false;
    }
    b.get(b.len() - 4..).is_some_and(|tail| {
        tail.iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    })
}
