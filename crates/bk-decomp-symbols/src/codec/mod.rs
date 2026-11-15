//! Encoding and decoding of symbols, scopes and the database (spec 4.11).

mod scope;
mod symbol;

use bk_marshal::{Decoder, Encoder};

use crate::database::Database;
use crate::error::Result;
use crate::ids::{ScopeId, SymbolId};

/// What decoding a `<function>` element yields (Ghidra `Funcdata::decode`
/// as `FunctionSymbol::decode` uses it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFunction {
    /// The function's name.
    pub name: String,
    /// Its display name.
    pub display_name: String,
    /// The symbol id the element carried.
    pub ghidra_id: u64,
    /// The function's size in bytes.
    pub size: i32,
}

/// The `<function>` element inside a `<mapsym>`: D07's (spec 5.3). Without
/// one, function symbols are written as `<functionshell>`.
pub trait FunctionCodec: Send + Sync {
    /// Writes the function of `sym`; `false` to have `<functionshell>`
    /// written instead.
    fn encode(&self, db: &Database, sym: SymbolId, enc: &mut dyn Encoder) -> Result<bool>;
    /// Reads a `<function>` element for a symbol of `scope`.
    fn decode(&self, db: &mut Database, scope: ScopeId, dec: &mut dyn Decoder<'_>) -> Result<DecodedFunction>;
}
