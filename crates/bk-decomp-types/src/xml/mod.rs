//! The XML (and packed) form of types and of the factory, and the hooks
//! through which other crates supply what this one does not own.

mod decode;
mod encode;
pub mod ids;
mod proto;

pub use decode::MAX_DECODE_DEPTH;
pub use proto::{PrototypeCodec, SignatureCodec};

use std::sync::Arc;

use bk_core::Provenance;
use bk_marshal::SpaceId;

/// Supplies type definitions on demand: the hook behind Ghidra's virtual
/// `TypeFactory::findById` (`TypeFactoryGhidra` asks the host).
pub trait TypeSource: Send + Sync {
    /// The XML definition (`<type>` or `<def>` element) of the type with
    /// this name, id and size, and who supplied it; `None` if unknown.
    fn definition(&self, name: &str, id: u64, size: i32) -> Option<(String, Provenance)>;
}

/// The scope look-ups behind `TypeSpacebase` (implemented with the symbol
/// tables, D06).
pub trait SpacebaseScopes: Send + Sync {
    /// The function address whose local scope has this id; `None` for the
    /// global scope.
    fn frame_of_scope(&self, scope: u64) -> Option<(SpaceId, u64)>;
    /// The id of the local scope of the function at `frame`, or of the
    /// global scope when `frame` is `None` or no function is there.
    fn scope_of_frame(&self, frame: Option<(SpaceId, u64)>) -> u64;
}

/// The hooks a factory can be given.
#[derive(Clone, Default)]
pub struct Hooks {
    /// Types supplied on demand.
    pub source: Option<Arc<dyn TypeSource>>,
    /// Scope look-ups for spacebase types.
    pub scopes: Option<Arc<dyn SpacebaseScopes>>,
    /// The storage part of function prototypes.
    pub prototypes: Option<Arc<dyn PrototypeCodec>>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field("source", &self.source.is_some())
            .field("scopes", &self.scopes.is_some())
            .field("prototypes", &self.prototypes.is_some())
            .finish()
    }
}
