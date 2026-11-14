//! The decompiler's type system: metatypes, every kind of data-type, the
//! factory that interns them, the two orderings type propagation rests on,
//! their XML form, and the C declaration parser.
//!
//! Ghidra: `Ghidra/Features/Decompiler/src/decompile/cpp/type.hh`/`type.cc`
//! (`Datatype` and its subclasses, `TypeFactory`), `metatype.hh`/`.cc`, and
//! the C parser of `grammar.y`. This is the decompiler's type model, not the
//! program database's.
//!
//! Types live in a [`TypeFactory`] arena and are named by [`TypeId`]. A
//! factory can be forked per function ([`TypeFactory::fork`]): the child
//! reads through to its frozen parent and holds the types created during
//! that function's decompilation, the category of *inferred* types
//! (ADR-025 3e). Every entry carries a [`Provenance`](bk_core::Provenance)
//! (ADR-025 3f) that takes no part in identity or ordering.

pub mod compare;
pub mod entry;
pub mod error;
pub mod factory;
pub mod ids;
pub mod meta;
pub mod org;
pub mod query;
pub mod xml;

pub use entry::{
    BitField, CodeSignature, EnumValues, Field, PointerData, TypeEntry, TypeFlags, TypeKind,
    hash_name, hash_size,
};
pub use error::{Result, TypeError};
pub use factory::TypeFactory;
pub use factory::composite::Layout;
pub use factory::enumeration::{Enumerator, Representation, assign_values};
pub use factory::typedef::PrototypePieces;
pub use ids::TypeId;
pub use meta::{Metatype, SubMetatype, TypeClass};
pub use org::{DataOrganization, SpaceInfo, TypeEnv};
pub use query::{BitFieldTriple, Nearest};

/// The deepest chain of components the recursive queries follow; a guard
/// against cyclic or hostile type graphs (ADR-009).
pub const MAX_DEPTH: usize = 256;
