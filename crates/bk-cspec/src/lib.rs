//! Compiler specifications and prototype models: reading a `.cspec` into a
//! [`CompilerSpec`](spec::CompilerSpec), assigning storage to a signature's
//! parameters, deciding which observed storage locations are parameters,
//! and the function prototype (`FuncProto`) with its XML.
//!
//! Ghidra: `Ghidra/Features/Decompiler/src/decompile/cpp/fspec.hh`/`.cc`
//! (minus `FuncCallSpecs` and the symbol-backed stores), `modelrules.hh`/
//! `.cc`, and the `.cspec` decoding of `architecture.cc`
//! (`parseCompilerConfig` and the `decode*` functions it calls). Injection
//! payloads and user-op fix-ups are kept as declarations
//! (`pcodeinject.cc`, `userop.cc`).
//!
//! The crate sees data types only through the [`ParamTypes`](types::ParamTypes)
//! trait (ADR-026), so the decompiler's type system and the program
//! database's can both drive it.

pub mod effect;
pub mod entry;
pub mod error;
pub mod ids;
pub mod types;

pub use effect::{EffectKind, EffectRecord};
pub use entry::{Containment, EntryFlags, Extension, ParamEntry};
pub use error::{CspecError, Result};
pub use types::{Metatype, ParamTypes, TypeClass, TypeField, TypeHandle, TypeQueryError};
