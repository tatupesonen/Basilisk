//! Compiler specifications and prototype models: reading a `.cspec` into a
//! [`CompilerSpec`], assigning storage to a signature's
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
//! The crate sees data types only through the [`ParamTypes`]
//! trait (ADR-026), so the decompiler's type system and the program
//! database's can both drive it.

pub mod effect;
pub mod entry;
pub mod error;
pub mod ids;
pub mod inject;
pub mod list;
pub mod model;
pub mod proto;
mod provenance_serde;
pub mod rules;
pub mod spec;
pub mod status;
pub mod summary;
pub mod trial;
pub mod types;

pub use effect::{EffectKind, EffectRecord};
pub use entry::{Containment, EntryFlags, Extension, ParamEntry};
pub use error::{CspecError, Result};
pub use inject::{InjectKind, InjectLibrary, InjectPayload};
pub use list::{AssignResult, ListKind, ParamList};
pub use model::{EXTRAPOP_UNKNOWN, ModelId, ProtoModel, ScoreProtoModel};
pub use proto::{EncodeMode, FuncProto, ModelRef, ParameterPieces, PieceFlags, PrototypePieces};
pub use spec::{CompilerSpec, ReadOptions};
pub use summary::{CallSite, FunctionSummary};
pub use trial::{ParamActive, ParamTrial};
pub use types::{Metatype, ParamTypes, TypeClass, TypeField, TypeHandle, TypeQueryError};
