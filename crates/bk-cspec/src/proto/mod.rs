//! Function prototypes: the raw pieces, assigned parameters, the internal
//! store and `FuncProto` with its XML (Ghidra `PrototypePieces`,
//! `ParameterPieces`, `ProtoParameter`, `ParameterBasic`,
//! `ProtoStoreInternal`, `FuncProto`).

mod codec;
mod funcproto;
mod pieces;
mod queries;
mod store;

pub use codec::EncodeMode;
pub use funcproto::{FuncProto, ModelRef, ProtoFlags};
pub use pieces::{ParameterPieces, PieceFlags, PrototypePieces};
pub use queries::Ctx;
pub use store::{ParameterBasic, ProtoStoreInternal};
