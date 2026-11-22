//! The decompiler's intermediate representation: a function's p-code ops
//! and the varnodes they read and write, in SSA form or on the way to it,
//! arranged in basic blocks over a `bk-decomp-cfg` graph; the two varnode
//! orders and the op bank's trees and lists in Ghidra's orders; covers; the
//! one mutation interface every pass goes through, with a recorder hook
//! (ADR-025 3a); the per-opcode property table; text dumps equal to the
//! console's; and loading and writing the oracle's state dumps.
//!
//! Ghidra: `varnode.hh/.cc` (`Varnode`, `VarnodeBank`), `op.hh/.cc`
//! (`PcodeOp`, `PcodeOpBank`, `PieceNode`), `cover.hh/.cc`, the
//! `BlockBasic` parts of `block.hh/.cc`, the op and varnode halves of
//! `funcdata_op.cc` and `funcdata_varnode.cc`, `Funcdata::printRaw`,
//! `printVarnodeTree` and the debug trace of `funcdata.cc`, and the
//! property words of `typeop.cc`, under
//! `Ghidra/Features/Decompiler/src/decompile/cpp/`. Specification:
//! `docs/features/decomp-ir.md`.
//!
//! - [`Ssa`]: one function's IR. Queries take `&Ssa` and ids; every change
//!   is a method named after `Funcdata`'s (module [`mutate`]); what those
//!   methods need from symbols, types, prototypes and high variables comes
//!   through [`FunctionEnv`] (ADR-046).
//! - [`Recorder`]: watches mutations; [`TraceRecorder`] reproduces Ghidra's
//!   `OPACTION_DEBUG` trace.
//! - [`props`]: the opcode table; [`semantics`]: what each op means at a
//!   unit boundary; [`mod@unit`]: units, origins and soundness as data.
//! - `state` (feature `bkstate`): `bkstate` dumps to and from an [`Ssa`].
//!
//! Ids are indices that are never reused within a function; nothing
//! recurses over input-sized structures; no method panics, whatever the
//! ids or the loaded state.

pub mod bank;
mod block;
mod check;
pub mod cover;
mod data;
pub mod error;
pub mod flags;
pub mod ids;
mod list;
pub mod mutate;
pub mod op;
mod opbank;
mod pool;
pub mod print;
pub mod props;
pub mod record;
pub mod semantics;
mod ssa;
#[cfg(feature = "bkstate")]
pub mod state;
pub mod unit;
pub mod varnode;

#[cfg(test)]
mod testing;

pub use bank::cursor::{DefCursor, LocCursor};
pub use bank::range::VnClass;
pub use bk_decomp_cfg::NodeId;
pub use block::CfgMut;
pub use cover::{Cover, CoverBlock, CoverPoint, OpSet};
pub use error::{IrError, IrResult};
pub use ids::{CallSpecId, EntryRef, HighId, OpId, UnitId, VarnodeId};
pub use list::OpIter;
pub use mutate::env::{Effect, FunctionEnv, LockedType, PropertiesAnswer, TableEnv};
pub use op::PieceNode;
pub use opbank::MAX_OPS;
pub use print::{CallName, NoNames, RawNames, RawOut};
pub use record::{Recorder, TraceRange, TraceRecorder};
pub use semantics::{EnvOp, Semantics};
pub use ssa::{CodeList, MemoryUse, Ssa};
pub use varnode::OffsetKind;
