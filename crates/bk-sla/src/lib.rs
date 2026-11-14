//! The compiled SLEIGH language file (`.sla`, format version 4): an
//! in-memory model of exactly what the file holds, laid out for instruction
//! decoding; a reader that validates untrusted input; and writers that
//! reproduce Ghidra's bytes.
//!
//! This crate corresponds to the `encode`/`decode` methods of Ghidra's C++
//! SLEIGH classes (`slaformat.cc`, `sleighbase.cc`, `slghsymbol.cc`,
//! `slghpattern.cc`, `slghpatexpress.cc`, `semantics.cc`); the C++ is
//! authoritative. The format is specified in `docs/inventory/01-sleigh.md`
//! section 2 and the crate in `docs/features/sla.md`.
//!
//! - [`Sla`]: the model — one immutable value of flat arenas with typed
//!   `u32` indices ([`model`]); read with [`Sla::read`],
//!   [`Sla::decode_packed`], [`Sla::decode_xml`]; written with
//!   [`Sla::write`], [`Sla::encode_packed`], [`Sla::encode_xml`].
//! - [`SlaBuilder`]: the producer's interface (the SLEIGH compiler).
//! - [`diff`]: a structural comparison with a path for each difference.
//! - [`Template`]: a p-code template outside a file (injection snippets).
//! - [`ids`]: the format scope's element and attribute ids.

pub mod builder;
pub mod diff;
pub mod error;
pub mod ids;
pub mod limits;
pub mod model;
mod read;
mod spaces;
mod template_codec;
mod validate;
mod write;

pub use builder::{
    BlockDef, ConstructorDef, DecisionDef, PairDef, PatternDef, PrintDef, SlaBuilder, SpaceDef,
    SymbolDef, TableDef,
};
pub use diff::{Difference, diff};
pub use error::{Location, SlaError, StreamError};
pub use limits::Limits;
pub use model::Sla;
pub use model::constructor::{
    Constructor, ContextChange, DecisionNode, DecisionPair, DisjointPattern, MaskWord,
    PatternBlock, PrintPiece, normalize_block,
};
pub use model::expr::{BinaryOp, Expr, Field, UnaryOp};
pub use model::handles::{
    BlockId, ConstructorId, DecisionId, ExprId, FieldId, HandleId, ScopeId, Span, StrId, SymbolId,
    TemplateId,
};
pub use model::symbol::{
    Header, Operand, Scope, SpaceKind, SpaceRecord, Subtable, Symbol, SymbolKind,
};
pub use model::template::{
    ConstTpl, ConstructTpl, HandleSelect, HandleTpl, OpTpl, Template, TemplateRef, VarnodeTpl,
};
pub use read::{PackedReader, inflate};
pub use spaces::CONSTANT_SPACE_NAME;
pub use template_codec::SpaceTable;
