//! Ghidra's two serialisation forms: XML and the packed binary form.
//!
//! Every processor specification file, every compiled `.sla` file and all
//! decompiler input and output is a tree of *elements* carrying *attributes*,
//! written either as XML text or in a compact byte encoding. This crate
//! reads and writes both forms behind one [`Decoder`] and one [`Encoder`]
//! interface. It corresponds to Ghidra's `marshal.hh`/`marshal.cc` and
//! `xml.hh`/`xml.y` (C++), with `PatchPackedEncode` from the Java twin in
//! `ghidra.program.model.pcode`.
//!
//! - [`ids`]: element and attribute ids ([`ElementId`], [`AttributeId`]) and
//!   the per-scope name table ([`IdTable`]).
//! - [`xml`]: the XML document tree, [`XmlDecoder`] and [`XmlEncoder`].
//! - [`packed`]: [`PackedDecoder`] and [`PackedEncoder`].
//! - [`space`]: what marshalling needs to know about address spaces; the
//!   spaces themselves live in `bk-core`.
//!
//! This is the lowest crate of the workspace and depends on no other `bk-*`
//! crate.

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod ids;
pub mod packed;
pub mod space;
pub mod xml;

pub use decoder::Decoder;
pub use encoder::Encoder;
pub use error::{AttributeKind, DecodeError, EncodeError};
pub use ids::{AttrCode, AttributeId, ElemCode, ElementId, IdTable, IdTableError};
pub use packed::{PackedDecoder, PackedEncoder};
pub use space::{NoSpaces, PackedSpace, SpaceId, SpaceRef, SpaceResolver};
pub use xml::{Document, ElementRef, XmlDecoder, XmlEncoder, XmlError};

/// The deepest nesting of open elements a decoder allows.
///
/// Routines that consume documents recurse once per level, so the limit
/// bounds their stack use on hostile input (ADR-009). Ghidra's own files nest
/// a few dozen levels at most.
pub const MAX_ELEMENT_DEPTH: usize = 1_000;
