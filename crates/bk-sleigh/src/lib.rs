//! The SLEIGH runtime, part 1: loading a compiled language, the decoding
//! context, decoding instructions and their disassembly text.
//!
//! This crate corresponds to Ghidra's C++ SLEIGH engine (`sleigh.cc`,
//! `sleighbase.cc`, `context.cc`, `globalcontext.cc`, `slghsymbol.cc`,
//! `slghpatexpress.cc`, `slghpattern.cc`, the handle part of `semantics.cc`),
//! which is authoritative because Ghidra's decompiler and the differential
//! oracle `pcodedump` run it. Specification: `docs/features/sleigh-decode.md`;
//! background: `docs/inventory/01-sleigh.md` sections 3–8.
//!
//! - [`Language`]: a loaded language, immutable and shared as
//!   `Arc<Language>` ([`Language::load`], [`Language::from_sla`]).
//! - [`ContextDb`]: the context database; the decoder reads context through
//!   [`ContextSource`] and writes commits through [`ContextSink`].
//! - [`Decoder`]: a per-thread worker that decodes into a reused [`Parse`]
//!   ([`Decoder::decode`], [`Decoder::resolve_handles`],
//!   [`Decoder::apply_commits`], [`Decoder::prepare`]) and prints it
//!   ([`Language::mnemonic`], [`Language::body`]).
//! - [`DecodeError`], [`LoadError`]: errors carrying Ghidra's messages.
//! - [`Translate`]: the translator interface, completed by p-code
//!   generation in a later part.

pub mod context;
pub mod decode;
pub mod dump;
pub mod emit;
pub mod error;
pub mod language;
pub mod pcode;
mod print;
pub mod translate;

pub use context::{ContextDb, ContextSink, ContextSource, ContextVar, OffsetRange, TrackedValue};
pub use decode::{
    ByteSource, Commit, Decoder, Disassembly, FixedHandle, Node, Parse, ParseState, Prepared,
    SliceBytes, WINDOW,
};
pub use emit::{CollectedOp, PcodeCollector, PcodeCounter, PcodeEmit, PcodeRecords};
pub use error::{DecodeError, ErrorClass, Limit, LoadError, RawText, TableKind};
pub use language::{Language, RegisterTable};
pub use pcode::{BuildFeature, BuildObserver, InjectContext, LiftError, LiftLimit};
pub use translate::{Translate, Translator};
