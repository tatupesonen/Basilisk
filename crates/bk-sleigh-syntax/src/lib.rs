//! SLEIGH front end: preprocessor, modal lexer and parser.
//!
//! SLEIGH is the language Ghidra's processors are specified in. This crate
//! turns `.slaspec` source and its `.sinc` includes into a symbol-free
//! syntax tree in which every node carries a span that resolves to the
//! original file, line and column, through `@include` and `$(NAME)`
//! expansion.

pub mod diag;
pub mod intern;
pub mod lex;
pub mod loader;
pub mod preprocess;
pub mod source;
pub mod span;

pub use diag::{Diagnostic, Severity};
pub use intern::{Interner, Symbol, kw};
pub use loader::{FileLoader, FsLoader, LoadError, MemoryLoader};
pub use preprocess::{Defines, Preprocessed, preprocess};
pub use source::{LineKind, SourceFile, SourceFileIndexer, SourceMap};
pub use span::{FileId, IncludeId, Location, Span};
