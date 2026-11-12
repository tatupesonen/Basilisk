//! Ghidra's language description files and the language registry.
//!
//! Ghidra describes each processor language with data files beside its
//! SLEIGH spec. This crate reads them into typed models and answers the
//! questions every tool asks before it can touch a binary: which languages
//! exist, what `x86:LE:64:default` is made of, and which language and
//! compiler should load a given file.
//!
//! * [`ldefs`] — language definitions (`.ldefs`), Ghidra's
//!   `SleighLanguageProvider` and `SleighLanguageDescription`.
//! * [`pspec`] — processor specifications (`.pspec`), read on the Java side
//!   by `SleighLanguage` and on the C++ side by
//!   `Architecture::parseProcessorConfig`; here one model serves both.
//! * [`opinion`] — loader opinions (`.opinion`), Ghidra's
//!   `QueryOpinionService`.
//! * [`LanguageRegistry`] — discovery and queries, Ghidra's
//!   `DefaultLanguageService`.
//! * [`schema`] — the grammar of the three file types as data, restating
//!   Ghidra's RELAX NG schemas; it is what the readers' strict mode
//!   enforces.
//!
//! Register names, address-space names and addresses are kept as the
//! strings and integers the files contain; resolving them against a loaded
//! SLEIGH language is the SLEIGH runtime's job.

mod endian;
mod error;
mod id;
pub mod ldefs;
pub mod opinion;
pub mod pspec;
mod reader;
mod registry;
pub mod schema;
mod value;

pub use endian::{Endian, ParseEndianError};
pub use error::{
    Mode, ParseError, ParseErrorKind, Position, ReadError, RegistryError, Violation, Warning,
};
pub use id::{CompilerSpecId, EmptyIdError, LanguageCompilerSpecPair, LanguageId, Processor};
pub use reader::Parsed;
pub use registry::{
    CompilerSpecDescription, ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecQuery,
    LanguageDescription, LanguageFiles, LanguageRegistry, LoadFailure, RegistryBuilder,
    SPEC_ROOT_ENV, spec_root_from_env,
};
