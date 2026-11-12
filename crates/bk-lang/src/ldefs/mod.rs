//! Language definition files (`.ldefs`): which languages a processor
//! module provides, and the files each one is made of.
//!
//! Ghidra reads these in `SleighLanguageProvider.read` after validating
//! them against `language_definitions.rxg`.

mod model;
mod read;

pub use model::{
    CompilerDefinition, ExternalName, LanguageDefinition, LanguageDefinitions, LanguageVersion,
    TruncatedSpace,
};
pub use read::{parse, read_file};
