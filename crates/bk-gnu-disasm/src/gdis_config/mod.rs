//! `.gdis` files: which disassembler options Ghidra sends to `gdis` for a
//! language (`Ghidra/Processors/*/data/languages/*.gdis`, named by an
//! `external_name tool="gdis.disassembler.options.file"` in the `.ldefs`).
//!
//! A file has an optional global option string, and optionally a context
//! register whose value selects further options and a display prefix:
//!
//! ```xml
//! <gdis>
//!     <global optstring="intel"/>
//!     <context_register>TMode</context_register>
//!     <options>
//!         <option value="0x1" optstring="force-thumb" display_prefix="T: "/>
//!     </options>
//! </gdis>
//! ```
//!
//! [`read::parse`] reads one as `GNUExternalDisassembler.parseGdisOptionsFile`
//! does, into the model of [`model`].

pub mod model;
pub mod read;

pub use model::{ContextOption, ContextOptions, GdisConfig};
pub use read::{ConfigError, parse, read_file};
