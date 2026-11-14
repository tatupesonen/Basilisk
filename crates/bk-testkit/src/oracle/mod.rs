//! The decompiler oracle's file formats (`docs/features/decomp-oracle.md`,
//! ADR-042): typed readers and writers for what the console extension
//! (`tools/reference/consoleext`) reads and writes. Every reader checks its
//! input fully, never panics, bounds what it accepts, and reports errors with
//! line numbers; every writer gives back, byte for byte, any text its reader
//! accepted.
//!
//! | Module | Format | Written by |
//! |---|---|---|
//! | [`graph`] | `bkgraph 1` | `bk dump blocks`; read by `bk cfg analyze`, `bk structure` |
//! | [`cfgdump`] | `bkcfg 1` | `bk cfg analyze` |
//! | [`structure`] | `bkstruct 1` | `bk structure`, `bk dump structure` |
//! | [`actions`] | `bkactions 1` | `bk list actions` |

pub mod actions;
pub mod cfgdump;
pub mod generate;
pub mod graph;
pub mod structure;
mod text;

#[cfg(test)]
pub(crate) mod strategies;

pub use actions::{ActionLine, ActionList};
pub use cfgdump::{CfgAnalysis, CfgDump, CfgNode, LoopRecord};
pub use graph::{AddressRange, Facts, GraphEdge, GraphFile, GraphNode, OracleAddress};
pub use structure::{
    GotoCause, GotoMark, KindData, NodeKind, NodeName, RuleApplication, StructEdge, StructNode,
    StructureDump, Structured, SwitchCase,
};
pub use text::{MAX_FILE_BYTES, ParseError, ParseErrorKind};

/// The checked-in sample files of every format
/// (`crates/bk-testkit/tests/data/oracle`), for this crate's tests and for
/// other crates' tests that want a real example.
pub fn sample_dir() -> std::path::PathBuf {
    crate::workspace_root().join("crates/bk-testkit/tests/data/oracle")
}
