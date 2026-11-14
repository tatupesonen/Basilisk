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
//! | [`state`] | `bkstate 1` | `bk dump state` |
//! | [`trace`] | Ghidra's `DEBUG` records | `decomp_dbg`, `decomp_bk_dbg` with `trace enable` |
//! | [`pcoderec`] | `pcoderec 1` | `bk pcode record` |

pub mod actions;
pub mod capture;
pub mod cfgdump;
pub mod generate;
pub mod graph;
pub mod host;
pub mod pcoderec;
pub mod state;
pub mod structure;
mod text;
pub mod trace;

#[cfg(test)]
pub(crate) mod strategies;

pub use actions::{ActionLine, ActionList};
pub use cfgdump::{CfgAnalysis, CfgDump, CfgNode, LoopRecord};
pub use graph::{AddressRange, Facts, GraphEdge, GraphFile, GraphNode, OracleAddress};
pub use pcoderec::{Answer, LookupError, RecEvent, RecOp, RecVarnode, RecordedPcode, Recording};
pub use state::StateDump;
pub use structure::{
    GotoCause, GotoMark, KindData, NodeKind, NodeName, RuleApplication, StructEdge, StructNode,
    StructureDump, Structured, SwitchCase,
};
pub use text::{MAX_FILE_BYTES, ParseError, ParseErrorKind};
pub use trace::{Trace, TraceOp, TraceRecord};

/// The checked-in sample files of every format
/// (`crates/bk-testkit/tests/data/oracle`), for this crate's tests and for
/// other crates' tests that want a real example.
pub fn sample_dir() -> std::path::PathBuf {
    crate::workspace_root().join("crates/bk-testkit/tests/data/oracle")
}

/// Read a text file, decompressing it when its name ends in `.gz`; at most
/// [`MAX_FILE_BYTES`] of text are accepted.
pub fn read_text(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let limit = u64::try_from(MAX_FILE_BYTES).unwrap_or(u64::MAX) + 1;
    let mut bytes = Vec::new();
    if path.extension().is_some_and(|e| e == "gz") {
        flate2::read::GzDecoder::new(file)
            .take(limit)
            .read_to_end(&mut bytes)?;
    } else {
        file.take(limit).read_to_end(&mut bytes)?;
    }
    if bytes.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is larger than {MAX_FILE_BYTES} bytes", path.display()),
        ));
    }
    String::from_utf8(bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Write a text file, compressing it when its name ends in `.gz`
/// (deterministically: no file name or time stamp in the gzip header).
pub fn write_text(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if path.extension().is_some_and(|e| e == "gz") {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(text.as_bytes())?;
        std::fs::write(path, encoder.finish()?)
    } else {
        std::fs::write(path, text)
    }
}
