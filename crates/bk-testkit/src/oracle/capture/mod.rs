//! The capture driver (`docs/features/decomp-oracle.md` 5.3, 6): runs the
//! extended consoles over a corpus and writes, per decompilation, the state
//! dumps at the four standard points and at the end, the `print raw` at the
//! first, the trace, every structuring run's graph and structure, and per
//! script the p-code recording — checking on the way that each end dump is
//! complete (6.2), that replaying the recording gives the same `print raw`
//! (6.3), and that `decomp_dbg` prints what `decomp` prints (6.6).
//! `bk-oracle` (the binary) runs it twice and compares (6.5).

mod checks;
mod run;
mod scripts;

pub use checks::{Completeness, check_completeness, without_pointers};
pub use run::{CaptureReport, FunctionSummary, ScriptSummary, capture_corpus, find_positions};
pub use scripts::{CorpusScript, Positions, data_tests, is_decompile, research};

use std::path::PathBuf;

/// Why a capture could not be made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// Reading or writing a file failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// A console did not run to the end.
    #[error(transparent)]
    Tool(#[from] crate::tools::ToolError),
    /// The corpus, or something the console printed, is not as expected.
    #[error("{0}")]
    Corpus(String),
}
