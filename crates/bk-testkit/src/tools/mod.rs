//! Typed wrappers around the reference tools.
//!
//! Each wrapper is obtained from a [`ReferenceDir`], runs one binary of its
//! `bin` directory with a time limit and returns a typed result:
//!
//! | Wrapper | Tool | Result |
//! |---|---|---|
//! | [`Sleigh`] | Ghidra's SLEIGH compiler | the compiler's messages |
//! | [`Decomp`] | Ghidra's decompiler consoles (`decomp`, `decomp_dbg`) and Basilisk's (`decomp_bk`, `decomp_bk_dbg`) | the transcript, command by command |
//! | [`DecompTest`] | Ghidra's test runner | pass or fail per test |
//! | [`Pcodedump`] | Basilisk's p-code oracle | parsed instructions and p-code ops |
//! | [`Snippetdump`] | Basilisk's p-code snippet oracle | one outcome per snippet |
//!
//! Arguments are passed as an argument vector; nothing goes through a shell.

mod process;

pub mod decomp;
pub mod decomp_test;
pub mod pcodedump;
pub mod sleigh;
pub mod snippetdump;

use std::path::PathBuf;
use std::time::Duration;

pub use decomp::{Decomp, DecompStep, DecompTranscript};
pub use decomp_test::{DataTestReport, DecompTest, ReportParseError, TestOutcome, UnitTestReport};
pub use pcodedump::{
    DumpError, DumpErrorKind, DumpInstruction, DumpOp, DumpParseError, DumpRecord, DumpVarnode,
    LiftError, LiftErrorKind, PcodeDump, Pcodedump, parse_dump,
};
pub use sleigh::Sleigh;
pub use snippetdump::{
    SnippetBase, SnippetOutcome, SnippetParameter, SnippetParseError, SnippetRecord, Snippetdump,
};

use crate::paths::{ReferenceDir, Tool};

/// What a tool printed and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// The exit code, or `None` when the tool was ended by a signal.
    pub code: Option<i32>,
    /// Everything written to standard output.
    pub stdout: String,
    /// Everything written to standard error.
    pub stderr: String,
    /// Wall-clock time from start to exit.
    pub elapsed: Duration,
}

impl ToolOutput {
    /// Whether the tool exited with code 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Turn a non-zero exit into [`ToolError::Failed`].
    pub(crate) fn require_success(self, tool: Tool) -> Result<Self, ToolError> {
        if self.success() {
            Ok(self)
        } else {
            Err(ToolError::Failed {
                tool,
                code: self.code,
                stdout: self.stdout,
                stderr: self.stderr,
            })
        }
    }
}

/// Why a reference tool did not produce a result.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolError {
    /// The binary is not in the reference directory.
    #[error("{tool}: no binary at {}; build it with scripts/build-reference.sh", path.display())]
    Missing {
        /// The tool that was asked for.
        tool: Tool,
        /// Where its binary was expected.
        path: PathBuf,
    },
    /// Starting the tool, or talking to it, failed.
    #[error("{tool}: {source}")]
    Io {
        /// The tool that was run.
        tool: Tool,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The tool ran past its time limit and was killed.
    #[error("{tool}: killed after exceeding its time limit of {timeout:?}")]
    Timeout {
        /// The tool that was run.
        tool: Tool,
        /// The limit it exceeded.
        timeout: Duration,
        /// What it had written to standard output.
        stdout: String,
        /// What it had written to standard error.
        stderr: String,
    },
    /// The tool exited with a code that means failure. Its output is kept,
    /// since the message is usually the point (a SLEIGH compile error, a
    /// decompiler script error).
    #[error("{tool}: exited with {}:\n{stdout}{stderr}", exit_text(*code))]
    Failed {
        /// The tool that was run.
        tool: Tool,
        /// Its exit code, or `None` when it was ended by a signal.
        code: Option<i32>,
        /// What it wrote to standard output.
        stdout: String,
        /// What it wrote to standard error.
        stderr: String,
    },
    /// The request cannot be expressed to the tool.
    #[error("{tool}: {reason}")]
    Unsupported {
        /// The tool that was asked.
        tool: Tool,
        /// What cannot be done and why.
        reason: String,
    },
    /// `pcodedump` printed something that is not its documented format.
    #[error("pcodedump: unexpected output: {0}")]
    Dump(#[from] DumpParseError),
    /// `snippetdump` printed something that is not its record format.
    #[error("snippetdump: unexpected output: {0}")]
    Snippet(#[from] SnippetParseError),
    /// `decomp_test` printed something that is not its usual report.
    #[error("decomp_test: unexpected output: {0}")]
    Report(#[from] ReportParseError),
}

/// "code N" or "a signal", for messages.
fn exit_text(code: Option<i32>) -> String {
    code.map_or_else(|| "a signal".to_owned(), |code| format!("code {code}"))
}

impl ReferenceDir {
    /// Ghidra's SLEIGH compiler.
    pub fn sleigh(&self) -> Sleigh {
        Sleigh::new(self.tool_path(Tool::Sleigh))
    }

    /// Ghidra's decompiler console, finding its languages in this directory.
    pub fn decomp(&self) -> Decomp {
        self.console(Tool::Decomp)
    }

    /// Ghidra's `CPUI_DEBUG` console (`decomp_dbg`): the same commands plus
    /// `trace` and `debug action`.
    pub fn decomp_dbg(&self) -> Decomp {
        self.console(Tool::DecompDbg)
    }

    /// The console with Basilisk's extension (`decomp_bk`): Ghidra's
    /// commands plus the `bk …` commands of `docs/features/decomp-oracle.md`.
    pub fn decomp_bk(&self) -> Decomp {
        self.console(Tool::DecompBk)
    }

    /// The `CPUI_DEBUG` console with Basilisk's extension (`decomp_bk_dbg`).
    pub fn decomp_bk_dbg(&self) -> Decomp {
        self.console(Tool::DecompBkDbg)
    }

    /// One of the four decompiler consoles.
    fn console(&self, tool: Tool) -> Decomp {
        Decomp::new(tool, self.tool_path(tool), self.root().to_path_buf())
    }

    /// Ghidra's decompiler test runner, finding its languages in this directory.
    pub fn decomp_test(&self) -> DecompTest {
        DecompTest::new(self.tool_path(Tool::DecompTest), self.root().to_path_buf())
    }

    /// The p-code oracle, finding its languages in this directory.
    pub fn pcodedump(&self) -> Pcodedump {
        Pcodedump::new(self.tool_path(Tool::Pcodedump), self.root().to_path_buf())
    }

    /// The p-code snippet oracle, finding its languages in this directory.
    pub fn snippetdump(&self) -> Snippetdump {
        Snippetdump::new(self.tool_path(Tool::Snippetdump), self.root().to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(code: Option<i32>) -> ToolOutput {
        ToolOutput {
            code,
            stdout: "out\n".to_owned(),
            stderr: "err\n".to_owned(),
            elapsed: Duration::ZERO,
        }
    }

    #[test]
    fn zero_exit_is_success() {
        assert!(output(Some(0)).success());
        assert!(output(Some(0)).require_success(Tool::Sleigh).is_ok());
    }

    #[test]
    fn failure_keeps_the_output() {
        let error = output(Some(2)).require_success(Tool::Sleigh).unwrap_err();
        let text = error.to_string();
        assert!(text.starts_with("sleigh: exited with code 2:"), "{text}");
        assert!(text.contains("out\n") && text.contains("err\n"), "{text}");
    }

    #[test]
    fn a_signal_is_a_failure() {
        let error = output(None).require_success(Tool::Decomp).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("decomp: exited with a signal:"),
            "{error}"
        );
    }
}
