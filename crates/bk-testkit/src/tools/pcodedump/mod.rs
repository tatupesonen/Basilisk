//! basilisk's disassembly and p-code oracle (`tools/reference/pcodedump.cc`):
//! Ghidra's SLEIGH engine decoding a byte buffer as a linear sweep.

mod model;
mod parse;

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

pub use model::{
    DumpError, DumpErrorKind, DumpInstruction, DumpOp, DumpRecord, DumpVarnode, LiftError,
    LiftErrorKind, PcodeDump,
};
pub use parse::{DumpParseError, parse_dump};

use super::ToolError;
use super::process::Invocation;
use crate::paths::Tool;

/// Runs `bin/pcodedump`. Obtain one with [`crate::ReferenceDir::pcodedump`].
#[derive(Debug, Clone)]
pub struct Pcodedump {
    program: PathBuf,
    root: PathBuf,
    timeout: Duration,
    context: Vec<(String, u32)>,
}

impl Pcodedump {
    const DEFAULT_TIMEOUT: Duration = Duration::from_mins(2);

    pub(crate) fn new(program: PathBuf, root: PathBuf) -> Self {
        Self {
            program,
            root,
            timeout: Self::DEFAULT_TIMEOUT,
            context: Vec::new(),
        }
    }

    /// Replace the time limit of one run.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set a context variable over the whole code space, overriding the
    /// processor specification's value — for example `TMode` = 1 to decode
    /// ARM bytes as Thumb.
    #[must_use]
    pub fn context(mut self, name: &str, value: u32) -> Self {
        self.context.push((name.to_owned(), value));
        self
    }

    /// Decode `bytes` as `language` (a language id such as
    /// `x86:LE:64:default`), the first byte at offset `base` of the
    /// language's default code space, and return the parsed listing.
    pub fn dump(&self, language: &str, base: u64, bytes: &[u8]) -> Result<PcodeDump, ToolError> {
        Ok(parse_dump(&self.dump_text(language, base, bytes)?)?)
    }

    /// Like [`Self::dump`], but return the listing as the tool printed it —
    /// the form to snapshot with `insta` (it is deterministic, so it needs
    /// no normalising).
    pub fn dump_text(&self, language: &str, base: u64, bytes: &[u8]) -> Result<String, ToolError> {
        let unsupported = |reason: String| ToolError::Unsupported {
            tool: Tool::Pcodedump,
            reason,
        };
        // The tool reads anything starting with "--" as an option.
        if language.is_empty() || language.starts_with('-') {
            return Err(unsupported(format!("{language:?} is not a language id")));
        }
        let mut invocation = Invocation::new(Tool::Pcodedump, &self.program, self.timeout)
            .arg(&self.root)
            .arg(language)
            .arg(format!("{base:#x}"));
        for (name, value) in &self.context {
            if name.is_empty() || name.contains('=') {
                return Err(unsupported(format!(
                    "{name:?} is not a context variable name"
                )));
            }
            invocation = invocation
                .arg("--context")
                .arg(OsString::from(format!("{name}={value}")));
        }
        invocation.stdin = bytes.to_vec();
        Ok(invocation.run()?.require_success(Tool::Pcodedump)?.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> Pcodedump {
        Pcodedump::new(
            PathBuf::from("/nonexistent/bin/pcodedump"),
            PathBuf::from("/nonexistent"),
        )
    }

    #[test]
    fn bad_requests_are_rejected_before_running() {
        for language in ["", "--quiet", "-x"] {
            let error = tool().dump(language, 0, &[]).unwrap_err();
            assert!(
                matches!(error, ToolError::Unsupported { .. }),
                "{language:?}: {error:?}"
            );
        }
        for name in ["", "a=b"] {
            let error = tool()
                .context(name, 1)
                .dump("x86:LE:64:default", 0, &[])
                .unwrap_err();
            assert!(
                matches!(error, ToolError::Unsupported { .. }),
                "{name:?}: {error:?}"
            );
        }
    }

    #[test]
    fn a_missing_tool_is_reported() {
        let error = tool().dump("x86:LE:64:default", 0, &[0x90]).unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Missing {
                    tool: Tool::Pcodedump,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
