//! Ghidra's SLEIGH compiler (`slgh_compile.cc`): `.slaspec` to `.sla`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::process::Invocation;
use super::{ToolError, ToolOutput};
use crate::paths::Tool;

/// Runs `bin/sleigh`. Obtain one with [`crate::ReferenceDir::sleigh`].
#[derive(Debug, Clone)]
pub struct Sleigh {
    program: PathBuf,
    timeout: Duration,
    options: Vec<OsString>,
}

impl Sleigh {
    /// Long enough for the largest specification on a loaded machine.
    const DEFAULT_TIMEOUT: Duration = Duration::from_mins(5);

    pub(crate) fn new(program: PathBuf) -> Self {
        Self {
            program,
            timeout: Self::DEFAULT_TIMEOUT,
            options: Vec::new(),
        }
    }

    /// Replace the time limit of one compilation.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Define a preprocessor macro, as `-DNAME=VALUE` does.
    #[must_use]
    pub fn define(mut self, name: &str, value: &str) -> Self {
        self.options
            .push(OsString::from(format!("-D{name}={value}")));
        self
    }

    /// Pass one of the compiler's single-letter switches, for example `'l'`
    /// to report pattern conflicts or `'y'` to write the `.sla` in the XML
    /// debug format.
    #[must_use]
    pub fn switch(mut self, letter: char) -> Self {
        self.options.push(OsString::from(format!("-{letter}")));
        self
    }

    /// Compile `slaspec` into `sla`. Includes are resolved relative to the
    /// specification, as the compiler does.
    ///
    /// Returns the compiler's output — warnings are on standard output — or
    /// [`ToolError::Failed`] with that output when the specification does
    /// not compile.
    pub fn compile(&self, slaspec: &Path, sla: &Path) -> Result<ToolOutput, ToolError> {
        // The compiler appends ".slaspec" / ".sla" to names that lack them;
        // insist on the extensions so the files it touches are the ones named.
        for (path, extension) in [(slaspec, "slaspec"), (sla, "sla")] {
            if path.extension().is_none_or(|found| found != extension) {
                return Err(ToolError::Unsupported {
                    tool: Tool::Sleigh,
                    reason: format!("{} does not end in .{extension}", path.display()),
                });
            }
        }
        let mut invocation = Invocation::new(Tool::Sleigh, &self.program, self.timeout);
        invocation.args.extend(self.options.iter().cloned());
        invocation
            .arg(slaspec)
            .arg(sla)
            .run()?
            .require_success(Tool::Sleigh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_become_arguments() {
        let sleigh = Sleigh::new(PathBuf::from("/ref/bin/sleigh"))
            .define("BaseDir", "/r")
            .switch('l');
        assert_eq!(
            sleigh.options,
            [OsString::from("-DBaseDir=/r"), OsString::from("-l")]
        );
    }

    #[test]
    fn file_names_must_carry_their_extensions() {
        let sleigh = Sleigh::new(PathBuf::from("/ref/bin/sleigh"));
        for (spec, sla) in [
            ("toy", "toy.sla"),
            ("toy.slaspec", "toy"),
            ("toy.sla", "toy.sla"),
        ] {
            let error = sleigh.compile(Path::new(spec), Path::new(sla)).unwrap_err();
            assert!(
                matches!(error, ToolError::Unsupported { .. }),
                "{spec} {sla}: {error:?}"
            );
        }
    }

    #[test]
    fn a_missing_compiler_is_reported() {
        let sleigh = Sleigh::new(PathBuf::from("/nonexistent/bin/sleigh"));
        let error = sleigh
            .compile(Path::new("toy.slaspec"), Path::new("toy.sla"))
            .unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Missing {
                    tool: Tool::Sleigh,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
