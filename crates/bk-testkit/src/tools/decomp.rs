//! Ghidra's decompiler console (`consolemain.cc`, `ifacedecomp.cc`): load an
//! image, run commands, print C.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::process::Invocation;
use super::{ToolError, ToolOutput};
use crate::datatest::DataTest;
use crate::paths::Tool;

/// The prompt the console echoes before each command of an `-i` script.
const SCRIPT_PROMPT: &str = "init> ";

/// Runs one of the decompiler consoles: `bin/decomp`, or `decomp_dbg`,
/// `decomp_bk`, `decomp_bk_dbg` (`docs/features/decomp-oracle.md`). Obtain
/// one with [`crate::ReferenceDir::decomp`] and its siblings.
#[derive(Debug, Clone)]
pub struct Decomp {
    tool: Tool,
    program: PathBuf,
    sleigh_home: PathBuf,
    timeout: Duration,
}

impl Decomp {
    const DEFAULT_TIMEOUT: Duration = Duration::from_mins(2);

    pub(crate) fn new(tool: Tool, program: PathBuf, sleigh_home: PathBuf) -> Self {
        Self {
            tool,
            program,
            sleigh_home,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Replace the time limit of one run.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Run console commands, one per item, as an `-i` script. The console
    /// stops at the first command that fails; that is
    /// [`ToolError::Failed`], with the transcript so far in its `stdout`.
    ///
    /// A `quit` is appended when the script does not end with one, so the
    /// console never waits for more input.
    pub fn run_script<I, S>(&self, commands: I) -> Result<DecompTranscript, ToolError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let tool = self.tool;
        let io_error = |source| ToolError::Io { tool, source };
        let mut script = tempfile::Builder::new()
            .prefix("bk-decomp-")
            .suffix(".script")
            .tempfile()
            .map_err(io_error)?;
        let mut last = String::new();
        for command in commands {
            // One command per line: a line break inside one would split it.
            last = command.as_ref().replace(['\r', '\n'], " ");
            writeln!(script, "{last}").map_err(io_error)?;
        }
        if last.trim() != "quit" {
            writeln!(script, "quit").map_err(io_error)?;
        }
        script.flush().map_err(io_error)?;

        let mut invocation = Invocation::new(tool, &self.program, self.timeout)
            .arg("-i")
            .arg(script.path());
        // The console finds languages through SLEIGHHOME when it is not
        // running from inside a Ghidra installation. LC_ALL=C keeps the
        // output free of the locale (decomp-oracle.md 4.11).
        invocation
            .envs
            .push(("SLEIGHHOME", self.sleigh_home.clone().into_os_string()));
        invocation.envs.push(("LC_ALL", "C".into()));
        let output = invocation.run()?.require_success(tool)?;
        Ok(DecompTranscript::parse(output))
    }

    /// Run a decompiler data test's script on its image and return what the
    /// console printed: Ghidra's actual output for the test, where
    /// `decomp_test` only says whether its patterns matched.
    pub fn run_data_test(&self, test: &DataTest) -> Result<DecompTranscript, ToolError> {
        let tool = self.tool;
        let io_error = |source| ToolError::Io { tool, source };
        let mut image = tempfile::Builder::new()
            .prefix("bk-decomp-")
            .suffix(".xml")
            .tempfile()
            .map_err(io_error)?;
        image
            .write_all(test.image.to_xml().as_bytes())
            .map_err(io_error)?;
        image.flush().map_err(io_error)?;
        let load = load_command(tool, image.path())?;
        self.run_script(
            std::iter::once(load.as_str()).chain(test.script.iter().map(String::as_str)),
        )
    }
}

/// The console command that loads the image at `path`. The console splits
/// commands at white space and has no quoting, so such a path cannot be
/// loaded.
fn load_command(tool: Tool, path: &Path) -> Result<String, ToolError> {
    match path.to_str() {
        Some(text) if !text.contains(char::is_whitespace) => Ok(format!("load file {text}")),
        _ => Err(ToolError::Unsupported {
            tool,
            reason: format!(
                "the console cannot load a file whose path has white space or is not UTF-8: {}",
                path.display()
            ),
        }),
    }
}

/// What the console printed for a script, split by command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompTranscript {
    /// Each command with the output that followed it, in order.
    pub steps: Vec<DecompStep>,
    /// The raw output and timing of the run.
    pub output: ToolOutput,
}

/// One command of a script and what the console printed in response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompStep {
    /// The command as the console echoed it.
    pub command: String,
    /// Everything printed until the next command, line breaks included.
    pub output: String,
}

impl DecompTranscript {
    /// Split standard output at the echoed commands.
    fn parse(output: ToolOutput) -> Self {
        let mut steps: Vec<DecompStep> = Vec::new();
        for line in output.stdout.split_inclusive('\n') {
            if let Some(command) = line.strip_prefix(SCRIPT_PROMPT) {
                steps.push(DecompStep {
                    command: command.trim_end_matches(['\r', '\n']).to_owned(),
                    output: String::new(),
                });
            } else if let Some(step) = steps.last_mut() {
                step.output.push_str(line);
            }
        }
        Self { steps, output }
    }

    /// The output of every step whose command is `command`, in order — for
    /// example each function printed by `print C`.
    pub fn outputs_of<'a>(&'a self, command: &'a str) -> impl Iterator<Item = &'a str> {
        self.steps
            .iter()
            .filter(move |step| step.command == command)
            .map(|step| step.output.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(stdout: &str) -> DecompTranscript {
        DecompTranscript::parse(ToolOutput {
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
            elapsed: Duration::ZERO,
        })
    }

    #[test]
    fn transcript_is_split_at_echoed_commands() {
        let parsed = transcript(
            "init> load file /tmp/image.xml\n/tmp/image.xml successfully loaded: Intel\n\
             init> lo fu main\nFunction main: 0x1000\ninit> print C\n\nint main(void)\n\n{\n  \
             return 0;\n}\ninit> quit\n",
        );
        let commands: Vec<_> = parsed
            .steps
            .iter()
            .map(|step| step.command.as_str())
            .collect();
        assert_eq!(
            commands,
            ["load file /tmp/image.xml", "lo fu main", "print C", "quit"]
        );
        assert_eq!(parsed.steps[1].output, "Function main: 0x1000\n");
        let printed: Vec<_> = parsed.outputs_of("print C").collect();
        assert_eq!(printed, ["\nint main(void)\n\n{\n  return 0;\n}\n"]);
        assert_eq!(parsed.steps[3].output, "");
    }

    #[test]
    fn output_before_the_first_command_is_not_a_step() {
        let parsed = transcript("banner\ninit> quit\n");
        assert_eq!(parsed.steps.len(), 1);
        assert_eq!(parsed.output.stdout, "banner\ninit> quit\n");
    }

    #[test]
    fn load_command_needs_a_plain_path() {
        assert_eq!(
            load_command(Tool::Decomp, Path::new("/tmp/a.xml")).unwrap(),
            "load file /tmp/a.xml"
        );
        let error = load_command(Tool::Decomp, Path::new("/tmp/my files/a.xml")).unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Unsupported {
                    tool: Tool::Decomp,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_missing_console_is_reported() {
        let decomp = Decomp::new(
            Tool::Decomp,
            PathBuf::from("/nonexistent/bin/decomp"),
            PathBuf::from("/nonexistent"),
        );
        let error = decomp.run_script(["quit"]).unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Missing {
                    tool: Tool::Decomp,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
