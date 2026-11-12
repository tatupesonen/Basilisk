//! Running a reference tool: no shell, a time limit, both output streams
//! captured.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use wait_timeout::ChildExt as _;

use super::{ToolError, ToolOutput};
use crate::paths::Tool;

/// One run of a tool. Arguments are passed as an argument vector, never
/// through a shell, so nothing in them is interpreted.
#[derive(Debug)]
pub(crate) struct Invocation<'a> {
    /// Which tool this is, for error messages.
    pub(crate) tool: Tool,
    /// The binary to run.
    pub(crate) program: &'a Path,
    /// Its arguments.
    pub(crate) args: Vec<OsString>,
    /// Bytes to feed to standard input. Standard input is always a pipe,
    /// closed once these are written: Ghidra's console refuses to start on
    /// macOS when its input is `/dev/null`.
    pub(crate) stdin: Vec<u8>,
    /// Environment variables to add.
    pub(crate) envs: Vec<(&'static str, OsString)>,
    /// Working directory, if not the caller's.
    pub(crate) cwd: Option<PathBuf>,
    /// How long the tool may run before it is killed.
    pub(crate) timeout: Duration,
}

impl<'a> Invocation<'a> {
    /// An invocation with no arguments, input, variables or working directory.
    pub(crate) fn new(tool: Tool, program: &'a Path, timeout: Duration) -> Self {
        Self {
            tool,
            program,
            args: Vec::new(),
            stdin: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            timeout,
        }
    }

    /// Append one argument.
    pub(crate) fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Run the tool to completion or to its time limit. A non-zero exit is
    /// not an error here; callers decide what an exit code means.
    pub(crate) fn run(self) -> Result<ToolOutput, ToolError> {
        let tool = self.tool;
        if !self.program.is_file() {
            return Err(ToolError::Missing {
                tool,
                path: self.program.to_path_buf(),
            });
        }
        let io_error = |source: io::Error| ToolError::Io { tool, source };

        let mut command = Command::new(self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &self.envs {
            command.env(name, value);
        }
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }

        let started = Instant::now();
        let mut child = command.spawn().map_err(io_error)?;

        // Feed and drain the pipes on their own threads: a tool that fills
        // one pipe while we block on another would otherwise deadlock.
        let feeder = child.stdin.take().map(|mut pipe| {
            let input = self.stdin;
            thread::spawn(move || match pipe.write_all(&input) {
                // A tool that exits without reading its input is not an error.
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
                _ => Ok(()),
            })
        });
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);

        let status = child.wait_timeout(self.timeout).map_err(io_error)?;
        if status.is_none() {
            // Past the limit: kill it, then reap it so the pipes close.
            child.kill().map_err(io_error)?;
            child.wait().map_err(io_error)?;
        }
        let elapsed = started.elapsed();

        if let Some(feeder) = feeder {
            join(feeder).map_err(io_error)?;
        }
        let stdout = collect(stdout).map_err(io_error)?;
        let stderr = collect(stderr).map_err(io_error)?;

        match status {
            Some(status) => Ok(ToolOutput {
                code: status.code(),
                stdout,
                stderr,
                elapsed,
            }),
            None => Err(ToolError::Timeout {
                tool,
                timeout: self.timeout,
                stdout,
                stderr,
            }),
        }
    }
}

/// Read a pipe to its end on a new thread.
fn drain<R: Read + Send + 'static>(mut pipe: R) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

/// The result of a pipe thread; a panic in it is reported as an I/O error.
fn join<T>(handle: JoinHandle<io::Result<T>>) -> io::Result<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("a pipe thread panicked"))?
}

/// What a drained pipe held, as text. The tools print ASCII; anything else
/// is replaced rather than rejected, since output is evidence, not input.
fn collect(handle: Option<JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<String> {
    match handle {
        Some(handle) => Ok(String::from_utf8_lossy(&join(handle)?).into_owned()),
        None => Ok(String::new()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const SH: &str = "/bin/sh";

    fn sh(script: &str, timeout: Duration) -> Invocation<'static> {
        // Any tool will do for the label; `sh` stands in for the binary.
        Invocation::new(Tool::Sleigh, Path::new(SH), timeout)
            .arg("-c")
            .arg(script)
    }

    #[test]
    fn captures_both_streams_and_the_exit_code() {
        let output = sh("echo out; echo err >&2; exit 3", Duration::from_secs(30))
            .run()
            .unwrap();
        assert_eq!(output.code, Some(3));
        assert_eq!(output.stdout, "out\n");
        assert_eq!(output.stderr, "err\n");
    }

    #[test]
    fn feeds_standard_input_and_closes_it() {
        let mut invocation = sh("cat", Duration::from_secs(30));
        invocation.stdin = b"hello\n".to_vec();
        assert_eq!(invocation.run().unwrap().stdout, "hello\n");
    }

    #[test]
    fn large_output_does_not_deadlock() {
        // More than a pipe buffer on each stream, with input left unread.
        let script = "i=0; while [ $i -lt 20000 ]; do echo 0123456789abcdef; \
                      echo 0123456789abcdef >&2; i=$((i+1)); done";
        let mut invocation = sh(script, Duration::from_mins(1));
        invocation.stdin = vec![b'x'; 1 << 20];
        let output = invocation.run().unwrap();
        assert_eq!(output.stdout.len(), 20000 * 17);
        assert_eq!(output.stderr.len(), 20000 * 17);
    }

    #[test]
    fn arguments_are_not_interpreted_by_a_shell() {
        let hostile = "$(echo injected); `echo injected`; a b\tc";
        let output = sh("printf '%s' \"$1\"", Duration::from_secs(30))
            .arg("argv0")
            .arg(hostile)
            .run()
            .unwrap();
        assert_eq!(output.stdout, hostile);
    }

    #[test]
    fn environment_and_working_directory_are_applied() {
        let dir = tempfile::tempdir().unwrap();
        let mut invocation = sh(
            "printf '%s|' \"$BK_TEST_VALUE\"; pwd -P",
            Duration::from_secs(30),
        );
        invocation
            .envs
            .push(("BK_TEST_VALUE", OsString::from("from env")));
        invocation.cwd = Some(dir.path().to_path_buf());
        let output = invocation.run().unwrap();
        let (value, cwd) = output.stdout.trim_end().split_once('|').unwrap();
        assert_eq!(value, "from env");
        assert_eq!(Path::new(cwd), std::fs::canonicalize(dir.path()).unwrap());
    }

    #[test]
    fn a_tool_past_its_limit_is_killed() {
        let started = Instant::now();
        let error = sh("echo before; exec sleep 30", Duration::from_millis(300))
            .run()
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "did not wait for the sleep"
        );
        match error {
            ToolError::Timeout {
                tool,
                timeout,
                stdout,
                ..
            } => {
                assert_eq!(tool, Tool::Sleigh);
                assert_eq!(timeout, Duration::from_millis(300));
                assert_eq!(stdout, "before\n", "output before the kill is kept");
            }
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_binary_is_reported_as_missing() {
        let error = Invocation::new(
            Tool::Pcodedump,
            Path::new("/nonexistent/bin/pcodedump"),
            Duration::from_secs(1),
        )
        .run()
        .unwrap_err();
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
        assert!(
            error.to_string().contains("scripts/build-reference.sh"),
            "{error}"
        );
    }
}
