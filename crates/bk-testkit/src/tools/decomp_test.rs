//! Ghidra's decompiler test runner (`test.cc`, `testfunction.cc`): the C++
//! unit tests compiled into it, and the data tests it reads from XML.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::process::Invocation;
use super::{ToolError, ToolOutput};
use crate::paths::Tool;

/// Runs `bin/decomp_test`. Obtain one with [`crate::ReferenceDir::decomp_test`].
///
/// The runner's exit code is its number of failed tests, so a non-zero exit
/// is a result, not an error: look at the report.
#[derive(Debug, Clone)]
pub struct DecompTest {
    program: PathBuf,
    sleigh_root: PathBuf,
    timeout: Duration,
}

/// The result of one test or check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestOutcome {
    /// A unit test's name, or the `name` of a data test's `<stringmatch>`.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// What the runner said about a failure, when it said anything.
    pub detail: Option<String>,
}

/// The runner's report on its unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitTestReport {
    /// One entry per test run, in the runner's order.
    pub tests: Vec<TestOutcome>,
    /// How many passed, from the runner's summary line.
    pub passed: usize,
    /// How many ran, from the runner's summary line.
    pub total: usize,
    /// The raw output and timing of the run.
    pub output: ToolOutput,
}

/// The runner's report on data tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTestReport {
    /// One entry per `<stringmatch>` applied, in the runner's order. When
    /// several files are run the entries are not labelled by file; run one
    /// file at a time to attribute them.
    pub checks: Vec<TestOutcome>,
    /// How many checks were applied, from the runner's totals.
    pub applied: usize,
    /// How many passed, from the runner's totals.
    pub passed: usize,
    /// Files whose checks could not be applied at all (the file did not
    /// parse, its script failed, or it printed nothing). The runner does not
    /// count these in its totals.
    pub errors: Vec<String>,
    /// The raw output and timing of the run.
    pub output: ToolOutput,
}

impl UnitTestReport {
    /// The tests that failed.
    pub fn failures(&self) -> impl Iterator<Item = &TestOutcome> {
        self.tests.iter().filter(|test| !test.passed)
    }
}

impl DataTestReport {
    /// Whether every check was applied and passed.
    pub fn all_passed(&self) -> bool {
        self.errors.is_empty() && self.passed == self.applied
    }

    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &TestOutcome> {
        self.checks.iter().filter(|check| !check.passed)
    }
}

/// Why the runner's output is not a report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReportParseError {
    /// The summary the runner ends with is absent: it crashed or was cut short.
    #[error("no `{expected}` line; the runner did not finish")]
    MissingSummary {
        /// The line that should be there.
        expected: &'static str,
    },
    /// The summary disagrees with the individual results before it.
    #[error(
        "summary says {summary_passed} of {summary_total} passed, but the lines before it show {passed} of {total}"
    )]
    CountMismatch {
        /// Passed count in the summary.
        summary_passed: usize,
        /// Total in the summary.
        summary_total: usize,
        /// Passed results seen.
        passed: usize,
        /// Results seen.
        total: usize,
    },
}

impl DecompTest {
    /// All 760 data-test checks take a few seconds; this allows for a slow
    /// machine.
    const DEFAULT_TIMEOUT: Duration = Duration::from_mins(10);

    pub(crate) fn new(program: PathBuf, sleigh_root: PathBuf) -> Self {
        Self {
            program,
            sleigh_root,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Replace the time limit of one run.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn invocation(&self) -> Invocation<'_> {
        Invocation::new(Tool::DecompTest, &self.program, self.timeout)
            .arg("-sleighpath")
            .arg(&self.sleigh_root)
    }

    /// Run the named unit tests, or all of them when `names` is empty. A
    /// name the runner does not know is ignored by it: compare the report's
    /// `total` with what was asked for.
    pub fn run_unit_tests<I, S>(&self, names: I) -> Result<UnitTestReport, ToolError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut invocation = self.invocation().arg("unittests");
        invocation.args.extend(names.into_iter().map(Into::into));
        let output = invocation.run()?;
        // Unit-test progress goes to standard error.
        let (tests, passed, total) = parse_unit_tests(&output.stderr)?;
        Ok(UnitTestReport {
            tests,
            passed,
            total,
            output,
        })
    }

    /// Run data-test files of `dir` by file name (`"deadvolatile.xml"`), or
    /// every `.xml` file in it when `files` is empty.
    pub fn run_data_tests<I, S>(&self, dir: &Path, files: I) -> Result<DataTestReport, ToolError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut invocation = self.invocation().arg("-path").arg(dir).arg("datatests");
        for file in files {
            let file = file.as_ref();
            // The runner silently skips names that match no file.
            if !dir.join(file).is_file() {
                return Err(ToolError::Io {
                    tool: Tool::DecompTest,
                    source: io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no data test {file} in {}", dir.display()),
                    ),
                });
            }
            invocation = invocation.arg(file);
        }
        let output = invocation.run()?;
        let (checks, applied, passed, errors) = parse_data_tests(&output.stdout)?;
        Ok(DataTestReport {
            checks,
            applied,
            passed,
            errors,
            output,
        })
    }

    /// Run one data-test file.
    pub fn run_data_test(&self, file: &Path) -> Result<DataTestReport, ToolError> {
        let not_a_file = || ToolError::Unsupported {
            tool: Tool::DecompTest,
            reason: format!("{} is not the path of a data-test file", file.display()),
        };
        let dir = file
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .ok_or_else(not_a_file)?;
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(not_a_file)?;
        self.run_data_tests(dir, [name])
    }
}

/// Parse the unit-test progress the runner writes: `testing : NAME ...`,
/// then `  passed.` or — after the failed assertion's own `  failed at …`
/// line — `  fail` or `  fail: REASON`; finally `P/T tests passed.`.
fn parse_unit_tests(text: &str) -> Result<(Vec<TestOutcome>, usize, usize), ReportParseError> {
    let mut tests = Vec::new();
    let mut current: Option<&str> = None;
    let mut assertion: Option<&str> = None;
    let mut summary = None;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("testing : ") {
            current = Some(name.strip_suffix(" ...").unwrap_or(name));
            assertion = None;
        } else if line == "  passed." {
            if let Some(name) = current.take() {
                tests.push(TestOutcome {
                    name: name.to_owned(),
                    passed: true,
                    detail: None,
                });
            }
        } else if let Some(reason) = line.strip_prefix("  fail") {
            if reason.is_empty() || reason.starts_with(':') {
                if let Some(name) = current.take() {
                    let reason = reason.trim_start_matches(':').trim();
                    let detail = assertion.take().or((!reason.is_empty()).then_some(reason));
                    tests.push(TestOutcome {
                        name: name.to_owned(),
                        passed: false,
                        detail: detail.map(str::to_owned),
                    });
                }
            } else if line.starts_with("  failed at ") {
                assertion = Some(line.trim());
            }
        } else if let Some(counts) = line.strip_suffix(" tests passed.")
            && let Some((passed, total)) = counts.split_once('/')
            && let (Ok(passed), Ok(total)) = (passed.parse(), total.parse())
        {
            summary = Some((passed, total));
        }
    }
    let (summary_passed, summary_total) = summary.ok_or(ReportParseError::MissingSummary {
        expected: "N/M tests passed.",
    })?;
    let passed = tests.iter().filter(|test| test.passed).count();
    if (summary_passed, summary_total) != (passed, tests.len()) {
        return Err(ReportParseError::CountMismatch {
            summary_passed,
            summary_total,
            passed,
            total: tests.len(),
        });
    }
    Ok((tests, summary_passed, summary_total))
}

/// The parts of a data-test report: checks, applied, passed, errors.
type DataTestParts = (Vec<TestOutcome>, usize, usize, Vec<String>);

/// Parse the data-test report the runner writes: `Success -- NAME` or
/// `FAIL -- NAME` per check, error lines for files it could not run, the two
/// totals, and a `Failures:` list. The list is capped at ten entries, so it
/// is used only for what appears nowhere else.
fn parse_data_tests(text: &str) -> Result<DataTestParts, ReportParseError> {
    let mut checks = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut applied = None;
    let mut passing = None;
    let mut in_failure_list = false;
    for line in text.lines() {
        if in_failure_list {
            // Script failures were already seen inline; the list is the only
            // place a file that printed nothing is mentioned.
            let entry = line.trim();
            let listed_only =
                entry.starts_with("Execution failed for ") || entry.starts_with("No output for ");
            if listed_only && !errors.iter().any(|error| error == entry) {
                errors.push(entry.to_owned());
            }
        } else if let Some(file) = line.strip_prefix("Error: Did not apply tests in ") {
            // Worded as the failure list words it, so the two can be matched.
            errors.push(format!("Execution failed for {file}"));
        } else if let Some(name) = line.strip_prefix("Success -- ") {
            checks.push(TestOutcome {
                name: name.to_owned(),
                passed: true,
                detail: None,
            });
        } else if let Some(name) = line.strip_prefix("FAIL -- ") {
            checks.push(TestOutcome {
                name: name.to_owned(),
                passed: false,
                detail: None,
            });
        } else if line.starts_with("Error parsing ") || line.starts_with("Error executing ") {
            errors.push(line.to_owned());
        } else if let Some(count) = line.strip_prefix("Total tests applied = ") {
            applied = count.trim().parse().ok();
        } else if let Some(count) = line.strip_prefix("Total passing tests = ") {
            passing = count.trim().parse().ok();
        } else if line.trim_end() == "Failures:" {
            in_failure_list = true;
        }
    }
    let applied: usize = applied.ok_or(ReportParseError::MissingSummary {
        expected: "Total tests applied = N",
    })?;
    let passing: usize = passing.ok_or(ReportParseError::MissingSummary {
        expected: "Total passing tests = N",
    })?;
    let passed = checks.iter().filter(|check| check.passed).count();
    if (passing, applied) != (passed, checks.len()) {
        return Err(ReportParseError::CountMismatch {
            summary_passed: passing,
            summary_total: applied,
            passed,
            total: checks.len(),
        });
    }
    Ok((checks, applied, passing, errors))
}

#[cfg(test)]
mod tests;
