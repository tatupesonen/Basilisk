//! Skipping tests whose oracle is not on this machine.
//!
//! A test that needs the Ghidra tree or the reference tools starts with
//!
//! ```no_run
//! let Some(reference) = bk_testkit::require_reference() else { return };
//! # let _ = reference;
//! ```
//!
//! When the requirement is met the test runs. When it is not, one line
//! saying what is missing and how to get it is written to standard error and
//! the test returns early — it is reported as passed by the harness, which
//! has no notion of "skipped", so the line is the record. The line is
//! written to the real standard error rather than through `eprintln!`, so
//! the harness's output capture does not hide it.
//!
//! On a machine that is supposed to have everything, set
//! `BASILISK_REQUIRE_REFERENCE=1`: a missing requirement then fails the test
//! instead of skipping it.

use std::fmt;
use std::io::Write as _;
use std::panic::Location;
use std::path::PathBuf;

use crate::paths::{
    self, Environment, GHIDRA_DIR_VAR, GhidraDir, ProcessEnvironment, REFERENCE_DIR_VAR,
    ReferenceDir, Tool,
};

/// Environment variable that turns skips into failures when set to anything
/// but the empty string or `0`.
pub const REQUIRE_VAR: &str = "BASILISK_REQUIRE_REFERENCE";

/// Something a test needs that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Missing {
    /// The Ghidra source tree, expected at this path.
    Ghidra(PathBuf),
    /// The reference directory, expected at this path.
    Reference(PathBuf),
    /// One tool of an otherwise present reference directory.
    Tool(Tool, PathBuf),
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ghidra(path) => write!(
                f,
                "the Ghidra source tree is not at {}; check it out there or set {GHIDRA_DIR_VAR}",
                path.display()
            ),
            Self::Reference(path) => write!(
                f,
                "the reference tools are not at {}; build them with scripts/build-reference.sh \
                 or set {REFERENCE_DIR_VAR}",
                path.display()
            ),
            Self::Tool(tool, path) => write!(
                f,
                "the reference tool `{tool}` is not at {}; build it with \
                 scripts/build-reference.sh",
                path.display()
            ),
        }
    }
}

/// What to do about a missing requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Print the line and return early from the test.
    Skip(String),
    /// Fail the test with this message.
    Fail(String),
}

/// Whether [`REQUIRE_VAR`] asks for skips to be failures.
pub(crate) fn skips_are_failures(env: &dyn Environment) -> bool {
    env.var(REQUIRE_VAR)
        .is_some_and(|value| !value.is_empty() && value != "0")
}

/// Decide between skipping and failing, and word the message.
pub(crate) fn verdict(
    missing: &Missing,
    env: &dyn Environment,
    test: Option<&str>,
    location: &Location<'_>,
) -> Verdict {
    let test = test.unwrap_or("test");
    let at = format!("{}:{}", location.file(), location.line());
    if skips_are_failures(env) {
        Verdict::Fail(format!(
            "{test} ({at}): {missing} ({REQUIRE_VAR} is set, so this is a failure)"
        ))
    } else {
        Verdict::Skip(format!("SKIPPED {test} ({at}): {missing}"))
    }
}

/// Act on a missing requirement: print the skip line, or panic when skips
/// are failures. Panicking is how a test fails; this is test-support code.
#[track_caller]
#[expect(
    clippy::panic,
    reason = "a required oracle that is missing must fail the calling test, and a panic is how a test fails"
)]
fn report(missing: &Missing) {
    let thread = std::thread::current();
    match verdict(
        missing,
        &ProcessEnvironment,
        thread.name(),
        Location::caller(),
    ) {
        Verdict::Skip(line) => {
            // Not `eprintln!`: the test harness captures that for passing
            // tests. One write, so lines from parallel tests do not interleave.
            let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
        }
        Verdict::Fail(message) => panic!("{message}"),
    }
}

/// The Ghidra source tree, or `None` after printing why the calling test is
/// skipped. Panics instead when [`REQUIRE_VAR`] is set.
#[track_caller]
pub fn require_ghidra() -> Option<GhidraDir> {
    let found = paths::ghidra_dir();
    if found.is_none() {
        report(&Missing::Ghidra(paths::expected_ghidra_dir()));
    }
    found
}

/// The reference directory, or `None` after printing why the calling test is
/// skipped. Panics instead when [`REQUIRE_VAR`] is set.
#[track_caller]
pub fn require_reference() -> Option<ReferenceDir> {
    let found = paths::reference_dir();
    if found.is_none() {
        report(&Missing::Reference(paths::expected_reference_dir()));
    }
    found
}

/// The reference directory with `tool` built in it, or `None` after printing
/// why the calling test is skipped. Panics instead when [`REQUIRE_VAR`] is
/// set.
#[track_caller]
pub fn require_tool(tool: Tool) -> Option<ReferenceDir> {
    let reference = require_reference()?;
    if reference.tool(tool).is_none() {
        report(&Missing::Tool(tool, reference.tool_path(tool)));
        return None;
    }
    Some(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::testing::FakeEnvironment;
    use rstest::rstest;

    fn here() -> &'static Location<'static> {
        Location::caller()
    }

    #[rstest]
    #[case(vec![], false)]
    #[case(vec![(REQUIRE_VAR, "1")], true)]
    #[case(vec![(REQUIRE_VAR, "true")], true)]
    #[case(vec![(REQUIRE_VAR, "0")], false)]
    #[case(vec![(REQUIRE_VAR, "")], false)]
    #[case(vec![(GHIDRA_DIR_VAR, "1")], false)]
    fn require_variable(#[case] vars: Vec<(&'static str, &'static str)>, #[case] expected: bool) {
        assert_eq!(skips_are_failures(&FakeEnvironment(vars)), expected);
    }

    #[test]
    fn absent_requirement_is_a_visible_skip() {
        let missing = Missing::Reference(PathBuf::from("/nowhere/reference"));
        let verdict = verdict(&missing, &FakeEnvironment(vec![]), Some("my_test"), here());
        let Verdict::Skip(line) = verdict else {
            panic!("expected a skip, got {verdict:?}")
        };
        assert!(line.starts_with("SKIPPED my_test ("), "{line}");
        assert!(line.contains("skip.rs:"), "names the call site: {line}");
        assert!(line.contains("/nowhere/reference"), "{line}");
        assert!(
            line.contains("scripts/build-reference.sh"),
            "says how to get it: {line}"
        );
        assert!(!line.contains('\n'), "one line: {line}");
    }

    #[test]
    fn absent_requirement_fails_when_required() {
        let missing = Missing::Ghidra(PathBuf::from("/nowhere/ghidra"));
        let env = FakeEnvironment(vec![(REQUIRE_VAR, "1")]);
        let verdict = verdict(&missing, &env, None, here());
        let Verdict::Fail(message) = verdict else {
            panic!("expected a failure, got {verdict:?}")
        };
        assert!(message.contains("/nowhere/ghidra"), "{message}");
        assert!(message.contains(GHIDRA_DIR_VAR), "{message}");
        assert!(message.contains(REQUIRE_VAR), "{message}");
    }

    #[test]
    fn missing_tool_names_the_tool_and_the_script() {
        let text = Missing::Tool(Tool::Pcodedump, PathBuf::from("/ref/bin/pcodedump")).to_string();
        assert!(text.contains("`pcodedump`"), "{text}");
        assert!(text.contains("/ref/bin/pcodedump"), "{text}");
        assert!(text.contains("scripts/build-reference.sh"), "{text}");
    }

    /// The public entry points agree with the path resolution: present means
    /// `Some` (the test really runs), absent means `None`. Which of the two
    /// applies depends on the machine, so this checks consistency only.
    #[test]
    fn present_requirements_are_returned() {
        if std::env::var_os(REQUIRE_VAR).is_some() {
            return; // an absent root would panic by design
        }
        assert_eq!(require_ghidra(), paths::ghidra_dir());
        assert_eq!(require_reference(), paths::reference_dir());
        if let Some(reference) = paths::reference_dir() {
            for tool in Tool::ALL {
                assert_eq!(require_tool(tool).is_some(), reference.tool(tool).is_some());
            }
        }
    }
}
