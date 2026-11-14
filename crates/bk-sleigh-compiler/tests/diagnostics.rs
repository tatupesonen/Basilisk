//! Spec 6.3: the diagnostics of this half, one small specification per
//! message (`tests/diagnostics/*.slaspec`). Each case's diagnostics are an
//! `insta` snapshot (checked without the reference tools); with the
//! reference compiler present, the success or failure and the multiset of
//! (severity, message) must also equal what Ghidra's C++ `sleigh` prints.
//!
//! A case's first line may be `#! -x -y`: the command-line switches it is
//! compiled with.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::allow_attributes,
    clippy::tests_outside_test_module,
    reason = "test code"
)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use bk_sleigh_compiler::{Options, Severity, elaborate};

fn cases_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("diagnostics")
}

fn cases() -> Vec<PathBuf> {
    let mut list: Vec<PathBuf> = std::fs::read_dir(cases_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "slaspec"))
        .collect();
    list.sort();
    list
}

fn switches(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let first = text.lines().next().unwrap_or("");
    first
        .strip_prefix("#!")
        .map(|rest| rest.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A message without Ghidra's inner `FILE:LINE: ` location, trimmed.
fn normalize(message: &str) -> String {
    let mut text = message.trim_end().to_owned();
    if let Some((head, rest)) = text.split_once(": ")
        && let Some((file, line)) = head.rsplit_once(':')
        && !file.is_empty()
        && !file.contains(' ')
        && line.chars().all(|c| c.is_ascii_digit())
        && !line.is_empty()
    {
        text = rest.to_owned();
    }
    // Ghidra prints two token pointers here, Basilisk the token names.
    let marker = "Mismatched tokens when combining patterns -- ";
    while let Some(at) = text.find(marker) {
        let start = at + marker.len();
        let end = text[start..].find(':').map_or(text.len(), |e| start + e);
        text.replace_range(at..end, "Mismatched tokens <normalized>");
    }
    text
}

/// Cases not compared with Ghidra's C++ compiler, and why.
const NOT_COMPARED: &[(&str, &str)] = &[
    ("pat_unused_field", "-f is an option of Ghidra's Java compiler only"),
    (
        "pat_div_zero",
        "division by zero in a constraint is undefined behaviour in Ghidra's C++ (SIGFPE on x86-64); Basilisk reports an error",
    ),
];

/// Our diagnostics for a case: success, and (severity, message) pairs.
fn ours(path: &Path) -> (bool, Vec<(String, String)>, String) {
    let options = Options::from_switches(switches(path).iter().map(String::as_str));
    let parsed = common::parse(path);
    let outcome = elaborate(&parsed, options);
    let mut list = Vec::new();
    let mut rendered = String::new();
    for d in &parsed.diagnostics {
        let line = format!("parse {:?}: {}", d.severity, d.message);
        rendered.push_str(&line);
        rendered.push('\n');
        list.push(("parse".to_owned(), d.message.clone()));
    }
    for d in &outcome.diagnostics {
        let severity = match d.severity {
            Severity::Error => "error",
            _ => "warning",
        };
        let loc = d
            .span
            .and_then(|s| parsed.sources.locate(s.start))
            .map(|l| {
                format!(
                    " (line {}{})",
                    l.line,
                    if d.located { ", located" } else { "" }
                )
            })
            .unwrap_or_default();
        let _ = writeln!(rendered, "{severity}{loc}: {}", d.message.trim_end());
        list.push((severity.to_owned(), normalize(&d.message)));
    }
    let ok = outcome.spec.is_some();
    rendered.push_str(if ok {
        "=> elaborated\n"
    } else {
        "=> no output\n"
    });
    (ok, list, rendered)
}

/// Cases where Ghidra's compiler dies of a memory error after printing
/// its first messages; Basilisk reports the same messages and then the
/// ones Ghidra never reaches.
const GHIDRA_CRASHES: &[(&str, &str)] = &[
    (
        "constrain_undefined",
        "constrainOperand returns a null equation, which the grammar then combines with `&`",
    ),
    (
        "macro_assign_bitrange",
        "expandMacros deletes the placeholder op and returns without replacing the op list; the dangling op is then used",
    ),
];

/// Ghidra's diagnostics for a case, and whether it was killed by a signal.
fn theirs(
    reference: &bk_testkit::ReferenceDir,
    path: &Path,
) -> (bool, Vec<(String, String)>, bool) {
    let out = std::env::temp_dir().join(format!(
        "bk-diag-{}-{}.sla",
        std::process::id(),
        path.file_stem().unwrap().to_string_lossy()
    ));
    let mut sleigh = reference
        .sleigh()
        .timeout(std::time::Duration::from_mins(1));
    for s in switches(path) {
        if let Some(letter) = s.strip_prefix('-').and_then(|r| r.chars().next()) {
            sleigh = sleigh.switch(letter);
        }
    }
    let (ok, stderr, crashed) = match sleigh.compile(path, &out) {
        Ok(o) => (true, format!("{}{}", o.stdout, o.stderr), false),
        Err(bk_testkit::ToolError::Failed {
            stdout,
            stderr,
            code,
            ..
        }) => {
            // A failed compile ends with "No output produced" or an
            // "Unrecoverable error"; anything else died of a memory error.
            let text = format!("{stdout}{stderr}");
            let crashed = code.is_none()
                || !(text.contains("No output produced") || text.contains("Unrecoverable error"));
            (false, text, crashed)
        }
        Err(e) => panic!("{e}"),
    };
    let _ = std::fs::remove_file(&out);
    let mut list: Vec<(String, String)> = Vec::new();
    for line in stderr.lines() {
        if line == "No output produced" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("WARN  ") {
            list.push(("warning".to_owned(), rest.to_owned()));
        } else if let Some(rest) = line.strip_prefix("Unrecoverable error: ") {
            list.push(("error".to_owned(), rest.to_owned()));
        } else if let Some((_, rest)) = line.split_once(" - ERROR ") {
            list.push(("error".to_owned(), rest.to_owned()));
        } else if let Some(last) = list.last_mut() {
            last.1.push('\n');
            last.1.push_str(line);
        }
    }
    let list = list.into_iter().map(|(s, m)| (s, normalize(&m))).collect();
    (ok, list, crashed)
}

#[test]
fn diagnostics_match_snapshots_and_ghidra() {
    let reference =
        bk_testkit::reference_dir().filter(|r| r.tool(bk_testkit::Tool::Sleigh).is_some());
    if reference.is_none() {
        eprintln!(
            "SKIPPED (oracle part only): reference sleigh compiler not found; comparing with snapshots"
        );
    }
    let mut mismatches = Vec::new();
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(cases_dir().join("snapshots"));
    settings.set_prepend_module_to_snapshot(false);
    let _guard = settings.bind_to_scope();
    for case in cases() {
        let name = case.file_stem().unwrap().to_string_lossy().into_owned();
        let (ok, mut list, rendered) = ours(&case);
        insta::assert_snapshot!(name.clone(), rendered);
        if let Some(reference) = reference
            .as_ref()
            .filter(|_| !NOT_COMPARED.iter().any(|(n, _)| *n == name))
        {
            let (their_ok, mut their_list, crashed) = theirs(reference, &case);
            list.sort();
            their_list.sort();
            let expect_crash = GHIDRA_CRASHES.iter().any(|(n, _)| *n == name);
            let agree = if crashed {
                // Everything Ghidra printed before dying must be ours too.
                let mut rest = list.clone();
                expect_crash
                    && !ok
                    && their_list.iter().all(|m| {
                        rest.iter()
                            .position(|o| o == m)
                            .map(|i| rest.remove(i))
                            .is_some()
                    })
            } else {
                !expect_crash && ok == their_ok && list == their_list
            };
            if !agree {
                mismatches.push(format!("{name}: ours ok={ok} {list:#?}\n  Ghidra ok={their_ok} crashed={crashed} {their_list:#?}"));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} cases differ from Ghidra:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The messages of this half (inventory 9, 10 d, 10 c.5) that every case
/// set must cover: each pattern must occur in at least one snapshot.
const MESSAGES: &[&str] = &[
    "Duplicate symbol name: ",
    ": redefined as a token",
    ": redefined as field",
    ": redefined as space",
    ": redefined",
    "token size must be multiple of 8",
    "' starts at ",
    "high must be less than token size",
    "Context field '",
    "high must be less than context size",
    "All context definitions must come before constructors",
    "must be a multiple of 4 bytes",
    "larger than 32 bits",
    "extends beyond the size of context register",
    "missing size attribute",
    "Multiple default spaces",
    "Parsed integer is too big (overflow)",
    "size of bitrange is zero",
    "bad bitrange",
    "list contains duplicate entries",
    "is wrong size for list",
    "Attach statement contains varnodes of different sizes",
    "is not a value pattern",
    "is not a varnode symbol",
    "Unexpected '^' at start of print pieces",
    "Constraining currently undefined operand",
    "No matching global symbol",
    "Redefining operand",
    "Cannot use 'inst_next' or 'inst_next2' to set context variable",
    "is not allowed in action expression",
    "Expecting context symbol, not",
    "Unknown varnode parameter",
    "Unknown assignment varnode",
    "Unknown export varnode",
    "Unknown jump destination",
    "Subtable not attached to operand",
    "Redefinition of symbol",
    "Illegal truncation on left-hand side of assignment",
    "Illegal subpiece on left-hand side of assignment",
    "Must use 'local' keyword to define symbol",
    "Multiple delayslot declarations",
    "Must be at least two inputs to cpool",
    "is placed more than once",
    "Size of bitrange is zero",
    "Bitrange is bad",
    "Illegal masked bitrange producing varnode larger than 64 bits",
    "Requested bit range out of bounds",
    "Assigned bitrange is bad",
    "Assigning to bitrange is superfluous",
    "Assigned bitrange extends past first 64 bits",
    "Localtemp size mismatch",
    "passes too many parameters",
    "passes too few parameters",
    "In definition of macro",
    "Could not expand submacro in definition of macro",
    "Cannot currently assign to bitrange of macro parameter that is a temporary",
    "constructor starting at line",
    "was placed but not used",
    "was referenced but never placed",
    "Could not expand macros",
    "Duplicate BUILD statements",
    "Unnecessary BUILD statements",
    "Could not resolve at least 1 variable size",
    "Cannot have export statement in root constructor",
    "Size of export is unknown",
    "Delay slot used in non-root constructor",
    "NOP constructors found",
    "Use -n switch to list each individually",
    "NOP detected",
    "Name collision: ",
    "No default space specified",
    "Using subtable with exports in expression",
    "Input and output sizes must match",
    "The output and all input sizes must match",
    "Output must be a boolean (size 1)",
    "Inputs must be the same size",
    "Input must be a boolean (size 1)",
    "Output and first input must be the same size",
    "Output size must be strictly bigger than input size",
    "Pointer size must match size of space",
    "Output must be strictly smaller than input",
    "Too much truncation",
    "exports inconsistently",
    "has inconsistent export size",
    "exports size 0",
    "Unnecessary Zero extension(zext)",
    "unnecessary extensions/truncations were converted to copies",
    "Use -u switch to list each individually",
    "Unsigned comparison with zero is always false",
    "Truncation operator out of bounds",
    "No register attached to",
    "Temporary is read but not written",
    "Temporary is written but not read",
    "operations wrote to temporaries that were not read",
    "Use -t switch to list each individually",
    "Constructor uses temporary varnode larger than 256 bytes.",
    "constructors with local collisions between operands",
    "Use -c switch to list each individually",
    "Possible operand collision between symbols",
    "Unreferenced table",
    "Duplicate (offset,size) pair for registers",
    "syntax error",
    // The back half (inventory 10 a–c).
    "Impossible pattern",
    "Equal constraint is impossible to match",
    "Less than constraint is impossible to match",
    "Less than or equal constraint is impossible to match",
    "Greater than constraint is impossible to match",
    "Greater than or equal constraint is impossible to match",
    "Interior ellipsis in pattern",
    "Double ellipsis in pattern",
    "Right/left ellipsis",
    "Left/right ellipsis",
    "Mismatched pattern sizes -- ",
    "Pattern size cannot vary (missing '...'?)",
    "Mismatched tokens when combining patterns -- ",
    "Operand used in pattern expression",
    "Unable to resolve operand offsets",
    "cannot be used in context expression",
    "Problem in table '",
    "Constructor has identical pattern to constructor at ",
    "Constructor pattern cannot be distinguished from constructor at ",
    "There are no constructors in table: ",
    "token field 'imm' defined but never used",
    "Division by zero in pattern expression",
    "Illegal recursion",
];

#[test]
fn every_message_has_a_case() {
    let mut all = String::new();
    for case in cases() {
        all.push_str(&ours(&case).2);
    }
    let missing: Vec<&str> = MESSAGES
        .iter()
        .copied()
        .filter(|m| !all.contains(m))
        .collect();
    assert!(missing.is_empty(), "messages without a case: {missing:#?}");
}
