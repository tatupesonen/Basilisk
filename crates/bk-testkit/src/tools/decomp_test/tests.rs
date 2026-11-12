//! Tests for the `decomp_test` wrapper and its report parsers.

use super::*;

const UNIT_OUTPUT: &str = "\
testing : float_decimal_precision ...
  passed.
testing : double_decimal_precision ...
  failed at ../unittests/testfloatemu.cc:187 asserting \"1.7e+308 == 1.79e+308\".
  fail
testing : marshal_bad ...
  fail: Unexpected end of stream
testing : float_opNan ...
  passed.
==============================
2/4 tests passed.
";

#[test]
fn unit_test_progress_is_parsed() {
    let (tests, passed, total) = parse_unit_tests(UNIT_OUTPUT).unwrap();
    assert_eq!((passed, total), (2, 4));
    let names: Vec<_> = tests
        .iter()
        .map(|test| (test.name.as_str(), test.passed))
        .collect();
    assert_eq!(
        names,
        [
            ("float_decimal_precision", true),
            ("double_decimal_precision", false),
            ("marshal_bad", false),
            ("float_opNan", true)
        ]
    );
    assert_eq!(
        tests[1].detail.as_deref(),
        Some("failed at ../unittests/testfloatemu.cc:187 asserting \"1.7e+308 == 1.79e+308\".")
    );
    assert_eq!(tests[2].detail.as_deref(), Some("Unexpected end of stream"));
    assert_eq!(tests[0].detail, None);
}

#[test]
fn unit_test_report_needs_its_summary() {
    let cut_short = "testing : a ...\n  passed.\ntesting : b ...\n";
    assert_eq!(
        parse_unit_tests(cut_short).unwrap_err(),
        ReportParseError::MissingSummary {
            expected: "N/M tests passed."
        }
    );
    let disagreeing = "testing : a ...\n  passed.\n==\n2/2 tests passed.\n";
    assert!(matches!(
        parse_unit_tests(disagreeing).unwrap_err(),
        ReportParseError::CountMismatch {
            summary_total: 2,
            total: 1,
            ..
        }
    ));
    assert_eq!(
        parse_unit_tests("==\n0/0 tests passed.\n").unwrap(),
        (Vec::new(), 0, 0)
    );
}

const DATA_OUTPUT: &str = "

Success -- Float print #5
FAIL -- Float print #6
Error: Did not apply tests in /d/broken.xml
Execution error: No function selected

Error parsing /d/bad.xml: Did not see <script> tag in <decompilertest>
Error executing /d/arch.xml: Error during architecture initialization: nope
Success -- Long double #1

Total tests applied = 3
Total passing tests = 2

Failures:
  Float print #6
  Execution failed for /d/broken.xml
  Error parsing /d/bad.xml: Did not see <script> tag in <decompilertest>
  Error executing /d/arch.xml: Error during architecture initialization: nope
  No output for /d/silent.xml
";

#[test]
fn data_test_report_is_parsed() {
    let (checks, applied, passed, errors) = parse_data_tests(DATA_OUTPUT).unwrap();
    assert_eq!((applied, passed), (3, 2));
    let seen: Vec<_> = checks
        .iter()
        .map(|check| (check.name.as_str(), check.passed))
        .collect();
    assert_eq!(
        seen,
        [
            ("Float print #5", true),
            ("Float print #6", false),
            ("Long double #1", true)
        ]
    );
    assert_eq!(
        errors,
        [
            "Execution failed for /d/broken.xml",
            "Error parsing /d/bad.xml: Did not see <script> tag in <decompilertest>",
            "Error executing /d/arch.xml: Error during architecture initialization: nope",
            "No output for /d/silent.xml",
        ],
        "each unrunnable file once"
    );
}

#[test]
fn data_test_report_needs_its_totals() {
    assert_eq!(
        parse_data_tests("Success -- a\n").unwrap_err(),
        ReportParseError::MissingSummary {
            expected: "Total tests applied = N"
        }
    );
    assert_eq!(
        parse_data_tests("Success -- a\nTotal tests applied = 1\n").unwrap_err(),
        ReportParseError::MissingSummary {
            expected: "Total passing tests = N"
        }
    );
    let disagreeing = "Success -- a\nTotal tests applied = 2\nTotal passing tests = 2\n";
    assert!(matches!(
        parse_data_tests(disagreeing).unwrap_err(),
        ReportParseError::CountMismatch {
            summary_total: 2,
            total: 1,
            ..
        }
    ));
}

#[test]
fn reports_summarise_themselves() {
    let output = ToolOutput {
        code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
        elapsed: Duration::ZERO,
    };
    let (checks, applied, passed, _) = parse_data_tests(DATA_OUTPUT).unwrap();
    let mut report = DataTestReport {
        checks,
        applied,
        passed,
        errors: Vec::new(),
        output: output.clone(),
    };
    assert!(!report.all_passed());
    assert_eq!(report.failures().count(), 1);
    report.checks.retain(|check| check.passed);
    report.applied = 2;
    assert!(report.all_passed());
    report.errors.push("No output for x".to_owned());
    assert!(!report.all_passed(), "an unrunnable file is not a pass");

    let (tests, passed, total) = parse_unit_tests(UNIT_OUTPUT).unwrap();
    let report = UnitTestReport {
        tests,
        passed,
        total,
        output,
    };
    let failed: Vec<_> = report.failures().map(|test| test.name.as_str()).collect();
    assert_eq!(failed, ["double_decimal_precision", "marshal_bad"]);
}

#[test]
fn a_data_test_that_is_not_there_is_an_error() {
    let runner = DecompTest::new(
        PathBuf::from("/nonexistent/decomp_test"),
        PathBuf::from("/r"),
    );
    let dir = tempfile::tempdir().unwrap();
    let error = runner
        .run_data_tests(dir.path(), ["missing.xml"])
        .unwrap_err();
    assert!(
        error.to_string().contains("no data test missing.xml"),
        "{error}"
    );
    let error = runner.run_data_test(Path::new("/")).unwrap_err();
    assert!(matches!(error, ToolError::Unsupported { .. }), "{error:?}");
}
