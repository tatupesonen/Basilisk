//! `basilisk sleigh compile` (`features/sleigh-compiler-back.md` 4.6, 4.7,
//! 6.3): exit statuses and messages, output files, `-a`, `-i`, CRLF
//! sources and path spellings; against Ghidra's compiler when the reference
//! tools are present.
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

use std::path::Path;
use std::process::{Command, Output, Stdio};

use bk_sla::{Limits, Sla};

/// A small specification with an include, a subtable and a context field.
const SPEC: &str = "define endian=little;
define alignment=1;
define space ram type=ram_space size=2 default;
define space register type=register_space size=1;
define register offset=0 size=1 [ A X ];
define register offset=8 size=4 [ ctx ];
define context ctx mode=(0,0);
@include \"tok.sinc\"
reg: r is r { export r; }
:ld reg, imm is op=1 & reg; imm { reg = imm; }
:nop is op=0 & r=0 & pad=0 { }
:mov reg is mode=1 & op=2 & reg { reg = 0; }
";

const SINC: &str = "define token ins(8) op=(4,7) r=(0,0) pad=(1,3);
define token data(8) imm=(0,7) spare=(0,3);
attach variables r [ A X ];
";

fn basilisk(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_basilisk"))
        .args(["sleigh", "compile"])
        .args(args)
        .current_dir(dir)
        .env_remove("BASILISK_GHIDRA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn write_spec(dir: &Path, name: &str, crlf: bool) {
    let fix = |t: &str| if crlf { t.replace('\n', "\r\n") } else { t.to_owned() };
    std::fs::write(dir.join(name), fix(SPEC)).unwrap();
    std::fs::write(dir.join("tok.sinc"), fix(SINC)).unwrap();
}

fn inflated(path: &Path) -> Vec<u8> {
    bk_sla::inflate(&std::fs::read(path).unwrap(), &Limits::default()).unwrap()
}

#[test]
fn compiles_with_default_and_explicit_output_names() {
    let dir = tempfile::tempdir().unwrap();
    write_spec(dir.path(), "toy.slaspec", false);
    let o = basilisk(dir.path(), &["toy"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let sla = Sla::read_file(&dir.path().join("toy.sla"), &Limits::default()).unwrap();
    assert!(!sla.symbols().is_empty());
    let o = basilisk(dir.path(), &["toy.slaspec", "out"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(inflated(&dir.path().join("out.sla")), inflated(&dir.path().join("toy.sla")));
    // XML form.
    let o = basilisk(dir.path(), &["-y", "toy.slaspec", "x.sla"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let xml = std::fs::read_to_string(dir.path().join("x.sla")).unwrap();
    assert!(xml.contains("<sleigh "), "{}", &xml[..xml.len().min(80)]);
    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
        .collect();
    assert_eq!(leftovers.len(), 0);
}

#[test]
fn bad_command_lines_and_failures() {
    let dir = tempfile::tempdir().unwrap();
    let o = basilisk(dir.path(), &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).starts_with("USAGE"));
    let o = basilisk(dir.path(), &["-q", "x"]);
    assert_eq!((o.status.code(), stderr(&o)), (Some(1), "Unknown option: -q\n".to_owned()));
    let o = basilisk(dir.path(), &["-l"]);
    assert_eq!((o.status.code(), stderr(&o)), (Some(1), "Missing input file name\n".to_owned()));
    let o = basilisk(dir.path(), &["a", "b", "c"]);
    assert_eq!((o.status.code(), stderr(&o)), (Some(1), "Too many parameters\n".to_owned()));
    let o = basilisk(dir.path(), &["-DX", "a"]);
    assert_eq!((o.status.code(), stderr(&o)), (Some(1), "Bad sleigh option: -DX\n".to_owned()));
    let o = basilisk(dir.path(), &["missing.slaspec"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(stderr(&o), "Unable to open specfile: missing.slaspec\n");
    // A compile error: Ghidra's line format, no output file.
    std::fs::write(dir.path().join("bad.slaspec"), "define endian=little;\n:x is y { }\n").unwrap();
    let o = basilisk(dir.path(), &["bad.slaspec"]);
    assert_eq!(o.status.code(), Some(2));
    let err = stderr(&o);
    assert!(err.contains(" - ERROR "), "{err}");
    assert!(err.ends_with("No output produced\n"), "{err}");
    assert!(!dir.path().join("bad.sla").exists());
}

#[test]
fn options_file_and_unused_field_warning() {
    let dir = tempfile::tempdir().unwrap();
    write_spec(dir.path(), "toy.slaspec", false);
    std::fs::write(dir.path().join("opts.txt"), "# comment\n\n  -f  \n-n\n").unwrap();
    let o = basilisk(dir.path(), &["-i", "opts.txt", "toy.slaspec"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(
        err.contains("WARN  tok.sinc:2: token field 'spare' defined but never used"),
        "{err}"
    );
    assert!(!err.contains("'imm'"), "{err}");
    let o = basilisk(dir.path(), &["-i", "nope.txt", "toy.slaspec"]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn all_mode_continues_after_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("b");
    std::fs::create_dir(&sub).unwrap();
    write_spec(dir.path(), "a.slaspec", false);
    write_spec(&sub, "c.slaspec", false);
    std::fs::write(dir.path().join("b").join("bad.slaspec"), "define endian=little;\n:x is y { }\n")
        .unwrap();
    // Java's form, `-a DIR`.
    let o = basilisk(dir.path(), &["-a", "."]);
    assert_eq!(o.status.code(), Some(255), "{}", stderr(&o));
    assert!(dir.path().join("a.sla").exists());
    assert!(sub.join("c.sla").exists());
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains("Compiling 3 slaspec files in ."), "{out}");
    assert!(out.contains("2 languages successfully compiled"), "{out}");
    assert!(out.contains("1 languages total failed to compile"), "{out}");
    // C++ form, trailing directory.
    let o = basilisk(dir.path(), &["-l", "-a", "b"]);
    assert_eq!(o.status.code(), Some(255));
}

#[test]
fn crlf_sources_and_path_spellings_give_the_same_file() {
    let lf = tempfile::tempdir().unwrap();
    let crlf = tempfile::tempdir().unwrap();
    write_spec(lf.path(), "toy.slaspec", false);
    write_spec(crlf.path(), "toy.slaspec", true);
    let o = basilisk(lf.path(), &["toy.slaspec"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let o = basilisk(crlf.path(), &["toy.slaspec"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(inflated(&lf.path().join("toy.sla")), inflated(&crlf.path().join("toy.sla")));
    // An absolute input with a `..` detour, output in another directory.
    let sub = lf.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let input = sub.join("..").join("toy.slaspec");
    let output = sub.join("again.sla");
    let o = basilisk(
        crlf.path(),
        &[input.to_str().unwrap(), output.to_str().unwrap()],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(inflated(&output), inflated(&lf.path().join("toy.sla")));
}

#[test]
fn messages_and_statuses_match_ghidra() {
    let Some(reference) = bk_testkit::skip::require_tool(bk_testkit::Tool::Sleigh) else {
        return;
    };
    let program = reference.tool(bk_testkit::Tool::Sleigh).unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_spec(dir.path(), "toy.slaspec", false);
    std::fs::write(dir.path().join("bad.slaspec"), "define endian=little;\n:x is y { }\n").unwrap();
    for args in [
        &["-q", "x"][..],
        &["-l"],
        &["a", "b", "c"],
        &["-DX", "a"],
        &["missing.slaspec"],
        &["toy.slaspec", "g.sla"],
    ] {
        let ours = basilisk(dir.path(), args);
        let theirs = Command::new(&program)
            .args(args)
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(ours.status.code(), theirs.status.code(), "{args:?}");
        assert_eq!(stderr(&ours), stderr(&theirs), "{args:?}");
    }
    // Errors: the same text after `FILE:LINE - ` (Ghidra prints its lexer
    // position there, Basilisk the diagnostic's location; spec 4.6).
    let strip = |text: String| -> Vec<String> {
        text.lines()
            .map(|l| l.split_once(" - ERROR ").map_or(l, |(_, m)| m).to_owned())
            .collect()
    };
    std::fs::write(
        dir.path().join("undef.slaspec"),
        format!("{SPEC}:bad A is op=3 {{ }}\n"),
    )
    .unwrap();
    {
        let ours = basilisk(dir.path(), &["undef.slaspec", "u1.sla"]);
        let theirs = Command::new(&program)
            .args(["undef.slaspec", "u2.sla"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert_eq!(ours.status.code(), theirs.status.code());
        assert_eq!(strip(stderr(&ours)), strip(stderr(&theirs)));
    }
    // Both refuse the bad specification with "No output produced".
    let ours = basilisk(dir.path(), &["bad.slaspec"]);
    let theirs = Command::new(&program)
        .arg("bad.slaspec")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(ours.status.code(), theirs.status.code());
    assert!(stderr(&theirs).ends_with("No output produced\n"));
    // Same compiled file.
    let o = basilisk(dir.path(), &["toy.slaspec", "b.sla"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(inflated(&dir.path().join("b.sla")), inflated(&dir.path().join("g.sla")));
}
