//! `basilisk disasm` (`features/sleigh-pcode.md` 4.7): help text, exit
//! statuses, and output equal to `pcodedump`'s — against the recorded
//! oracle output of the `bkpc` fixture language everywhere, and against the
//! live oracle when the reference tools are present.
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

#[path = "../../bk-sleigh/tests/fixture/mod.rs"]
mod fixture;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn basilisk(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_basilisk"))
        .arg("disasm")
        .args(args)
        .env_remove("BASILISK_GHIDRA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn s(text: &str) -> &std::ffi::OsStr {
    text.as_ref()
}

/// A directory with Ghidra's layout holding the `bkpc` language.
fn language_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let languages = dir
        .path()
        .join("Ghidra")
        .join("Processors")
        .join("BkPcode")
        .join("data")
        .join("languages");
    std::fs::create_dir_all(&languages).unwrap();
    fixture::pcode::write_language_dir(&languages);
    // The registry wants every file a language names.
    std::fs::write(
        languages.join("bkpc.cspec"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<compiler_spec>\n</compiler_spec>\n",
    )
    .unwrap();
    dir
}

#[test]
fn help_and_exit_statuses() {
    let help = basilisk(&[s("--help")]);
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(
        text.starts_with("USAGE: basilisk disasm --language <id>"),
        "{text}"
    );
    for option in [
        "--root",
        "--base",
        "--context",
        "--hex",
        "--format",
        "--no-pcode",
        "--quiet",
        "--timing",
    ] {
        assert!(text.contains(option), "{option}");
    }
    // Bad command lines: 2.
    for args in [
        vec![s("--hex"), s("00")],
        vec![s("--language"), s("x:LE:32:d"), s("--bogus")],
        vec![s("--language"), s("x:LE:32:d"), s("--hex"), s("0")],
        vec![s("--language"), s("x:LE:32:d"), s("--format"), s("xml")],
        vec![
            s("--language"),
            s("x:LE:32:d"),
            s("--context"),
            s("novalue"),
        ],
    ] {
        assert_eq!(basilisk(&args).status.code(), Some(2), "{args:?}");
    }
    // A language that cannot be loaded: 1.
    let root = language_root();
    let r = root.path().as_os_str();
    for args in [
        vec![
            s("--language"),
            s("Nope:LE:32:default"),
            s("--root"),
            r,
            s("--hex"),
            s("00"),
        ],
        vec![
            s("--language"),
            s("BkPcode:BE:32:default"),
            s("--hex"),
            s("00"),
        ],
        vec![
            s("--language"),
            s("BkPcode:BE:32:default"),
            s("--root"),
            r,
            s("--context"),
            s("nosuch=1"),
            s("--hex"),
            s("00"),
        ],
    ] {
        assert_eq!(basilisk(&args).status.code(), Some(1), "{args:?}");
    }
}

/// The recorded block of `pcodedump` output for the stream at `base`.
fn recorded(base: &str) -> (String, String) {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../bk-sleigh/tests/data/pcode-fixture-oracle.txt"),
    )
    .unwrap();
    let mut lines = text
        .lines()
        .skip_while(|l| !l.starts_with(&format!("stream\t{base}\t")));
    lines.next().expect("stream recorded");
    let bytes = lines
        .next()
        .unwrap()
        .strip_prefix("bytes\t")
        .unwrap()
        .to_owned();
    let mut out = String::new();
    for line in lines.take_while(|l| *l != "end") {
        out.push_str(line);
        out.push('\n');
    }
    (bytes, out)
}

#[test]
fn output_equals_recorded_pcodedump() {
    let root = language_root();
    for base in ["0x2040", "0x2060", "0x2080", "0x2000"] {
        let (bytes, expected) = recorded(base);
        let out = basilisk(&[
            s("--language"),
            s("BkPcode:BE:32:default"),
            s("--root"),
            root.path().as_os_str(),
            s("--base"),
            s(base),
            s("--hex"),
            s(&bytes),
        ]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        let (header, rest) = text.split_once('\n').unwrap();
        assert_eq!(
            header,
            format!(
                "H\t1\tBkPcode:BE:32:default\tram\t{base}\t{}",
                bytes.len() / 2
            )
        );
        assert_eq!(rest, expected, "stream {base}");
    }
}

#[test]
fn text_listing_and_options() {
    let root = language_root();
    let base = [
        s("--language"),
        s("BkPcode:BE:32:default"),
        s("--root"),
        root.path().as_os_str(),
        s("--hex"),
        s("0112 0221 0e00"),
    ];
    let mut args = base.to_vec();
    args.extend([s("--format"), s("text")]);
    let text = String::from_utf8(basilisk(&args).stdout).unwrap();
    assert!(text.contains("0x0  01 12"), "{text}");
    assert!(text.contains("add r1,r2"), "{text}");
    assert!(text.contains("(register,0x4,4,r1) = INT_ADD"), "{text}");
    assert!(text.contains("!! unimplemented"), "{text}");
    let mut args = base.to_vec();
    args.push(s("--no-pcode"));
    let text = String::from_utf8(basilisk(&args).stdout).unwrap();
    assert!(!text.contains("\nP\t") && !text.contains("\nU\t"), "{text}");
    let mut args = base.to_vec();
    args.extend([s("--quiet"), s("--timing")]);
    let out = basilisk(&args);
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 2);
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.starts_with("timing\tload_seconds="), "{err}");
    assert!(err.contains("instructions=3\tops="), "{err}");
}

#[test]
fn reads_files_and_standard_input_in_binary() {
    let root = language_root();
    let file = root.path().join("code.bin");
    std::fs::write(&file, [0x01, 0x12, 0x0d, 0x0a]).unwrap();
    let args = [
        s("--language"),
        s("BkPcode:BE:32:default"),
        s("--root"),
        root.path().as_os_str(),
    ];
    let mut with_file = args.to_vec();
    with_file.push(file.as_os_str());
    let a = basilisk(&with_file);
    let mut child = Command::new(env!("CARGO_BIN_EXE_basilisk"))
        .arg("disasm")
        .args(args)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0x01, 0x12, 0x0d, 0x0a])
        .unwrap();
    let b = child.wait_with_output().unwrap();
    assert_eq!(a.stdout, b.stdout);
    // 0d 0a is not turned into a newline: `cst` needs four bytes.
    let text = String::from_utf8(a.stdout).unwrap();
    assert!(text.contains("truncated"), "{text}");
}

/// Byte-for-byte equality with the live oracle on a real language.
#[test]
fn output_equals_live_pcodedump() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Pcodedump) else {
        return;
    };
    let hex = "554889e54883ec10897dfc8b45fc83c0015dc3e8000000000f0b";
    let ours = basilisk(&[
        s("--language"),
        s("x86:LE:64:default"),
        s("--root"),
        reference.root().as_os_str(),
        s("--base"),
        s("0x1000"),
        s("--hex"),
        s(hex),
    ]);
    assert_eq!(ours.status.code(), Some(0));
    let theirs = Command::new(reference.tool_path(bk_testkit::Tool::Pcodedump))
        .arg(reference.root())
        .args(["x86:LE:64:default", "0x1000", "--hex", hex])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(ours.stdout).unwrap(),
        String::from_utf8(theirs.stdout).unwrap()
    );
}
