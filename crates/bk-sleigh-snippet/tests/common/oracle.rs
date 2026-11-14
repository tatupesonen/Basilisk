//! The `snippetdump` oracle (`tools/reference/snippetdump.cc`, record
//! format version 1 in `tools/reference/README.md`) and the same records
//! run through Basilisk.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use bk_sleigh_snippet::{Parameter, SnippetCompiler, SnippetError, TempAllocator};

/// Where a record's temporaries start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Base {
    /// Continue from the carried base.
    Continue,
    /// Set the carried base, then continue from it.
    Start(u32),
    /// Use this base; the carried base is untouched.
    Fixed(u32),
}

/// One snippet to compile.
#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) source: String,
    pub(crate) base: Base,
    pub(crate) body: String,
    pub(crate) params: Vec<Parameter>,
}

/// What a compile gave, in a form both sides produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Compiled: base used, base after, first ignored error (if any), XML.
    Ok {
        base: u32,
        next: u32,
        first_error: Option<String>,
        xml: String,
    },
    /// `parseStream` failed: base used, Ghidra's message.
    Rejected { base: u32, message: String },
    /// An exception escaped: base used, its message.
    Exception { base: u32, message: String },
}

pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn hex(field: &str) -> u32 {
    u32::from_str_radix(field.trim_start_matches("0x"), 16).expect("hex field")
}

/// Runs the oracle on `records` for language `id` under `root`.
pub(crate) fn run_oracle(tool: &Path, root: &Path, id: &str, records: &[Record]) -> Vec<Outcome> {
    let mut input = String::new();
    for r in records {
        input.push_str("S\t");
        input.push_str(&escape(&r.source));
        input.push('\t');
        match r.base {
            Base::Continue => input.push_str("continue"),
            Base::Start(b) => input.push_str(&format!("{b:#x}")),
            Base::Fixed(b) => input.push_str(&format!("fixed:{b:#x}")),
        }
        input.push('\t');
        input.push_str(&escape(&r.body));
        for p in &r.params {
            input.push('\t');
            input.push_str(&escape(&format!("{}:{}", p.index, p.name)));
        }
        input.push('\n');
    }
    let mut child = Command::new(tool)
        .arg(root)
        .arg(id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("snippetdump starts");
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        stdin.write_all(input.as_bytes()).expect("write records");
    });
    let output = child.wait_with_output().expect("snippetdump runs");
    writer.join().expect("writer");
    assert!(
        output.status.success(),
        "snippetdump {id} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("utf-8 output");
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.first().copied() {
            Some("O") => {
                let first = unescape(f[5]);
                out.push(Outcome::Ok {
                    base: hex(f[2]),
                    next: hex(f[3]),
                    first_error: (f[4] == "1").then_some(first),
                    xml: unescape(f[6]),
                });
            }
            Some("F") => {
                let base = hex(f[2]);
                let message = unescape(f[4]);
                out.push(if f[3] == "rejected" {
                    Outcome::Rejected { base, message }
                } else {
                    Outcome::Exception { base, message }
                });
            }
            _ => {}
        }
    }
    assert_eq!(out.len(), records.len(), "one result per record for {id}");
    out
}

/// Runs `records` through Basilisk with the oracle's base rules, starting
/// the carried base at `start`.
pub(crate) fn run_basilisk(
    compiler: &SnippetCompiler,
    start: u32,
    records: &[Record],
) -> Vec<Outcome> {
    let mut carried = TempAllocator::new(start);
    records
        .iter()
        .map(|r| {
            let mut fixed;
            let temps = match r.base {
                Base::Continue => &mut carried,
                Base::Start(b) => {
                    carried = TempAllocator::new(b);
                    &mut carried
                }
                Base::Fixed(b) => {
                    fixed = TempAllocator::new(b);
                    &mut fixed
                }
            };
            let base = temps.next;
            match compiler.compile(&r.body, &r.params, temps) {
                Ok(compiled) => Outcome::Ok {
                    base,
                    next: temps.next,
                    first_error: compiled.warnings.first().cloned(),
                    xml: compiled.template.encode_xml(compiler.space_table()),
                },
                Err(SnippetError::Aborted { message, .. }) => Outcome::Exception { base, message },
                Err(e) => Outcome::Rejected {
                    base,
                    message: e.messages().first().cloned().unwrap_or_default(),
                },
            }
        })
        .collect()
}
