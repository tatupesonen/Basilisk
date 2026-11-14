//! `bk-oracle`: the decompiler oracle's capture driver
//! (`docs/features/decomp-oracle.md` 5.3, 6). Needs the reference tools
//! with Basilisk's console extension and the Ghidra tree (Unix: the
//! reference tools are).
//!
//! ```text
//! bk-oracle capture <datatests|research|all> <out> [--runs N] [--only TEXT]
//!     captures every script N times (default 2) into <out>/run<i>, requires
//!     the runs to be byte-identical, writes <out>/summary.txt and
//!     <out>/captures.<library>.txt (a digest per capture file)
//! bk-oracle compare <capture-dir-1> <capture-dir-2> [--write FILE]
//!     the captures of two reference builds: every differing file must
//!     differ only by named causes; the counts per file and cause are
//!     printed (and written)
//! bk-oracle check <out> <fixtures-dir>
//!     the drift of a capture against the checked-in fixtures, by file
//! ```

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the binary's job is to print"
)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use bk_testkit::oracle::capture::{self, CaptureReport};
use bk_testkit::oracle::host::{self, Library};
use bk_testkit::oracle::read_text;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn usage() -> ExitCode {
    eprintln!(
        "usage: bk-oracle capture <datatests|research|all> <out> [--runs N] [--only TEXT]\n       \
         bk-oracle compare <capture-dir-1> <capture-dir-2> [--write FILE]\n       \
         bk-oracle check <out> <fixtures-dir>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("capture") => cmd_capture(args.get(1..).unwrap_or(&[])),
        Some("compare") => cmd_compare(args.get(1..).unwrap_or(&[])),
        Some("check") => cmd_check(args.get(1..).unwrap_or(&[])),
        _ => return usage(),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("bk-oracle: {e}");
            ExitCode::from(1)
        }
    }
}

/// The value after `--name`, if given.
fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn cmd_capture(args: &[String]) -> Result<bool> {
    let (Some(corpus), Some(out)) = (args.first(), args.get(1)) else {
        return Err("capture needs a corpus and an output directory".into());
    };
    let runs: usize = option(args, "--runs").map_or(Ok(2), str::parse)?;
    let only = option(args, "--only");
    let reference =
        bk_testkit::reference_dir().ok_or("no reference directory (BASILISK_REFERENCE_DIR)")?;
    let ghidra = bk_testkit::ghidra_dir().ok_or("no Ghidra tree (BASILISK_GHIDRA_DIR)")?;
    let library = Library::of_reference(&reference).ok_or("the reference STAMP names no host")?;
    let mut scripts = Vec::new();
    if corpus == "datatests" || corpus == "all" {
        scripts.extend(capture::data_tests(&ghidra)?);
    }
    if corpus == "research" || corpus == "all" {
        scripts.extend(capture::research(&bk_testkit::workspace_root())?);
    }
    if scripts.is_empty() {
        return Err(format!("unknown corpus {corpus}").into());
    }
    if let Some(text) = only {
        scripts.retain(|s| s.name.contains(text));
    }
    let positions = capture::find_positions(&reference, &ghidra)?;
    // Absolute: the consoles run in the corpus directory.
    std::fs::create_dir_all(out)?;
    let out = std::fs::canonicalize(out)?;
    let mut first: Option<(CaptureReport, BTreeMap<String, u64>)> = None;
    let mut ok = true;
    for run in 1..=runs.max(1) {
        let dir = out.join(format!("run{run}"));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        let started = std::time::Instant::now();
        let report = capture::capture_corpus(&reference, &scripts, &positions, &dir);
        let digests = host::digest_tree(&dir)?;
        println!(
            "run {run}: {} scripts, {} files, {} errors, {:.1} s",
            report.scripts.len(),
            digests.len(),
            report.errors().len(),
            started.elapsed().as_secs_f64()
        );
        match &first {
            None => first = Some((report, digests)),
            Some((_, d1)) => {
                let diff = host::diff_tables(d1, &digests);
                if !diff.is_empty() {
                    ok = false;
                    println!(
                        "run {run} differs from run 1 (Ghidra's output is not deterministic):"
                    );
                    for p in diff
                        .changed
                        .iter()
                        .chain(&diff.only_first)
                        .chain(&diff.only_second)
                    {
                        println!("  {p}");
                    }
                }
            }
        }
    }
    let Some((report, digests)) = first else {
        return Ok(false);
    };
    std::fs::write(out.join("summary.txt"), report.summary())?;
    std::fs::write(
        out.join(format!("captures.{}.txt", library.name())),
        host::write_digests(&digests),
    )?;
    let verbose = std::env::var_os("BK_ORACLE_VERBOSE").is_some();
    for e in report.errors() {
        ok = false;
        if verbose {
            let lines: Vec<&str> = e.lines().collect();
            let tail = lines.len().saturating_sub(12);
            println!("error: {}", lines.first().unwrap_or(&""));
            for l in lines.get(tail.max(1)..).unwrap_or(&[]) {
                println!("    {l}");
            }
        } else {
            println!("error: {}", e.lines().next().unwrap_or(""));
        }
    }
    println!("{}", report.summary().lines().last().unwrap_or(""));
    Ok(ok)
}

fn cmd_compare(args: &[String]) -> Result<bool> {
    let (Some(a), Some(b)) = (args.first(), args.get(1)) else {
        return Err("compare needs two capture directories".into());
    };
    let (a, b) = (Path::new(a), Path::new(b));
    let da = host::digest_tree(a)?;
    let db = host::digest_tree(b)?;
    let diff = host::diff_tables(&da, &db);
    let mut ok = diff.only_first.is_empty() && diff.only_second.is_empty();
    for p in diff.only_first.iter().chain(&diff.only_second) {
        println!("only in one capture: {p}");
    }
    let mut report = String::from("# host differences: <file>\t<cause>\t<lines>\n");
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for path in &diff.changed {
        let ta = read_text(&a.join(path))?;
        let tb = read_text(&b.join(path))?;
        match host::classify(&ta, &tb, &host::KNOWN_CAUSES) {
            Ok(counts) => {
                for (cause, n) in counts {
                    report.push_str(&format!("{path}\t{cause}\t{n}\n"));
                    *totals.entry(cause).or_insert(0) += n;
                }
            }
            Err(e) => {
                ok = false;
                println!("{path}: {e}");
            }
        }
    }
    for (cause, n) in &totals {
        report.push_str(&format!("total\t{cause}\t{n}\n"));
    }
    print!("{report}");
    println!(
        "{} files compared, {} differ, {}",
        da.len(),
        diff.changed.len(),
        if ok {
            "all by named causes"
        } else {
            "NOT all by named causes"
        }
    );
    if let Some(file) = option(args, "--write") {
        std::fs::write(file, report)?;
    }
    Ok(ok)
}

fn cmd_check(args: &[String]) -> Result<bool> {
    let (Some(out), Some(fixtures)) = (args.first(), args.get(1)) else {
        return Err("check needs a capture output and the fixtures directory".into());
    };
    let (out, fixtures) = (Path::new(out), Path::new(fixtures));
    let mut ok = true;
    for entry in std::fs::read_dir(out)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if Library::of_file_name(&name).is_none() || !name.starts_with("captures.") {
            continue;
        }
        let new = host::read_digests(&std::fs::read_to_string(out.join(&name))?)
            .ok_or("bad digest table")?;
        let Ok(old_text) = std::fs::read_to_string(fixtures.join(&name)) else {
            println!("no fixture {name} to compare with");
            ok = false;
            continue;
        };
        let old = host::read_digests(&old_text).ok_or("bad fixture digest table")?;
        let diff = host::diff_tables(&old, &new);
        if diff.is_empty() {
            println!("{name}: no drift ({} files)", new.len());
            continue;
        }
        ok = false;
        println!("{name}: drift");
        for p in &diff.changed {
            println!("  changed {p}");
        }
        for p in &diff.only_first {
            println!("  gone    {p}");
        }
        for p in &diff.only_second {
            println!("  new     {p}");
        }
    }
    let summary_new = std::fs::read_to_string(out.join("summary.txt"))?;
    match std::fs::read_to_string(fixtures.join("summary.txt")) {
        Ok(old) if old == summary_new => println!("summary.txt: no drift"),
        _ => {
            ok = false;
            println!("summary.txt: drift");
        }
    }
    Ok(ok)
}
