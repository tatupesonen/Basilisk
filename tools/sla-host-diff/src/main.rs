//! Compares two builds of Ghidra's compiled SLEIGH files (`.sla`).
//!
//! Commands (see README.md):
//!
//! * `scan LEFT RIGHT` — pair the `.sla` files of two directory trees by
//!   file name, compare their inflated streams, and list the ones that
//!   differ with the stream lengths and the first differing offset.
//! * `diff LEFT.sla RIGHT.sla [CAP]` — `bk_sla::diff` of two files, every
//!   difference on its own line.
//! * `classify LEFT RIGHT` — for each differing pair: the number of
//!   differences by kind (path shape), and an analysis of each decision
//!   tree that differs (see `trees.rs`).

mod trees;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bk_sla::{Limits, Sla};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["scan", left, right] => scan(Path::new(left), Path::new(right)),
        ["diff", left, right] => diff_files(Path::new(left), Path::new(right), 1_000_000),
        ["diff", left, right, cap] => match cap.parse() {
            Ok(cap) => diff_files(Path::new(left), Path::new(right), cap),
            Err(e) => Err(format!("bad CAP {cap}: {e}")),
        },
        ["classify", left, right] => classify(Path::new(left), Path::new(right)),
        ["trees", left, right] => trees_files(Path::new(left), Path::new(right), false),
        ["trees", left, right, "-v"] => trees_files(Path::new(left), Path::new(right), true),
        _ => Err("usage: sla-host-diff scan|classify LEFT_DIR RIGHT_DIR | diff A.sla B.sla [CAP] | trees A.sla B.sla [-v]".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// All `.sla` files under `dir`, by file stem.
fn find_sla(dir: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "sla")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                if out.insert(stem.to_owned(), path.clone()).is_some() {
                    return Err(format!("duplicate {stem} under {}", dir.display()));
                }
            }
        }
    }
    Ok(out)
}

fn stream(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    bk_sla::inflate(&bytes, &Limits::default()).map_err(|e| format!("{}: {e}", path.display()))
}

fn load(path: &Path) -> Result<Sla, String> {
    Sla::read_file(path, &Limits::default()).map_err(|e| format!("{}: {e}", path.display()))
}

/// Pairs that differ: (stem, left path, right path).
fn differing(left: &Path, right: &Path, verbose: bool) -> Result<Vec<(String, PathBuf, PathBuf)>, String> {
    let a = find_sla(left)?;
    let b = find_sla(right)?;
    let mut out = Vec::new();
    let (mut same, mut only) = (0, 0);
    for (stem, pa) in &a {
        let Some(pb) = b.get(stem) else {
            only += 1;
            if verbose {
                println!("only-left {stem}");
            }
            continue;
        };
        let (sa, sb) = (stream(pa)?, stream(pb)?);
        if sa == sb {
            same += 1;
            continue;
        }
        if verbose {
            let first = sa.iter().zip(&sb).position(|(x, y)| x != y).unwrap_or(sa.len().min(sb.len()));
            println!(
                "differ {stem}: len {} vs {} (delta {:+}), first difference at {first} ({:.1}% in)",
                sa.len(),
                sb.len(),
                sb.len() as i64 - sa.len() as i64,
                100.0 * first as f64 / sa.len() as f64
            );
        }
        out.push((stem.clone(), pa.clone(), pb.clone()));
    }
    only += b.keys().filter(|k| !a.contains_key(*k)).count();
    if verbose {
        println!(
            "left {} files, right {} files: {} identical streams, {} differ, {} unpaired",
            a.len(),
            b.len(),
            same,
            out.len(),
            only
        );
    }
    Ok(out)
}

fn scan(left: &Path, right: &Path) -> Result<(), String> {
    differing(left, right, true).map(|_| ())
}

fn diff_files(left: &Path, right: &Path, cap: usize) -> Result<(), String> {
    let (a, b) = (load(left)?, load(right)?);
    let diffs = bk_sla::diff(&a, &b, cap);
    for d in &diffs {
        println!("{d}");
    }
    println!("{} differences (cap {cap})", diffs.len());
    Ok(())
}

/// The kind of a difference: its path with numbers, quoted names and
/// source positions replaced by placeholders.
fn kind(path: &str) -> String {
    let mut out = String::new();
    let mut in_quote = false;
    let mut in_paren = false;
    let mut last_num = false;
    for c in path.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                if in_quote {
                    out.push_str("\"*\"");
                }
            }
            _ if in_quote => {}
            '(' => {
                in_paren = true;
                out.push_str("(*)");
            }
            ')' => in_paren = false,
            _ if in_paren => {}
            '0'..='9' => {
                if !last_num {
                    out.push('N');
                }
                last_num = true;
                continue;
            }
            _ => out.push(c),
        }
        last_num = false;
    }
    // Collapse decision paths "decision/N/N/N" to "decision/…".
    let mut collapsed = String::new();
    for part in out.split(' ') {
        if !collapsed.is_empty() {
            collapsed.push(' ');
        }
        if part.starts_with("decision/") {
            collapsed.push_str("decision/…");
        } else {
            collapsed.push_str(part);
        }
    }
    collapsed
}

fn classify(left: &Path, right: &Path) -> Result<(), String> {
    for (stem, pa, pb) in differing(left, right, false)? {
        let (a, b) = (load(&pa)?, load(&pb)?);
        let diffs = bk_sla::diff(&a, &b, 1_000_000);
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        let mut tables: BTreeMap<String, usize> = BTreeMap::new();
        for d in &diffs {
            *kinds.entry(kind(&d.path)).or_default() += 1;
            let table = d.path.split('"').nth(1).unwrap_or("").to_owned();
            *tables.entry(format!("{} {table}", d.path.split(' ').next().unwrap_or(""))).or_default() += 1;
        }
        println!("== {stem}: {} differences in {} tables/symbols", diffs.len(), tables.len());
        for (k, n) in &kinds {
            println!("  {n:6}  {k}");
        }
        let report = trees::compare(&a, &b, false);
        print!("{report}");
    }
    Ok(())
}

fn trees_files(left: &Path, right: &Path, verbose: bool) -> Result<(), String> {
    let (a, b) = (load(left)?, load(right)?);
    print!("{}", trees::compare(&a, &b, verbose));
    Ok(())
}
