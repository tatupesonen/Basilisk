//! Shared support of the differential tests: the reference tools, the
//! language registry over the reference directory, basilisk's sweep and the
//! record-by-record comparison with `pcodedump`.
#![allow(dead_code, reason = "each test file uses part of this module")]

pub mod sweep;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::Language;
use bk_testkit::{ReferenceDir, Tool};

pub use sweep::{Record, Sweep, sweep};

/// The reference directory with `pcodedump`, or `None` after printing why
/// the test is skipped.
pub fn reference() -> Option<ReferenceDir> {
    bk_testkit::require_tool(Tool::Pcodedump)
}

/// The language registry over a directory with Ghidra's layout.
pub fn registry(root: &Path) -> Arc<LanguageRegistry> {
    static CACHE: OnceLock<Mutex<HashMap<std::path::PathBuf, Arc<LanguageRegistry>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap();
    Arc::clone(cache.entry(root.to_path_buf()).or_insert_with(|| {
        // The reference directory mirrors Ghidra's layout without module
        // manifests, so each processor directory is added as a module.
        let mut builder = LanguageRegistry::builder().include_hidden(true);
        let mut dirs: Vec<_> = std::fs::read_dir(root.join("Ghidra").join("Processors"))
            .expect("reference processors directory")
            .map(|e| e.expect("directory entry").path())
            .collect();
        dirs.sort();
        for dir in dirs {
            builder = builder.module(dir);
        }
        Arc::new(builder.build().expect("registry over the reference directory"))
    }))
}

/// Loads a language of the reference directory.
pub fn load(reference: &ReferenceDir, id: &str) -> Arc<Language> {
    let registry = registry(reference.root());
    let id = LanguageId::new(id).expect("language id");
    Arc::new(Language::load(&registry, &id).unwrap_or_else(|e| panic!("load {id}: {e}")))
}

/// The oracle's records of one run, without `H`, `P` and `U`.
#[derive(Clone, Debug, Default)]
pub struct OracleDump {
    pub lines: Vec<String>,
    pub instructions: u64,
    /// Errors in the `T` record minus the `U` records.
    pub errors: u64,
}

/// Runs `pcodedump` and keeps the records this part compares.
pub fn oracle(reference: &ReferenceDir, id: &str, base: u64, data: &[u8], context: &[(String, u32)]) -> OracleDump {
    let mut tool = reference.pcodedump().timeout(std::time::Duration::from_secs(600));
    for (name, value) in context {
        tool = tool.context(name, *value);
    }
    let text = tool
        .dump_text(id, base, data)
        .unwrap_or_else(|e| panic!("pcodedump {id}: {e}"));
    parse_oracle(&text)
}

/// Keeps the `I`, `E` and `T` records of `pcodedump` output.
pub fn parse_oracle(text: &str) -> OracleDump {
    let mut dump = OracleDump::default();
    let mut unlifted = 0u64;
    for line in text.lines() {
        match line.as_bytes().first() {
            Some(b'I' | b'E') => dump.lines.push(line.to_owned()),
            Some(b'U') => unlifted += 1,
            Some(b'T') => {
                let mut fields = line.split('\t').skip(1);
                dump.instructions = fields.next().and_then(|f| f.parse().ok()).unwrap_or(0);
                let errors: u64 = fields.next().and_then(|f| f.parse().ok()).unwrap_or(0);
                dump.errors = errors.saturating_sub(unlifted);
            }
            _ => {}
        }
    }
    dump
}

fn line_address(line: &str) -> u64 {
    line.split('\t')
        .nth(1)
        .and_then(|f| u64::from_str_radix(f.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

/// The kinds of difference the harness tolerates (`features/sleigh-decode.md`
/// 6.2), counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tolerated {
    pub over_20_operands: u64,
    pub past_byte_16: u64,
    pub next2_and_commit: u64,
}

impl Tolerated {
    pub fn add(&mut self, other: &Self) {
        self.over_20_operands += other.over_20_operands;
        self.past_byte_16 += other.past_byte_16;
        self.next2_and_commit += other.next2_and_commit;
    }
}

/// The outcome of comparing one sweep with the oracle.
#[derive(Clone, Debug, Default)]
pub struct Comparison {
    /// For each basilisk record, whether the oracle printed the same line.
    pub confirmed: Vec<bool>,
    pub tolerated: Tolerated,
    pub failures: Vec<String>,
}

/// Compares record by record, resynchronising after a tolerated difference
/// (and after a failure, to report more than the first) at the next address
/// both sides have a record for.
pub fn compare(oracle: &OracleDump, ours: &Sweep) -> Comparison {
    let mut out = Comparison {
        confirmed: vec![false; ours.records.len()],
        ..Comparison::default()
    };
    let (mut oi, mut bi) = (0usize, 0usize);
    let mut differed = false;
    while oi < oracle.lines.len() && bi < ours.records.len() {
        let line = &oracle.lines[oi];
        let record = &ours.records[bi];
        if *line == record.line {
            out.confirmed[bi] = true;
            oi += 1;
            bi += 1;
            continue;
        }
        differed = true;
        let previous = bi.checked_sub(1).map(|p| &ours.records[p]);
        if record.too_many_operands && line.ends_with("\terror\tSLEIGH parser out of state space") {
            out.tolerated.over_20_operands += 1;
        } else if record.reads_past_window {
            out.tolerated.past_byte_16 += 1;
        } else if previous.is_some_and(|p| p.uses_next2 && p.committed) {
            out.tolerated.next2_and_commit += 1;
        } else if out.failures.len() < 20 {
            out.failures.push(format!("expected {line}\n     got {}", record.line));
        } else {
            out.failures.push(String::new());
        }
        // Resynchronise.
        let here = record.address.max(line_address(line));
        let theirs: std::collections::BTreeSet<u64> =
            oracle.lines[oi..].iter().map(|l| line_address(l)).filter(|&a| a > here).collect();
        let common = ours.records[bi..]
            .iter()
            .map(|r| r.address)
            .find(|a| *a > here && theirs.contains(a));
        let Some(common) = common else {
            oi = oracle.lines.len();
            bi = ours.records.len();
            break;
        };
        while oi < oracle.lines.len() && line_address(&oracle.lines[oi]) != common {
            oi += 1;
        }
        while bi < ours.records.len() && ours.records[bi].address != common {
            bi += 1;
        }
    }
    if !differed {
        if oi < oracle.lines.len() || bi < ours.records.len() {
            out.failures.push(format!(
                "record counts differ: oracle {} basilisk {}",
                oracle.lines.len(),
                ours.records.len()
            ));
        } else if oracle.instructions != ours.instructions || oracle.errors != ours.errors {
            out.failures.push(format!(
                "T records differ: oracle T\t{}\t{} basilisk {}",
                oracle.instructions,
                oracle.errors,
                ours.t_line()
            ));
        }
    }
    out
}
