//! Shared support of the differential tests: the reference tools, the
//! language registry over the reference directory, basilisk's sweep and the
//! record-by-record comparison with `pcodedump`.
#![allow(dead_code, reason = "each test file uses part of this module")]

pub(crate) mod coverage;
pub(crate) mod directed;
pub(crate) mod real_code;
pub(crate) mod recording;
pub(crate) mod sweep;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::Language;
use bk_testkit::{ReferenceDir, Tool};

pub(crate) use sweep::{Sweep, sweep};

/// The reference directory with `pcodedump`, or `None` after printing why
/// the test is skipped.
pub(crate) fn reference() -> Option<ReferenceDir> {
    bk_testkit::require_tool(Tool::Pcodedump)
}

/// The language registry over a directory with Ghidra's layout.
pub(crate) fn registry(root: &Path) -> Arc<LanguageRegistry> {
    static CACHE: OnceLock<Mutex<HashMap<std::path::PathBuf, Arc<LanguageRegistry>>>> =
        OnceLock::new();
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
        Arc::new(
            builder
                .build()
                .expect("registry over the reference directory"),
        )
    }))
}

/// Loads a language of the reference directory.
pub(crate) fn load(reference: &ReferenceDir, id: &str) -> Arc<Language> {
    let registry = registry(reference.root());
    let id = LanguageId::new(id).expect("language id");
    Arc::new(Language::load(&registry, &id).unwrap_or_else(|e| panic!("load {id}: {e}")))
}

/// The oracle's records of one run, without `H`, `P` and `U`.
#[derive(Clone, Debug, Default)]
pub(crate) struct OracleDump {
    pub(crate) lines: Vec<String>,
    pub(crate) instructions: u64,
    /// Errors in the `T` record minus the `U` records.
    pub(crate) errors: u64,
}

/// Runs `pcodedump` and keeps the records this part compares.
pub(crate) fn oracle(
    reference: &ReferenceDir,
    id: &str,
    base: u64,
    data: &[u8],
    context: &[(String, u32)],
) -> OracleDump {
    try_oracle(reference, id, base, data, context).unwrap_or_else(|e| panic!("pcodedump {id}: {e}"))
}

/// Runs `pcodedump`; the error says how it failed (a crash is reported as
/// "exited with a signal").
pub(crate) fn try_oracle(
    reference: &ReferenceDir,
    id: &str,
    base: u64,
    data: &[u8],
    context: &[(String, u32)],
) -> Result<OracleDump, String> {
    let mut tool = reference
        .pcodedump()
        .timeout(std::time::Duration::from_mins(10));
    for (name, value) in context {
        tool = tool.context(name, *value);
    }
    tool.dump_text(id, base, data)
        .map(|text| parse_oracle(&text))
        .map_err(|e| e.to_string())
}

/// Whether an oracle failure is a crash of the process.
pub(crate) fn is_crash(error: &str) -> bool {
    error.contains("signal")
}

/// The bytes `[start, end)` of the instruction whose processing makes the
/// oracle crash: the shortest crashing prefix ends with it.
pub(crate) fn locate_crash(
    reference: &ReferenceDir,
    id: &str,
    base: u64,
    data: &[u8],
    context: &[(String, u32)],
) -> (usize, usize) {
    let crashes = |len: usize| {
        try_oracle(reference, id, base, &data[..len], context).is_err_and(|e| is_crash(&e))
    };
    let (mut ok, mut bad) = (0usize, data.len());
    while bad - ok > 1 {
        let mid = ok + (bad - ok) / 2;
        if crashes(mid) {
            bad = mid;
        } else {
            ok = mid;
        }
    }
    let before = try_oracle(reference, id, base, &data[..bad - 1], context).unwrap_or_default();
    let start = before
        .lines
        .last()
        .filter(|l| l.contains("\ttruncated\t"))
        .map_or(bad - 1, |l| (line_address(l) - base) as usize);
    (start, bad)
}

/// Keeps the `I`, `E` and `T` records of `pcodedump` output.
pub(crate) fn parse_oracle(text: &str) -> OracleDump {
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
pub(crate) struct Tolerated {
    pub(crate) over_20_operands: u64,
    pub(crate) past_byte_16: u64,
    pub(crate) next2_and_commit: u64,
}

impl Tolerated {
    pub(crate) fn add(&mut self, other: &Self) {
        self.over_20_operands += other.over_20_operands;
        self.past_byte_16 += other.past_byte_16;
        self.next2_and_commit += other.next2_and_commit;
    }
}

/// The outcome of comparing one sweep with the oracle.
#[derive(Clone, Debug, Default)]
pub(crate) struct Comparison {
    /// For each basilisk record, whether the oracle printed the same line.
    pub(crate) confirmed: Vec<bool>,
    pub(crate) tolerated: Tolerated,
    pub(crate) failures: Vec<String>,
}

/// Compares record by record, resynchronising after a tolerated difference
/// (and after a failure, to report more than the first) at the next address
/// both sides have a record for.
pub(crate) fn compare(oracle: &OracleDump, ours: &Sweep) -> Comparison {
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
            if line.ends_with("\terror\tSLEIGH parser out of state space") {
                // Equal because the harness fails as Ghidra does.
                out.tolerated.over_20_operands += 1;
            } else {
                out.confirmed[bi] = true;
            }
            oi += 1;
            bi += 1;
            continue;
        }
        let without_flow = |l: &str| {
            let mut f: Vec<&str> = l.split('\t').collect();
            if f.len() > 3 {
                f[3] = "";
            }
            f.join("\t")
        };
        if record.delay_over_20 && without_flow(line) == without_flow(&record.line) {
            out.tolerated.over_20_operands += 1;
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
            out.failures
                .push(format!("expected {line}\n     got {}", record.line));
        } else {
            out.failures.push(String::new());
        }
        // Resynchronise.
        let here = record.address.max(line_address(line));
        let theirs: std::collections::BTreeSet<u64> = oracle.lines[oi..]
            .iter()
            .map(|l| line_address(l))
            .filter(|&a| a > here)
            .collect();
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
