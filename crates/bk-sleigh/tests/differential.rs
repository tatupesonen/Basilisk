//! The differential test against `pcodedump` (`features/sleigh-decode.md`
//! 6.2): `I`, `E` and `T` records over directed samples per root leaf pair,
//! random bytes and real code, with coverage thresholds.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Mutex;

use common::coverage::{Budget, Extra, LanguageResult, run_language};

/// One language id per distinct (`.sla`, `.pspec`) pair, sorted.
fn all_languages(reference: &bk_testkit::ReferenceDir) -> Vec<String> {
    let registry = common::registry(reference.root());
    let mut seen = BTreeSet::new();
    // pcodedump looks for the `.sla` beside the `.ldefs` that names it
    // (Ghidra searches every language directory); languages whose file lies
    // elsewhere (RISC-V's `old/` definitions) cannot be run by the oracle.
    let mut ids: Vec<(String, std::path::PathBuf, std::path::PathBuf)> = registry
        .languages()
        .iter()
        .filter(|d| {
            let files = d.files();
            let beside = files
                .ldefs
                .parent()
                .zip(files.sla.file_name())
                .map(|(dir, name)| dir.join(name));
            beside.is_some_and(|p| p.is_file())
        })
        .map(|d| {
            (
                d.id().to_string(),
                d.files().sla.clone(),
                d.files().pspec.clone(),
            )
        })
        .collect();
    ids.sort();
    ids.into_iter()
        .filter(|(_, sla, pspec)| seen.insert((sla.clone(), pspec.clone())))
        .map(|(id, _, _)| id)
        .collect()
}

/// The checked-in exceptions: (language, metric) → cause.
fn exceptions() -> BTreeMap<(String, String), String> {
    let text = include_str!("data/coverage-exceptions.txt");
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut f = l.splitn(3, '\t');
            let id = f.next().unwrap().to_owned();
            let metric = f.next().unwrap_or("").to_owned();
            ((id, metric), f.next().unwrap_or("").to_owned())
        })
        .collect()
}

fn run_all(
    ids: &[String],
    budget: Budget,
    extras: &BTreeMap<String, Vec<Extra>>,
    threads: usize,
) -> Vec<LanguageResult> {
    let Some(reference) = common::reference() else {
        return Vec::new();
    };
    let queue = Mutex::new(ids.to_vec());
    let results = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let Some(id) = queue.lock().unwrap().pop() else {
                        break;
                    };
                    let lang = common::load(&reference, &id);
                    let none = Vec::new();
                    let result = run_language(
                        &reference,
                        &lang,
                        &id,
                        budget,
                        extras.get(&id).unwrap_or(&none),
                    );
                    eprintln!("{}", result.row());
                    for f in result.failures.iter().take(6) {
                        eprintln!("FAIL {}: {f}", result.id);
                    }
                    for c in &result.oracle_crashes {
                        eprintln!("CRASH {}: {c}", result.id);
                    }
                    results.lock().unwrap().push(result);
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by(|a, b| a.id.cmp(&b.id));
    results
}

fn report_failures(results: &[LanguageResult]) -> usize {
    let mut count = 0;
    for r in results {
        for f in &r.failures {
            eprintln!("{}: {f}", r.id);
            count += 1;
        }
    }
    count
}

/// The reduced form that runs in the gate: twelve languages, one directed
/// sample per root leaf pair.
#[test]
fn twelve_languages_one_sample_per_pair() {
    if common::reference().is_none() {
        return;
    }
    let ids: Vec<String> = [
        "x86:LE:32:default",
        "x86:LE:64:default",
        "ARM:LE:32:v8",
        "AARCH64:LE:64:v8A",
        "MIPS:BE:32:default",
        "PowerPC:BE:32:default",
        "sparc:BE:32:default",
        "68000:BE:32:default",
        "avr8:LE:16:default",
        "RISCV:LE:64:default",
        "Hexagon:LE:32:default",
        "Toy:BE:32:default",
    ]
    .map(str::to_owned)
    .to_vec();
    let budget = Budget {
        samples_per_pair: 1,
        random_bytes: 0,
        max_streams: 1000,
        coverage_attempts: 0,
    };
    let results = run_all(&ids, budget, &BTreeMap::new(), 3);
    assert_eq!(results.len(), ids.len());
    assert_eq!(
        report_failures(&results),
        0,
        "records differ from pcodedump"
    );
}

/// The full run: every language, eight directed samples per root leaf pair
/// plus a coverage search, 64 kB of random bytes, and real code. Long
/// (hundreds of oracle processes); run it with `--ignored`.
#[test]
#[ignore = "long: every language against pcodedump"]
fn every_language() {
    let Some(reference) = common::reference() else {
        return;
    };
    let ids = all_languages(&reference);
    let budget = Budget {
        samples_per_pair: 8,
        random_bytes: 64 * 1024,
        max_streams: 1000,
        coverage_attempts: 300_000,
    };
    let extras = common::real_code::extras(&reference);
    let threads = std::env::var("BK_THREADS")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(3);
    let results = run_all(&ids, budget, &extras, threads);
    let failures = report_failures(&results);
    for r in &results {
        for crash in &r.oracle_crashes {
            eprintln!("{}: oracle crashed on {crash}", r.id);
        }
    }
    let exceptions = exceptions();
    let mut table = String::new();
    let (mut targeted, mut confirmed) = (0usize, 0usize);
    let mut below = Vec::new();
    for r in &results {
        table.push_str(&r.row());
        table.push('\n');
        targeted += r.targeted;
        confirmed += r.confirmed.len() + r.over_20_decoded;
        let pairs = (r.confirmed.len() + r.over_20_decoded) as f64 / r.targeted.max(1) as f64;
        if pairs < 0.95 && !exceptions.contains_key(&(r.id.clone(), "pairs".to_owned())) {
            below.push(format!("{} pairs {:.2}%", r.id, 100.0 * pairs));
        }
        if r.ctor_rate() < 0.90
            && !exceptions.contains_key(&(r.id.clone(), "constructors".to_owned()))
        {
            below.push(format!(
                "{} constructors {:.2}%",
                r.id,
                100.0 * r.ctor_rate()
            ));
        }
    }
    let overall = confirmed as f64 / targeted.max(1) as f64;
    let _ = writeln!(table, "all\tpairs {targeted}\tconfirmed {confirmed}");
    let out = bk_testkit::workspace_root()
        .join("target")
        .join("sleigh-coverage.txt");
    std::fs::write(&out, &table).unwrap();
    eprintln!("coverage table written to {}", out.display());
    insta::assert_snapshot!("coverage_table", table);
    assert_eq!(failures, 0, "records differ from pcodedump");
    assert!(
        overall >= 0.99,
        "root pairs confirmed overall {:.3}%",
        100.0 * overall
    );
    assert!(
        below.is_empty(),
        "below threshold without an exception: {below:#?}"
    );
}
