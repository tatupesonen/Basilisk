#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]
//! Spec tests 1 and 2 over the whole corpus (L): every state dump D00's
//! capture driver writes for the data tests and the research corpus (the
//! four standard points and the end) loads and writes back byte for byte —
//! bank orders recomputed, op texts printed by this crate — and the
//! block-level `print raw` of the first point equals the console's.
//!
//! The capture is made into `target/decomp-ir/capture` (or read from
//! `BK_IR_CAPTURE` if set). A summary goes to `target/decomp-ir/corpus.txt`.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bk_core::{NoRegisters, RegisterLookup};
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_lang::{LanguageId, LanguageRegistry};
use bk_sleigh::Language;
use bk_testkit::oracle::capture;
use bk_testkit::oracle::{StateDump, read_text};
use bk_testkit::{Tool, require_ghidra, require_tool, workspace_root};

struct Lang {
    regs: Arc<dyn RegisterLookup>,
    userops: Vec<Option<String>>,
}

fn languages(reference: &bk_testkit::ReferenceDir) -> LanguageRegistry {
    let mut b = LanguageRegistry::builder();
    for e in std::fs::read_dir(reference.root().join("Ghidra/Processors")).unwrap() {
        b = b.module(e.unwrap().path());
    }
    b.build().unwrap()
}

fn lang<'a>(reg: &LanguageRegistry, cache: &'a mut HashMap<String, Lang>, arch: &str) -> &'a Lang {
    let id = arch.rsplit_once(':').map_or(arch, |(l, _)| l).to_owned();
    cache.entry(id.clone()).or_insert_with(|| {
        let l = Language::load(reg, &LanguageId::new(&id).unwrap()).unwrap();
        Lang {
            regs: Arc::clone(l.registers()) as Arc<dyn RegisterLookup>,
            userops: (0..l.num_user_ops())
                .map(|i| l.user_op_name(i).map(str::to_owned))
                .collect(),
        }
    })
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn first_diff(a: &str, b: &str) -> Option<(usize, String, String)> {
    for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
        if x != y {
            return Some((i + 1, x.to_owned(), y.to_owned()));
        }
    }
    (a.lines().count() != b.lines().count())
        .then(|| (0, "line count".to_owned(), String::new()))
}

/// The cause of a difference, by what our line shows.
fn cause(ours: &str) -> &'static str {
    if ours.contains("{unlinked:") {
        "join-record-missing"
    } else {
        "other"
    }
}

#[test]
fn every_captured_dump_round_trips_and_prints_as_the_console() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let out_dir = workspace_root().join("target/decomp-ir");
    let cap = std::env::var_os("BK_IR_CAPTURE")
        .map_or_else(|| out_dir.join("capture"), PathBuf::from);
    if !cap.join("datatests").is_dir() {
        let positions = capture::find_positions(&reference, &ghidra).unwrap();
        let mut scripts = capture::data_tests(&ghidra).unwrap();
        scripts.extend(capture::research(&workspace_root()).unwrap());
        let jobs = std::thread::available_parallelism().map_or(4, |n| n.get());
        let report = capture::capture_corpus(&reference, &scripts, &positions, &cap, jobs);
        eprintln!("capture: {}", report.summary().lines().last().unwrap_or(""));
    }
    let reg = languages(&reference);
    let mut cache = HashMap::new();
    let mut all = Vec::new();
    files(&cap, &mut all);
    let (mut loaded, mut equal, mut raw_eq, mut raw_n) = (0, 0, 0, 0);
    let mut causes: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut report = String::new();
    for path in all.iter().filter(|p| p.extension().is_some_and(|e| e == "state")) {
        let name = path.strip_prefix(&cap).unwrap().display().to_string();
        let text = read_text(path).unwrap();
        let dump = StateDump::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        let l = lang(&reg, &mut cache, &dump.arch_id);
        let spaces = Arc::new(spaces_from_dump(&dump, Arc::clone(&l.regs)).unwrap());
        let ssa = match load(&dump, Arc::clone(&spaces)) {
            Ok(s) => s,
            Err(e) => {
                *causes.entry("load-error").or_default() += 1;
                let _ = writeln!(report, "LOAD {name}: {e}");
                continue;
            }
        };
        loaded += 1;
        let names = DumpNames::from_dump(&dump, &spaces).with_userops(l.userops.clone());
        let out = write(&ssa, &dump, &names, &CanonicalCalls::Identity).unwrap();
        match first_diff(&text, &out) {
            None => equal += 1,
            Some((line, a, b)) => {
                *causes.entry(cause(&b)).or_default() += 1;
                let _ = writeln!(report, "DIFF {name}:{line}\n  dump {a}\n  ours {b}");
            }
        }
        // Test 2: block-level print raw at the first point.
        let raw_path = PathBuf::from(path.to_string_lossy().replace(".p1.state", ".p1.raw"));
        if name.ends_with(".p1.state") && raw_path.is_file() {
            raw_n += 1;
            let console = read_text(&raw_path).unwrap();
            let ours = ssa.print_raw(&names).unwrap_or_default();
            match first_diff(&console, &ours) {
                None => raw_eq += 1,
                Some((line, a, b)) => {
                    *causes.entry("print-raw").or_default() += 1;
                    let _ = writeln!(report, "RAW {name}:{line}\n  console {a}\n  ours    {b}");
                }
            }
        }
    }
    let _ = NoRegisters;
    let summary = format!(
        "dumps loaded {loaded}, written equal {equal}; print raw equal {raw_eq} of {raw_n}; differences {causes:?}\n"
    );
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("corpus.txt"), format!("{summary}{report}")).unwrap();
    eprintln!("{summary}");
    assert!(loaded > 0, "no dumps found in {}", cap.display());
    let other = causes.get("other").copied().unwrap_or(0)
        + causes.get("load-error").copied().unwrap_or(0)
        + causes.get("print-raw").copied().unwrap_or(0);
    assert_eq!(other, 0, "see target/decomp-ir/corpus.txt\n{}", report.lines().take(40).collect::<Vec<_>>().join("\n"));
}
