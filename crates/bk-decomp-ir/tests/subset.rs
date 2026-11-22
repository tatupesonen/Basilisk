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
//! Spec 6, test 1 (S): the checked-in subset of the corpus — every dump of
//! 20 functions chosen to cover every opcode and every op and varnode flag
//! bit that occurs in the full capture — loads, keeps the invariants and
//! writes back byte for byte on every system, with the checked-in register
//! tables (`tests/data/lang`).
//!
//! The selection is mechanical: `select_subset` (L, ignored; run it with
//! `cargo test -p bk-decomp-ir --test subset -- --ignored` after
//! `tests/corpus.rs` has made `target/decomp-ir/capture`) covers the rarest
//! uncovered feature first with the function that adds the most, then fills
//! up to 20 with the richest functions (ties: the name), among
//! the functions whose dumps all round-trip (no join varnodes) in a
//! language with a checked-in table, and writes `tests/data/subset/` and
//! its `LIST.md`.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bk_core::NoRegisters;
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_testkit::oracle::{StateDump, read_text, write_text};
use bk_testkit::workspace_root;
use support::lang::{LANGUAGES, LangTables};

const FUNCTIONS: usize = 20;

fn subset_dir() -> PathBuf {
    workspace_root().join("crates/bk-decomp-ir/tests/data/subset")
}

fn language(dump: &StateDump) -> String {
    dump.arch_id
        .rsplit_once(':')
        .map_or(dump.arch_id.as_str(), |(l, _)| l)
        .to_owned()
}

/// Loads, checks and writes one dump; `Err` with the first differing line.
/// Round-trips one dump; returns how many of its varnodes have a high.
fn round_trip(text: &str) -> Result<usize, String> {
    let dump = StateDump::parse(text).map_err(|e| e.to_string())?;
    let lang = language(&dump);
    let tables = LangTables::load(&lang).ok_or_else(|| format!("no table for {lang}"))?;
    let bare = spaces_from_dump(&dump, Arc::new(NoRegisters)).map_err(|e| e.to_string())?;
    let regs = Arc::new(tables.reg_table(&bare));
    let spaces = Arc::new(spaces_from_dump(&dump, regs).map_err(|e| e.to_string())?);
    let ssa = load(&dump, Arc::clone(&spaces)).map_err(|e| e.to_string())?;
    let bad = ssa.invariant_violations();
    if !bad.is_empty() {
        return Err(format!("invariants: {bad:?}"));
    }
    // Loading calls no varnode setter: no high-variable event.
    if !ssa.high_events().is_empty() {
        return Err(format!("load recorded {:?}", ssa.high_events()));
    }
    let highs = ssa
        .loc_order()
        .filter(|&v| ssa.varnode_high(v).is_some())
        .count();
    let names = DumpNames::from_dump(&dump, &spaces).with_userops(tables.userops.clone());
    let out = write(&ssa, &dump, &names, &CanonicalCalls::Identity).map_err(|e| e.to_string())?;
    match text.lines().zip(out.lines()).position(|(a, b)| a != b) {
        Some(i) => Err(format!(
            "line {}: {:?} / {:?}",
            i + 1,
            text.lines().nth(i),
            out.lines().nth(i)
        )),
        None if text != out => Err("length differs".into()),
        None => Ok(highs),
    }
}

#[test]
fn checked_in_subset_round_trips() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(subset_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".state.gz"))
        .collect();
    files.sort();
    assert!(files.len() >= FUNCTIONS, "subset has {} dumps", files.len());
    let mut functions = BTreeSet::new();
    let mut highs = 0;
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        // <corpus>.<script>.<k>.<point>.state.gz
        let parts: Vec<&str> = name.rsplitn(4, '.').collect();
        functions.insert(parts[3].to_owned());
        let text = read_text(f).unwrap();
        match round_trip(&text) {
            Ok(n) => highs += n,
            Err(e) => panic!("{name}: {e}"),
        }
    }
    assert_eq!(functions.len(), FUNCTIONS);
    assert!(highs > 0, "no dump of the subset has high variables");
    eprintln!(
        "subset: {} dumps of {} functions round-trip",
        files.len(),
        functions.len()
    );
}

/// What a dump shows: opcodes and the set bits of op and varnode flags.
fn features(dump: &StateDump, out: &mut BTreeSet<String>) {
    let bits = |out: &mut BTreeSet<String>, what: &str, v: u32| {
        for b in 0..32 {
            if v & (1 << b) != 0 {
                out.insert(format!("{what}:{b}"));
            }
        }
    };
    for o in &dump.ops {
        out.insert(format!("op:{}", o.opcode));
        bits(out, "opflag", o.flags);
        bits(out, "opaddl", o.addl_flags);
    }
    for v in &dump.varnodes {
        bits(out, "vnflag", v.flags);
        bits(out, "vnaddl", v.addl_flags);
    }
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else if p.extension().is_some_and(|x| x == "state") {
            out.push(p);
        }
    }
}

#[test]
#[ignore = "selects the subset from a capture (L); writes tests/data/subset"]
fn select_subset() {
    let cap = workspace_root().join("target/decomp-ir/capture");
    let mut all = Vec::new();
    files(&cap, &mut all);
    assert!(!all.is_empty(), "no capture in {}", cap.display());
    // Function → (dumps, features, eligible).
    let mut by_fn: BTreeMap<String, (Vec<PathBuf>, BTreeSet<String>, bool)> = BTreeMap::new();
    let mut everything = BTreeSet::new();
    for p in &all {
        let rel = p.strip_prefix(&cap).unwrap();
        let corpus = rel
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let stem: Vec<&str> = name.rsplitn(3, '.').collect(); // state, point, rest
        let func = format!("{corpus}.{}", stem[2]);
        let text = read_text(p).unwrap();
        let dump = StateDump::parse(&text).unwrap();
        let entry = by_fn
            .entry(func)
            .or_insert_with(|| (Vec::new(), BTreeSet::new(), true));
        features(&dump, &mut entry.1);
        features(&dump, &mut everything);
        entry.0.push(p.clone());
        let ok = LANGUAGES.contains(&language(&dump).as_str()) && round_trip(&text).is_ok();
        entry.2 &= ok;
    }
    // Rarest uncovered feature first: of the eligible functions that have
    // it, the one that adds the most (ties: the name). Then fill up to
    // FUNCTIONS by gain.
    let mut covered = BTreeSet::new();
    let mut chosen: Vec<String> = Vec::new();
    let eligible: Vec<&String> = by_fn
        .iter()
        .filter(|(_, (_, _, ok))| *ok)
        .map(|(f, _)| f)
        .collect();
    let gain = |f: &String, covered: &BTreeSet<String>| by_fn[f].1.difference(covered).count();
    loop {
        let rarest = everything
            .iter()
            .filter(|x| !covered.contains(*x))
            .filter_map(|x| {
                let n = eligible.iter().filter(|f| by_fn[**f].1.contains(x)).count();
                (n > 0).then_some((n, x.clone()))
            })
            .min();
        let Some((_, feature)) = rarest else {
            break;
        };
        let pick = eligible
            .iter()
            .filter(|f| by_fn[**f].1.contains(&feature) && !chosen.iter().any(|c| c == **f))
            .max_by(|a, b| gain(a, &covered).cmp(&gain(b, &covered)).then(b.cmp(a)))
            .map(|f| (*f).clone())
            .unwrap();
        covered.extend(by_fn[&pick].1.iter().cloned());
        chosen.push(pick);
    }
    assert!(
        chosen.len() <= FUNCTIONS,
        "coverage needs {} functions",
        chosen.len()
    );
    while chosen.len() < FUNCTIONS {
        let pick = eligible
            .iter()
            .filter(|f| !chosen.iter().any(|c| c == **f))
            .max_by(|a, b| by_fn[**a].1.len().cmp(&by_fn[**b].1.len()).then(b.cmp(a)))
            .map(|f| (*f).clone())
            .unwrap();
        chosen.push(pick);
    }
    let missing: Vec<_> = everything.difference(&covered).cloned().collect();
    let dir = subset_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut list = String::from(
        "# The checked-in subset (`tests/subset.rs`, `select_subset`)\n\n\
         Chosen for coverage of opcodes and op/varnode flag bits (rarest first)\n\
         among the functions whose dumps all round-trip in a language with a\n\
         checked-in table.\n\n",
    );
    for f in &chosen {
        let _ = writeln!(list, "- `{f}`");
        for p in &by_fn[f].0 {
            let name = p.file_name().unwrap().to_string_lossy();
            let corpus = f.split_once('.').unwrap().0;
            let to = dir.join(format!("{corpus}.{name}.gz"));
            write_text(&to, &read_text(p).unwrap()).unwrap();
        }
    }
    let _ = write!(
        list,
        "\nFeatures in the full capture: {}; covered: {}; not covered (only in \
         functions that cannot be checked in): {missing:?}\n",
        everything.len(),
        covered.len()
    );
    std::fs::write(dir.join("LIST.md"), list).unwrap();
    eprintln!("chosen {chosen:?}; missing {missing:?}");
}
