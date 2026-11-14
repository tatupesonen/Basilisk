#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]
//! Every structuring run of the corpora (`docs/features/decomp-cfg.md`
//! 6.3.2, 6.4): the data tests and the research fragments, each
//! `decompile` captured with D00's `bk capture structure` (the basic-block
//! graph with its real facts and the switch defaults installed, at every
//! `blockstructure` start whose structure is empty, and Ghidra's hierarchy
//! at the next action). For every run Ghidra's own structurer is also run on
//! the captured graph with `bk structure … asgiven trace`, which gives the
//! flips, goto marks, change count and rule sequence.
//!
//! The table (`tests/data/structure_corpus.<library>.txt.gz`) holds per
//! run the captured graph (the input, as text) and digests of Ghidra's two
//! dumps. `replay` (S) structures each graph `AsGiven` and requires
//! Basilisk's `bkstruct` dump to equal `bk structure`'s and its `S`/`P`
//! records to equal the captured hierarchy. `capture` (L, ignored)
//! regenerates it: `tests/oracle/regen_corpus.sh`.

mod support {
    pub(crate) mod oracle;
    pub(crate) mod table;
    pub(crate) mod graphgen;
}

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bk_decomp_cfg::{GhidraGotoSelector, Limits, Record, StructureOptions, structure};
use bk_testkit::oracle::capture::{CorpusScript, data_tests, is_decompile, research};
use bk_testkit::oracle::host::{Library, digest};
use bk_testkit::oracle::{GraphFile, StructureDump};
use support::oracle::{cfg_of, dump_structure, struct_dump};
use support::table::{data_dir, escape, read_gz, unescape, write_gz};

const HEADER: &str = "# bk-decomp-cfg corpus table v1: script decompilation run graph(bkgraph 1, escaped) fnv64(bk structure asgiven trace) fnv64(captured structure)";

fn table_path(lib: Library) -> PathBuf {
    data_dir().join(format!("structure_corpus.{}.txt.gz", lib.name()))
}

fn path_arg(p: &Path) -> String {
    let s = p.to_str().expect("UTF-8 path");
    assert!(!s.contains(char::is_whitespace), "the console cannot take {s}");
    s.to_owned()
}

/// The script of `bk capture structure` for every decompilation of `s`.
fn capture_script(s: &CorpusScript, out: &Path) -> Vec<String> {
    let mut lines = vec![s.load.clone()];
    let mut d = 0;
    for c in &s.commands {
        if is_decompile(c) {
            lines.push(format!("bk capture structure {}", path_arg(&out.join(format!("{}.{d}", s.name)))));
            d += 1;
        } else {
            lines.push(c.clone());
        }
    }
    lines
}

/// Basilisk on one captured graph: the `bkstruct` dump as `bk structure …
/// asgiven trace` writes it, and the `S`/`P` records as `bk dump
/// structure` writes them.
fn basilisk(graph: &GraphFile) -> (String, String) {
    let (cfg, facts) = cfg_of(graph);
    let options = StructureOptions { record: Record::Trace, ..StructureOptions::default() };
    let r = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new());
    let full = struct_dump(&r).write();
    let hier = match &r {
        Ok(s) => dump_structure(&s.hierarchy).write(),
        Err(e) => StructureDump::Error(e.to_string()).write(),
    };
    (full, hier)
}

fn hex(d: u64) -> String {
    format!("{d:016x}")
}

#[test]
#[ignore = "runs decomp_bk over both corpora; tests/oracle/regen_corpus.sh"]
fn capture() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let lib = Library::of_reference(&reference).unwrap();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("bk-cfg-corpus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let mut scripts = data_tests(&ghidra).unwrap();
    scripts.extend(research(&bk_testkit::workspace_root()).unwrap());
    let mut skipped = Vec::new();
    for s in &scripts {
        let dir = out.join(s.corpus);
        std::fs::create_dir_all(&dir).unwrap();
        let r = reference
            .decomp_bk()
            .current_dir(&s.dir)
            .timeout(Duration::from_mins(5))
            .run_script(capture_script(s, &dir));
        if let Err(e) = r {
            skipped.push(format!("{}/{}: {}", s.corpus, s.name, e.to_string().lines().next().unwrap_or("")));
        }
    }
    // Every captured run, in name order.
    let mut runs: BTreeMap<String, (PathBuf, PathBuf)> = BTreeMap::new();
    for corpus in ["datatests", "research"] {
        let dir = out.join(corpus);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            if let Some(stem) = name.strip_suffix(".blocks.bkg") {
                let bks = dir.join(format!("{stem}.structure.bks"));
                runs.insert(format!("{corpus}/{stem}"), (p.clone(), bks));
            }
        }
    }
    // Ghidra's structurer on every captured graph.
    let elseif = ghidra.data_tests_dir().join("elseif.xml");
    let mut script = vec![format!("load test file {}", path_arg(&elseif))];
    for (bkg, _) in runs.values() {
        script.push(format!("bk structure {} {}.ag asgiven trace", path_arg(bkg), path_arg(bkg)));
    }
    reference
        .decomp_bk()
        .timeout(Duration::from_mins(30))
        .run_script(&script)
        .expect("bk structure session");
    let mut text = String::from(HEADER);
    text.push('\n');
    let mut mismatch = Vec::new();
    for (key, (bkg, bks)) in &runs {
        let graph = std::fs::read_to_string(bkg).unwrap();
        let ag = std::fs::read_to_string(format!("{}.ag", bkg.display())).unwrap();
        let captured = std::fs::read_to_string(bks).unwrap();
        let (script_name, run) = key.rsplit_once('.').unwrap();
        let _ = writeln!(text, "{script_name}\t{run}\t{}\t{}\t{}", escape(&graph), hex(digest(ag.as_bytes())), hex(digest(captured.as_bytes())));
        let (full, hier) = basilisk(&GraphFile::parse(&graph).unwrap());
        if full != ag || hier != captured {
            mismatch.push(key.clone());
        }
    }
    let dest = std::env::var("BK_CFG_TABLE_OUT")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(|| table_path(lib), |d| PathBuf::from(d).join(format!("structure_corpus.{}.txt.gz", lib.name())));
    write_gz(&dest, &text);
    eprintln!("corpus capture: {} scripts, {} skipped {skipped:?}, {} structuring runs, {} differ from Basilisk {mismatch:?}; wrote {}", scripts.len(), skipped.len(), runs.len(), mismatch.len(), dest.display());
    let _ = std::fs::remove_dir_all(&out);
}

fn read_table(lib: Library) -> Option<Vec<(String, String, String, String, String)>> {
    let text = read_gz(&table_path(lib))?;
    Some(
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| {
                let f: Vec<&str> = l.splitn(5, '\t').collect();
                (f[0].to_owned(), f[1].to_owned(), unescape(f[2]), f[3].to_owned(), f[4].to_owned())
            })
            .collect(),
    )
}

#[test]
fn replay() {
    let tables: Vec<(Library, Vec<_>)> = [Library::Libcxx, Library::Libstdcxx]
        .into_iter()
        .filter_map(|l| read_table(l).map(|t| (l, t)))
        .collect();
    if tables.is_empty() {
        eprintln!("skipped: no structure_corpus table (tests/oracle/regen_corpus.sh)");
        return;
    }
    if let [(_, a), (_, b)] = &tables[..] {
        assert!(a == b, "the two reference builds captured different corpus runs");
    }
    let rows = &tables[0].1;
    let mut differ = Vec::new();
    let (mut gotos, mut flips, mut rules) = (0usize, 0usize, 0usize);
    for (script, run, graph, ag, captured) in rows {
        let g = GraphFile::parse(graph).unwrap();
        let (full, hier) = basilisk(&g);
        if hex(digest(full.as_bytes())) != *ag || hex(digest(hier.as_bytes())) != *captured {
            differ.push(format!("{script}.{run}"));
        }
        if let Ok(StructureDump::Ok(s)) = StructureDump::parse(&full) {
            gotos += s.gotos.len();
            flips += s.flips.len();
            rules += s.trace.len();
        }
    }
    eprintln!(
        "corpus replay: {} structuring runs, {} differ; {gotos} goto marks, {flips} flips, {rules} rule applications compared",
        rows.len(),
        differ.len()
    );
    assert!(differ.is_empty(), "{differ:?}");
}

/// The largest corpus graph, structured as the pipeline does (6.7).
#[test]
#[ignore = "benchmark"]
fn largest_corpus_graph() {
    let Some(rows) = read_table(Library::Libcxx).or_else(|| read_table(Library::Libstdcxx)) else {
        eprintln!("skipped: no corpus table");
        return;
    };
    let mut steps_ratio: f64 = 0.0;
    let mut largest: Option<(usize, String, GraphFile)> = None;
    for (script, run, graph, _, _) in rows {
        let g = GraphFile::parse(&graph).unwrap();
        let (cfg, facts) = cfg_of(&g);
        let size = cfg.len() + cfg.edge_count();
        let options = StructureOptions {
            limits: Limits { max_steps: Some(u64::MAX / 2), ..Limits::default() },
            ..StructureOptions::default()
        };
        if let Ok(s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) {
            steps_ratio = steps_ratio.max(s.measure.steps as f64 / (size * size) as f64);
        }
        if largest.as_ref().is_none_or(|(n, _, _)| cfg.len() > *n) {
            largest = Some((cfg.len(), format!("{script}.{run}"), g));
        }
    }
    let (n, name, g) = largest.unwrap();
    let (cfg, facts) = cfg_of(&g);
    let mut best = Duration::MAX;
    let mut steps = 0;
    for _ in 0..20 {
        let t = Instant::now();
        let s = structure(&cfg, &facts, &StructureOptions::default(), &mut GhidraGotoSelector::new()).unwrap();
        best = best.min(t.elapsed());
        steps = s.measure.steps;
    }
    eprintln!(
        "bench corpus: largest graph {name}: {n} nodes {} edges, structure (as given) {:.3} ms, {steps} steps; worst steps/(n+e)^2 over the corpus {steps_ratio:.3}",
        cfg.edge_count(),
        best.as_secs_f64() * 1e3
    );
}
