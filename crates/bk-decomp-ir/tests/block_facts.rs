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
//! Spec 6, test 9 (L): the block facts of a loaded state equal the facts the
//! console's `bk dump blocks` writes at the same moment
//! (`tools/reference/consoleext/bk_cfg.cc`, `writeBasicGraph`), for every
//! decompilation of both corpora, at the start of each `blockstructure`
//! (both instances, found by path) and once more at the stop after that
//! (where the console has finished, the end).
//!
//! The capture is made into `target/decomp-ir/facts` (re-used when
//! present). `max_implied_ref` is Ghidra's default, 2
//! (`architecture.cc:1421`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bk_core::NoRegisters;
use bk_decomp_ir::state::{load, spaces_from_dump};
use bk_testkit::oracle::capture::{CorpusScript, data_tests, is_decompile, research};
use bk_testkit::oracle::{ActionList, GraphFile, StateDump, read_text};
use bk_testkit::{Tool, require_ghidra, require_tool, workspace_root};

const STOPS: usize = 3;

/// The stops whose dump and graph are compared.
const STOPS_COMPARED: usize = 1684;

/// The dumps `bk-testkit` cannot read because a dead op has an empty input
/// slot (`-`); waiting on the reader change that goes with `@joins`.
const UNREADABLE: &str = include_str!("data/facts_unreadable.txt");

fn script(s: &CorpusScript, positions: &[u32], out: &Path) -> Vec<String> {
    let mut lines = vec![s.load.clone()];
    let mut k = 0;
    for c in &s.commands {
        if !is_decompile(c) {
            lines.push(c.clone());
            continue;
        }
        for p in positions {
            lines.push(format!("bk break start {p}"));
        }
        lines.push(c.clone());
        for n in 0..STOPS {
            let f = |kind: &str| {
                out.join(format!("{}.{k}.{n}.{kind}", s.name))
                    .display()
                    .to_string()
            };
            lines.push(format!("bk dump state {}", f("state")));
            lines.push(format!("bk dump blocks {}", f("bkg")));
            lines.push("continue".into());
        }
        lines.push("bk break clear".into());
        lines.push("continue".into());
        k += 1;
    }
    lines
}

#[test]
fn block_facts_equal_the_consoles_at_blockstructure() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let out = workspace_root().join("target/decomp-ir/facts");
    let mut scripts = data_tests(&ghidra).unwrap();
    scripts.extend(research(&workspace_root()).unwrap());
    if !out.join("done").is_file() {
        std::fs::create_dir_all(&out).unwrap();
        let listing = reference
            .decomp_bk()
            .current_dir(ghidra.data_tests_dir())
            .run_script(["load test file elseif.xml", "bk list actions"])
            .unwrap();
        let actions =
            ActionList::parse(listing.outputs_of("bk list actions").next().unwrap()).unwrap();
        let positions: Vec<u32> = [
            "universal:fullloop:mainloop:blockstructure",
            "universal:blockstructure",
        ]
        .iter()
        .map(|p| actions.position_of(p).unwrap_or_else(|| panic!("no {p}")))
        .collect();
        let queue = Arc::new(Mutex::new(scripts.clone()));
        let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        let handles: Vec<_> = (0..jobs)
            .map(|_| {
                let (queue, reference, out, positions) = (
                    Arc::clone(&queue),
                    reference.clone(),
                    out.clone(),
                    positions.clone(),
                );
                std::thread::spawn(move || {
                    while let Some(s) = queue.lock().unwrap().pop() {
                        let _ = reference
                            .decomp_bk()
                            .current_dir(&s.dir)
                            .run_script(script(&s, &positions, &out));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        std::fs::write(out.join("done"), "").unwrap();
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "state"))
        .collect();
    files.sort();
    let (mut compared, mut blocks, mut bad) = (0, 0, Vec::new());
    let (mut unreadable, mut skipped) = (Vec::new(), 0);
    for state in &files {
        let bkg = state.with_extension("bkg");
        let (Ok(st), Ok(g)) = (read_text(state), read_text(&bkg)) else {
            skipped += 1;
            continue;
        };
        // A dump whose dead ops have empty input slots (`-`) does not
        // parse: `bk-testkit` reads an op's inputs as a plain list (a
        // follow-up for the reader). Counted, and only that error allowed.
        let dump = match StateDump::parse(&st) {
            Ok(d) => d,
            Err(e) if format!("{e:?}").contains("field: \"inputs\"") => {
                unreadable.push(state.file_name().unwrap().to_string_lossy().into_owned());
                continue;
            }
            Err(e) => panic!("{}: {e}", state.display()),
        };
        let graph = GraphFile::parse(&g).unwrap();
        let spaces = Arc::new(spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap());
        let ssa = load(&dump, spaces).unwrap();
        let ours: Vec<_> = ssa.blocks().collect();
        compared += 1;
        if ours.len() != graph.nodes.len() {
            bad.push(format!(
                "{}: {} blocks, console {}",
                state.display(),
                ours.len(),
                graph.nodes.len()
            ));
            continue;
        }
        for (b, node) in ours.iter().zip(&graph.nodes) {
            blocks += 1;
            let f = ssa.block_fact(*b, 2);
            let got = (
                f.complex,
                f.switch_out,
                f.ends_in_return,
                f.negation_changes_dataflow,
            );
            let want = (
                node.facts.complex,
                node.facts.switch_out,
                node.facts.ends_in_return,
                node.facts.negation_changes_dataflow,
            );
            if got != want || ssa.cfg().index(*b) != Some(node.index as i32) {
                bad.push(format!(
                    "{} block {}: ours {got:?}, console {want:?}",
                    state.display(),
                    node.index
                ));
            }
        }
    }
    eprintln!(
        "block facts: {compared} stops, {blocks} blocks compared, {} differ; {} dumps with empty input slots unreadable; {skipped} stops without a graph",
        bad.len(),
        unreadable.len()
    );
    std::fs::write(
        workspace_root().join("target/decomp-ir/facts-unreadable.txt"),
        unreadable.join("\n"),
    )
    .unwrap();
    // Pinned (2026-11-16 capture; the same on the Mac and the build host
    // for these scripts): the exception may not grow unnoticed.
    assert_eq!(
        (compared, skipped),
        (STOPS_COMPARED, 0),
        "stops compared / without a graph"
    );
    let pinned: Vec<&str> = UNREADABLE.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(unreadable, pinned, "dumps with empty input slots");
    assert!(bad.is_empty(), "{:#?}", &bad[..bad.len().min(30)]);
}
