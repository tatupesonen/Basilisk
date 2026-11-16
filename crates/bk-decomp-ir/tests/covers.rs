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
//! Spec 6, test 8 (L): for the final state of every decompilation of both
//! corpora, the cover of a sample of varnodes (up to eight written or input
//! varnodes per function, spread over the def order) printed by
//! [`Ssa::print_cover`] equals the console's `print cover varnode`
//! (`IfcVarnodeCover`, `ifacedecomp.cc:1681`; `Cover::print`,
//! `cover.cc:615`). Where the console's cover is dirty (`Varnode::printCover`,
//! `varnode.cc:274`) or absent, nothing is compared; those are counted.
//!
//! The end states come from the corpus capture (`tests/corpus.rs`, into
//! `target/decomp-ir/capture`); the test makes it when absent.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bk_core::NoRegisters;
use bk_decomp_ir::state::{load, spaces_from_dump};
use bk_decomp_ir::{Ssa, VarnodeId};
use bk_testkit::oracle::capture::{self, CorpusScript, is_decompile};
use bk_testkit::oracle::{StateDump, read_text};
use bk_testkit::{Tool, require_ghidra, require_tool, workspace_root};

const PER_FUNCTION: usize = 8;

/// One comparison: the function, the console command, our text.
type Case = (String, String, Option<String>);

/// The console's spelling of a varnode (`parse_varnode`, `grammar.y:1490`).
fn spelling(ssa: &Ssa, vn: VarnodeId) -> Option<String> {
    let flags = ssa.varnode_flags(vn);
    let addr = ssa.varnode_addr(vn);
    let space = ssa.spaces().space_of(addr)?;
    let code = ssa.spaces().default_code_space()?;
    let mut s = format!(
        "[{},{:#x},{}](",
        space.name(),
        addr.offset(),
        ssa.varnode_size(vn)
    );
    if ssa.is_input(vn) {
        s.push('i');
    } else {
        let def = ssa.varnode_def(vn)?;
        let pc = ssa.op_addr(def);
        if pc.space() != Some(code.id()) {
            return None;
        }
        let _ = write!(s, "{:#x}:{:x}", pc.offset(), ssa.op_time(def));
    }
    s.push(')');
    let skip = bk_decomp_ir::flags::vflags::CONSTANT | bk_decomp_ir::flags::vflags::ANNOTATION;
    (flags & skip == 0 && ssa.has_cover(vn)).then_some(s)
}

#[test]
fn covers_print_as_the_console() {
    let Some(reference) = require_tool(Tool::DecompBk) else {
        return;
    };
    let Some(ghidra) = require_ghidra() else {
        return;
    };
    let cap = workspace_root().join("target/decomp-ir/capture");
    let mut scripts = capture::data_tests(&ghidra).unwrap();
    scripts.extend(capture::research(&workspace_root()).unwrap());
    if !cap.join("datatests").is_dir() {
        let positions = capture::find_positions(&reference, &ghidra).unwrap();
        let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        capture::capture_corpus(&reference, &scripts, &positions, &cap, jobs);
    }
    // Per script: the commands, and what we expect for each.
    let mut work: Vec<(CorpusScript, Vec<String>, Vec<Case>)> = Vec::new();
    for s in &scripts {
        let mut lines = vec![s.load.clone()];
        let mut cases = Vec::new();
        let mut k = 0;
        for c in &s.commands {
            lines.push(c.clone());
            if !is_decompile(c) {
                continue;
            }
            let path: PathBuf = cap.join(s.corpus).join(format!("{}.{k}.end.state", s.name));
            k += 1;
            let Ok(text) = read_text(&path) else {
                continue;
            };
            let dump = StateDump::parse(&text).unwrap();
            let spaces = Arc::new(spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap());
            let ssa = load(&dump, spaces).unwrap();
            let named: Vec<(VarnodeId, String)> = ssa
                .def_order()
                .filter_map(|v| spelling(&ssa, v).map(|s| (v, s)))
                .collect();
            let step = named.len().div_ceil(PER_FUNCTION).max(1);
            for (vn, sp) in named.iter().step_by(step) {
                let cmd = format!("print cover varnode {sp}");
                lines.push(cmd.clone());
                cases.push((format!("{}.{}", s.name, k - 1), cmd, ssa.print_cover(*vn)));
            }
        }
        if !cases.is_empty() {
            work.push((s.clone(), lines, cases));
        }
    }
    let results = Arc::new(Mutex::new(BTreeMap::new()));
    let queue = Arc::new(Mutex::new(work));
    let jobs = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let handles: Vec<_> = (0..jobs)
        .map(|_| {
            let (queue, results, reference) =
                (Arc::clone(&queue), Arc::clone(&results), reference.clone());
            std::thread::spawn(move || {
                while let Some((s, lines, cases)) = queue.lock().unwrap().pop() {
                    let t = reference.decomp_bk().current_dir(&s.dir).run_script(lines);
                    results.lock().unwrap().insert(s.name.clone(), (t, cases));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let (mut equal, mut dirty, mut other, mut bad) = (0, 0, 0, Vec::new());
    for (name, (t, cases)) in results.lock().unwrap().iter() {
        let t = t.as_ref().unwrap_or_else(|e| panic!("{name}: {e}"));
        // The console's outputs of the cover commands, in order.
        let mut outputs = t
            .steps
            .iter()
            .filter(|s| s.command.starts_with("print cover varnode"));
        for (func, cmd, ours) in cases {
            let console = outputs.next().map_or("", |s| s.output.as_str());
            if console.starts_with("Cover is dirty") {
                dirty += 1;
            } else if console.contains("No cover")
                || console.contains("Unknown varnode")
                || console.contains("rror")
            {
                other += 1;
            } else if ours.as_deref() == Some(console) {
                equal += 1;
            } else {
                bad.push(format!(
                    "{func} {cmd}\n console {console:?}\n ours    {ours:?}"
                ));
            }
        }
    }
    eprintln!(
        "covers: {equal} equal, {} differ, {dirty} dirty in the console, {other} not printed",
        bad.len()
    );
    for b in bad.iter().take(5) {
        eprintln!("{b}");
    }
    assert!(equal > 0);
    assert!(bad.is_empty(), "{}", bad[..bad.len().min(20)].join("\n"));
}
