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
//! Benchmarks (`docs/features/decomp-cfg.md` 6.7), as ignored release
//! tests: `cargo test --release -p bk-decomp-cfg --test bench -- --ignored
//! --nocapture`. Numbers go to `docs/PERF.md`.

mod support {
    pub(crate) mod graphgen;
}

use std::time::{Duration, Instant};

use bk_decomp_cfg::{Analyse, Cfg, GhidraGotoSelector, Limits, StructureOptions, structure};
use support::graphgen::{GenGraph, generate_func_sized, generate_large_reducible};

fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..runs {
        let t = Instant::now();
        let r = f();
        best = best.min(t.elapsed());
        last = Some(r);
    }
    (best, last.unwrap())
}

#[test]
#[ignore = "benchmark"]
fn analyses() {
    for n in [1_000usize, 10_000, 100_000] {
        let g = generate_func_sized(42, n);
        let c = g.to_cfg();
        let (t, _) = best_of(5, || {
            let mut a = c.clone();
            let roots = a.structure_loops().unwrap();
            a.forward_dominators(&roots).unwrap();
            a
        });
        eprintln!(
            "bench analyses: {} nodes {} edges: structure_loops + forward_dominators {:.3} ms ({:.0} ns/node)",
            c.len(),
            c.edge_count(),
            t.as_secs_f64() * 1e3,
            t.as_secs_f64() * 1e9 / c.len() as f64
        );
    }
}

fn structure_bench(label: &str, g: &GenGraph) {
    let c = g.to_cfg();
    let facts = g.block_facts();
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        limits: Limits {
            max_steps: Some(u64::MAX / 2),
            ..Limits::default()
        },
        ..StructureOptions::default()
    };
    let (t, r) = best_of(3, || {
        structure(&c, &facts, &options, &mut GhidraGotoSelector::new())
    });
    let steps = r.as_ref().map(|s| s.measure.steps).unwrap_or(0);
    let gotos = r
        .as_ref()
        .map(|s| s.measure.goto_marks.total())
        .unwrap_or(0);
    let size = (c.len() + c.edge_count()) as u64;
    eprintln!(
        "bench structure {label}: {} nodes {} edges: {:.3} ms, {steps} steps ({:.2} x (n+e)^2, default limit {}), {gotos} gotos, {}",
        c.len(),
        c.edge_count(),
        t.as_secs_f64() * 1e3,
        steps as f64 / (size * size) as f64,
        Limits::default_steps(c.len() as u64, c.edge_count() as u64),
        if r.is_ok() {
            "ok".to_owned()
        } else {
            format!("{:?}", r.err())
        }
    );
}

#[test]
#[ignore = "benchmark"]
fn structuring() {
    for n in [1_000usize, 10_000] {
        structure_bench("reducible", &generate_large_reducible(7, n));
    }
    for n in [1_000usize, 3_000] {
        structure_bench("function-like", &generate_func_sized(9, n));
    }
}

#[test]
#[ignore = "benchmark"]
fn memory() {
    let g = generate_large_reducible(7, 10_000);
    let c: Cfg = g.to_cfg();
    let per_node = bk_decomp_cfg::NODE_BYTES;
    let per_edge = 2 * bk_decomp_cfg::EDGE_HALF_BYTES;
    eprintln!(
        "bench memory: {per_node} bytes per node (without lists), {per_edge} bytes per edge (two halves); graph of {} nodes {} edges: about {} KiB",
        c.len(),
        c.edge_count(),
        (c.len() * per_node + c.edge_count() * per_edge) / 1024
    );
}

/// The reference console's time for `structure blocks` on the same graphs
/// (wall clock of one console run minus a run that only loads).
#[test]
#[ignore = "benchmark; needs the reference console"]
fn reference_console() {
    let Some(reference) = bk_testkit::require_tool(bk_testkit::Tool::Decomp) else {
        return;
    };
    let Some(ghidra) = bk_testkit::require_ghidra() else {
        return;
    };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bk-cfg-bench");
    std::fs::create_dir_all(&dir).unwrap();
    let load = format!(
        "load test file {}",
        ghidra.data_tests_dir().join("elseif.xml").display()
    );
    let base = best_of(3, || {
        reference.decomp().run_script([load.as_str()]).unwrap()
    })
    .0;
    for (label, g) in [
        ("reducible 1000", generate_large_reducible(7, 1_000)),
        ("reducible 10000", generate_large_reducible(7, 10_000)),
        ("function-like 1000", generate_func_sized(9, 1_000)),
    ] {
        let input = dir.join("g.xml");
        std::fs::write(&input, g.to_xml()).unwrap();
        let cmd = format!(
            "structure blocks {} {}",
            input.display(),
            dir.join("g.out").display()
        );
        let (t, _) = best_of(3, || {
            reference
                .decomp()
                .timeout(Duration::from_mins(10))
                .run_script([load.as_str(), cmd.as_str()])
                .unwrap()
        });
        eprintln!(
            "bench reference structure blocks {label}: {:.3} ms (console run minus load)",
            (t.saturating_sub(base)).as_secs_f64() * 1e3
        );
    }
}
