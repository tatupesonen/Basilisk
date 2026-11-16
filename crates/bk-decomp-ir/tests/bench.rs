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
//! Spec 6, test 12: benchmarks, as ignored release tests:
//!
//!     cargo test --release -p bk-decomp-ir --test bench -- --ignored --nocapture
//!
//! * loading (and writing back) the largest dump of the corpus capture
//!   (`target/decomp-ir/capture`, made by `tests/corpus.rs`), else the
//!   largest checked-in sample;
//! * creating, inserting and destroying one million ops;
//! * a full walk of the op tree with a rule-like body that inserts a `COPY`
//!   before every third op and destroys every op it inserted;
//! * bytes per op and per varnode ([`MemoryUse`]).
//!
//! Numbers go to `docs/PERF.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bk_core::{Address, NoRegisters, Space, SpaceManager};
use bk_decomp_ir::state::{CanonicalCalls, DumpNames, load, spaces_from_dump, write};
use bk_decomp_ir::{MemoryUse, OpId, Ssa, TableEnv};
use bk_pcode::OpCode;
use bk_testkit::oracle::{StateDump, read_text, sample_dir};
use bk_testkit::workspace_root;

fn best_of<T>(runs: usize, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..runs {
        let t = Instant::now();
        let v = f();
        best = best.min(t.elapsed());
        last = Some(v);
    }
    (best, last.unwrap())
}

fn largest(dir: &Path, best: &mut Option<(u64, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            largest(&p, best);
        } else if p.extension().is_some_and(|x| x == "state" || x == "gz")
            && p.to_string_lossy().contains(".state")
        {
            let len = e.metadata().map_or(0, |m| m.len());
            if best.as_ref().is_none_or(|(l, _)| len > *l) {
                *best = Some((len, p));
            }
        }
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_load_largest_dump() {
    let mut best = None;
    largest(
        &workspace_root().join("target/decomp-ir/capture"),
        &mut best,
    );
    if best.is_none() {
        largest(&sample_dir(), &mut best);
    }
    let (_, path) = best.unwrap();
    let text = read_text(&path).unwrap();
    let dump = StateDump::parse(&text).unwrap();
    let spaces = Arc::new(spaces_from_dump(&dump, Arc::new(NoRegisters)).unwrap());
    let (parse, _) = best_of(5, || StateDump::parse(&text).unwrap());
    let (t_load, ssa) = best_of(5, || load(&dump, Arc::clone(&spaces)).unwrap());
    let names = DumpNames::from_dump(&dump, &spaces);
    let (t_write, _) = best_of(5, || {
        write(&ssa, &dump, &names, &CanonicalCalls::Identity).unwrap()
    });
    let m = ssa.memory_use();
    eprintln!(
        "load {}: {} kB text, {} varnodes, {} ops; parse {:.3} ms, load {:.3} ms, write {:.3} ms; IR {} kB",
        path.file_name().unwrap().to_string_lossy(),
        text.len() / 1000,
        m.varnodes,
        m.ops,
        parse.as_secs_f64() * 1e3,
        t_load.as_secs_f64() * 1e3,
        t_write.as_secs_f64() * 1e3,
        m.total_bytes() / 1000
    );
}

fn function() -> (Ssa, TableEnv, Address, bk_decomp_ir::NodeId) {
    let mut m = SpaceManager::new();
    for s in [
        Space::constant(),
        Space::processor("ram", false, 8, 1, 1, true, 0, 0).unwrap(),
        Space::processor("register", false, 4, 1, 2, false, 0, 0).unwrap(),
        Space::unique(3, false).unwrap(),
        Space::fspec(4).unwrap(),
        Space::iop(5).unwrap(),
        Space::join(6, false).unwrap(),
    ] {
        m.insert_space(s).unwrap();
    }
    let ram = m.space_by_name("ram").unwrap().id();
    let mut ssa = Ssa::new(Arc::new(m), 0x1000_0000).unwrap();
    let b = ssa.add_block(0).unwrap();
    (ssa, TableEnv::default(), Address::new(ram, 0x1000), b)
}

#[test]
#[ignore = "benchmark"]
fn bench_million_ops() {
    const N: usize = 1_000_000;
    let (mut ssa, mut env, pc, b) = function();
    let t = Instant::now();
    let mut ops = Vec::with_capacity(N);
    for i in 0..N {
        let op = ssa.new_op(1, pc.add(ssa.spaces(), (i / 4) as i64)).unwrap();
        ssa.op_set_opcode(op, OpCode::Copy).unwrap();
        let c = ssa.new_constant(&mut env, 4, i as u64).unwrap();
        ssa.op_set_input(&mut env, op, c, 0).unwrap();
        ssa.new_unique_out(&mut env, 4, op).unwrap();
        ops.push(op);
    }
    let create = t.elapsed();
    let t = Instant::now();
    for &op in &ops {
        ssa.op_insert(op, b, None).unwrap();
    }
    let insert = t.elapsed();
    let m = ssa.memory_use();
    let t = Instant::now();
    for &op in &ops {
        ssa.op_destroy(op).unwrap();
    }
    let destroy = t.elapsed();
    eprintln!(
        "1e6 ops: create (op, constant input, unique output) {:.0} ns/op, insert {:.0} ns/op, destroy {:.0} ns/op; {} B per op slot, {} B per varnode slot; {:.1} MB IR ({} B per op with its two varnodes and indexes)",
        create.as_secs_f64() * 1e9 / N as f64,
        insert.as_secs_f64() * 1e9 / N as f64,
        destroy.as_secs_f64() * 1e9 / N as f64,
        MemoryUse::OP_SLOT,
        MemoryUse::VARNODE_SLOT,
        m.total_bytes() as f64 / 1e6,
        m.total_bytes() / N
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_rule_like_walk() {
    const N: usize = 200_000;
    let (mut ssa, mut env, pc, b) = function();
    for i in 0..N {
        let op = ssa.new_op(1, pc.add(ssa.spaces(), i as i64)).unwrap();
        ssa.op_set_opcode(op, OpCode::Copy).unwrap();
        let c = ssa.new_constant(&mut env, 4, i as u64).unwrap();
        ssa.op_set_input(&mut env, op, c, 0).unwrap();
        ssa.new_unique_out(&mut env, 4, op).unwrap();
        ssa.op_insert(op, b, None).unwrap();
    }
    let t = Instant::now();
    let walk: Vec<OpId> = ssa.ops_main().collect();
    let mut inserted = Vec::new();
    for (i, op) in walk.into_iter().enumerate() {
        if i % 3 != 0 || !ssa.op_exists(op) {
            continue;
        }
        let x = ssa.op_output(op).unwrap();
        let k = ssa.new_constant(&mut env, 4, 1).unwrap();
        let new = ssa.new_op_before(&mut env, op, OpCode::IntAdd, (x, k, None));
        if let Ok(new) = new {
            inserted.push(new);
        }
    }
    for op in inserted {
        ssa.op_destroy(op).unwrap();
    }
    let el = t.elapsed();
    eprintln!(
        "rule-like walk over {N} ops (insert before every third, then destroy those): {:.1} ms, {:.0} ns per visited op",
        el.as_secs_f64() * 1e3,
        el.as_secs_f64() * 1e9 / N as f64
    );
}
