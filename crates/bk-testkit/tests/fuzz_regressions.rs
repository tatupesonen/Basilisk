//! Replays every input the fuzzer found against the oracle readers
//! (`fuzz/regressions/bk_testkit_*`), through the targets' own input
//! transformation (`fuzz/fuzz_targets/bk_testkit_shared`): none may panic,
//! loop or exhaust memory, and whatever is accepted must be written back
//! byte for byte.

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

#[path = "../../../fuzz/fuzz_targets/bk_testkit_shared/mod.rs"]
mod shared;

use std::time::{Duration, Instant};

use bk_testkit::oracle::{
    ActionList, CfgDump, GraphFile, RecordedPcode, Recording, StateDump, StructureDump, Trace,
    read_text, sample_dir,
};
use bk_testkit::workspace_root;

fn inputs(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = workspace_root().join("fuzz/regressions").join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Vec<u8>)> = entries
        .map(|e| e.unwrap().path())
        .map(|p| (p.display().to_string(), std::fs::read(&p).unwrap()))
        .collect();
    out.sort();
    out
}

fn sample(name: &str) -> String {
    read_text(&sample_dir().join(name)).unwrap()
}

/// Run `check` on every regression input of `target` against `samples`
/// (picked by the input's second byte, as the targets do), in bounded time.
fn replay(target: &str, samples: &[String], check: fn(&str)) {
    for (name, data) in inputs(target) {
        let pick = usize::from(data.get(1).copied().unwrap_or(0)) % samples.len();
        let started = Instant::now();
        if let Some(text) = shared::text(&data, &samples[pick]) {
            check(&text);
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{name} took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn graph_and_analysis_inputs() {
    replay(
        "bk_testkit_graph",
        &[sample("elseif.blocks.bkg"), sample("elseif.cfg")],
        |text| {
            if let Ok(g) = GraphFile::parse(text) {
                assert_eq!(g.write(), text);
            }
            if let Ok(d) = CfgDump::parse(text) {
                assert_eq!(d.write(), text);
            }
        },
    );
}

#[test]
fn structure_and_action_inputs() {
    replay(
        "bk_testkit_structure",
        &[sample("random.trace.bks"), sample("decompile.actions")],
        |text| {
            if let Ok(d) = StructureDump::parse(text) {
                assert_eq!(d.write(), text);
            }
            if let Ok(l) = ActionList::parse(text) {
                assert_eq!(l.write(), text);
            }
        },
    );
}

#[test]
fn state_inputs() {
    replay(
        "bk_testkit_state",
        &[sample("switchind.end.state.gz")],
        |text| {
            if let Ok(d) = StateDump::parse(text) {
                assert_eq!(d.write(), text);
            }
        },
    );
}

#[test]
fn trace_inputs() {
    let sample = "Decompiling f\nDEBUG 0: constbase\n0x001006ca:287: **\n   0x001006ca:287: DF(0x001006ca:287) = #0x0:1\n\n\
DEBUG 1: extrapopsetup\n0x00100708:288: **\n   0x00100708:288: RSP(0x00100708:288) = RSP(free) + #0x8\n\nDecompilation complete\n";
    replay("bk_testkit_trace", &[sample.to_owned()], |text| {
        if let Ok(t) = Trace::extract(text) {
            assert_eq!(Trace::extract(&t.write()).ok(), Some(t));
        }
    });
}

#[test]
fn recording_inputs() {
    replay(
        "bk_testkit_pcoderec",
        &[sample("elseif.pcoderec.gz")],
        |text| {
            if let Ok(r) = Recording::parse(text) {
                assert_eq!(r.write(), text);
                let addrs: Vec<_> = r.events.iter().map(|e| e.addr().clone()).collect();
                let replay = RecordedPcode::new(r);
                for a in &addrs {
                    let _ = replay.instruction(a);
                }
            }
        },
    );
}
