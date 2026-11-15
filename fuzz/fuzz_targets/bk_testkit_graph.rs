//! Arbitrary bytes read as a graph file (`bkgraph 1`) and as an analysis
//! dump (`bkcfg 1`) by `bk-testkit`'s oracle readers. Neither may panic, and
//! whatever is accepted must be written back byte for byte.

#![no_main]

mod bk_testkit_shared;

use bk_testkit::oracle::{CfgDump, GraphFile};
use libfuzzer_sys::fuzz_target;

const GRAPH: &str = include_str!("../../crates/bk-testkit/tests/data/oracle/elseif.blocks.bkg");
const CFG: &str = include_str!("../../crates/bk-testkit/tests/data/oracle/elseif.cfg");

fuzz_target!(|data: &[u8]| {
    let pick = data.get(1).copied().unwrap_or(0) % 2;
    let Some(text) = bk_testkit_shared::text(data, if pick == 0 { GRAPH } else { CFG }) else {
        return;
    };
    if let Ok(graph) = GraphFile::parse(&text) {
        assert_eq!(graph.write(), text);
        let _ = graph.out_edges();
        let _ = graph.to_ghidra_xml();
    }
    if let Ok(dump) = CfgDump::parse(&text) {
        assert_eq!(dump.write(), text);
    }
});
