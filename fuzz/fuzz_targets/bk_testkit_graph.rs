//! Arbitrary bytes read as a graph file (`bkgraph 1`) and as an analysis
//! dump (`bkcfg 1`) by `bk-testkit`'s oracle readers. Neither may panic, and
//! whatever is accepted must be written back byte for byte.

#![no_main]

use bk_testkit::oracle::{CfgDump, GraphFile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(graph) = GraphFile::parse(text) {
        assert_eq!(graph.write(), text);
        let _ = graph.out_edges();
        let _ = graph.to_ghidra_xml();
    }
    if let Ok(dump) = CfgDump::parse(text) {
        assert_eq!(dump.write(), text);
    }
});
