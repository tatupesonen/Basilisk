//! Arbitrary bytes read as a control-flow graph (nodes, edges, indices,
//! dominators, labels, facts; at most 512 nodes) and structured by
//! `bk-decomp-cfg` in both modes, then finished. The process must not
//! panic, overflow the stack, hang or exceed the limits it is given.

#![no_main]

use bk_decomp_cfg::{
    Analyse, BlockFacts, Cfg, Fact, GhidraGotoSelector, Limits, NodeId, StructureOptions,
    edge_labels, finish, structure,
};
use libfuzzer_sys::fuzz_target;

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn next(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes(data);
    let n = (usize::from(b.next()) | (usize::from(b.next() & 1) << 8)).min(512);
    let mut cfg = Cfg::new();
    let ids: Vec<NodeId> = (0..n).filter_map(|_| cfg.add_node(0).ok()).collect();
    let mut facts = BlockFacts::neutral(n);
    for (i, &id) in ids.iter().enumerate() {
        let degree = usize::from(b.next() % 8);
        for _ in 0..degree {
            let t = usize::from(b.next()) % n.max(1);
            if let Some(&to) = ids.get(t) {
                let _ = cfg.add_edge(id, to);
            }
        }
        let f = b.next();
        facts.set(i, Fact {
            complex: f & 1 != 0,
            switch_out: f & 2 != 0,
            ends_in_return: f & 4 != 0,
            negation_changes_dataflow: f & 8 != 0,
        });
        let _ = cfg.set_index(id, i32::from(b.next()) - 8);
    }
    // Labels and dominators as a hostile pipeline might hand them over.
    for &id in &ids {
        let sel = b.next();
        if sel & 0x80 != 0 {
            let slot = usize::from(sel & 7);
            let label = match sel & 0x30 {
                0x00 => edge_labels::GOTO,
                0x10 => edge_labels::DEFAULT_SWITCH,
                0x20 => edge_labels::BACK | edge_labels::LOOP,
                _ => edge_labels::IRREDUCIBLE,
            };
            let _ = cfg.set_out_edge_label(id, slot, label);
        }
        if sel & 0x40 != 0 {
            let d = ids.get(usize::from(b.next()) % n.max(1)).copied();
            let _ = cfg.set_idom(id, d);
        }
    }
    let limits = Limits { max_steps: Some(4_000_000), ..Limits::default() };
    for analyse in [Analyse::Recompute, Analyse::AsGiven] {
        let options = StructureOptions { analyse, limits, ..StructureOptions::default() };
        if let Ok(mut s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) {
            let _ = finish(&mut s.hierarchy, &facts, None);
            let mut enc = bk_marshal::XmlEncoder::new(false);
            let _ = s.hierarchy.encode(&mut enc);
        }
    }
    let mut analysed = cfg.clone();
    if let Ok(roots) = analysed.structure_loops() {
        let _ = analysed.forward_dominators(&roots);
        let _ = analysed.dom_tree();
        let _ = analysed.dom_depth();
        let options = StructureOptions { limits, ..StructureOptions::default() };
        let _ = structure(&analysed, &facts, &options, &mut GhidraGotoSelector::new());
    }
});
