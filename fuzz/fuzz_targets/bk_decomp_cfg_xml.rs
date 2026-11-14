//! Arbitrary text decoded as a block document (`structure blocks` input)
//! by `bk-decomp-cfg`, then structured and encoded as the console's command
//! does. The process must not panic, overflow the stack or hang.

#![no_main]

use bk_decomp_cfg::{Analyse, BlockFacts, Cfg, GhidraGotoSelector, Limits, StructureOptions, structure};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let limits = Limits { max_nodes: 4096, max_edges: 16384, max_steps: Some(4_000_000) };
    let Ok(cfg) = Cfg::decode_xml(text, &limits) else { return };
    let facts = BlockFacts::neutral(cfg.id_bound());
    let options = StructureOptions { analyse: Analyse::Recompute, limits, ..StructureOptions::default() };
    if let Ok(s) = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new()) {
        let mut enc = bk_marshal::XmlEncoder::new(true);
        let _ = s.hierarchy.encode(&mut enc);
    }
});
