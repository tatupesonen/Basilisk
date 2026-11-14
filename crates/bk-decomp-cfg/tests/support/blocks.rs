//! `structure blocks` in Basilisk: decode a bare graph, structure it as the
//! console's command does (`Analyse::Recompute`, neutral facts, no
//! `finish`), encode the result.

use bk_decomp_cfg::{
    Analyse, BlockFacts, Cfg, GhidraGotoSelector, Limits, StructureOptions, structure,
};
use bk_marshal::XmlEncoder;

/// The output `structure blocks <in> <out>` writes for `xml`, or the error
/// message it prints.
pub(crate) fn structure_blocks(xml: &str) -> Result<String, String> {
    let cfg = Cfg::decode_xml(xml, &Limits::default()).map_err(|e| e.to_string())?;
    let facts = BlockFacts::neutral(cfg.id_bound());
    let options = StructureOptions {
        analyse: Analyse::Recompute,
        ..StructureOptions::default()
    };
    let s = structure(&cfg, &facts, &options, &mut GhidraGotoSelector::new())
        .map_err(|e| e.to_string())?;
    let mut enc = XmlEncoder::new(true);
    s.hierarchy.encode(&mut enc).map_err(|e| e.to_string())?;
    Ok(enc.into_string())
}
