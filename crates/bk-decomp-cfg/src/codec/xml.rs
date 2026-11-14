//! The block XML that `structure blocks` reads and writes.
//!
//! Ghidra: `BlockEdge::encode/decode` (block.cc:35, 48),
//! `FlowBlock::encode/decode` (2528, 2543), `encodeHeader/decodeHeader`
//! (2488, 2495), `encodeEdges/decodeEdges` (2503, 2515),
//! `decodeNextInEdge` (89), `BlockGraph::encodeBody/decodeBody` (1390,
//! 1407), the `encodeBody` of `BlockGoto` (2967), `BlockMultiGoto` (3000)
//! and `BlockIfGoto` (3259), the `encodeHeader` of `BlockCopy` (2910) and
//! `BlockCondition` (3121), and `BlockMap` (3788–3844). Edge labels are not
//! encoded. Encoding walks the hierarchy with an explicit stack.

use bk_marshal::ids::{ATTRIB_INDEX, ATTRIB_TYPE, ATTRIBUTES, ELEM_TARGET, ELEMENTS};
use bk_marshal::{
    AttributeId, Decoder, Document, ElementId, Encoder, IdTable, NoSpaces, XmlDecoder,
};

use crate::cfg::Cfg;
use crate::error::{CfgError, LimitKind};
use crate::flags::{Kind, name_to_kind};
use crate::graph::{Edge, Graph, KindData, NodeId, to_u32};
use crate::hierarchy::Hierarchy;
use crate::limits::Limits;

/// Marshaling attribute `altindex` (block.cc:22).
pub const ATTRIB_ALTINDEX: AttributeId = AttributeId::new("altindex", 75);
/// Marshaling attribute `depth` (block.cc:23).
pub const ATTRIB_DEPTH: AttributeId = AttributeId::new("depth", 76);
/// Marshaling attribute `end` (block.cc:24).
pub const ATTRIB_END: AttributeId = AttributeId::new("end", 77);
/// Marshaling attribute `opcode` (block.cc:25).
pub const ATTRIB_OPCODE: AttributeId = AttributeId::new("opcode", 78);
/// Marshaling attribute `rev` (block.cc:26).
pub const ATTRIB_REV: AttributeId = AttributeId::new("rev", 79);
/// Marshaling element `bhead` (block.cc:28).
pub const ELEM_BHEAD: ElementId = ElementId::new("bhead", 102);
/// Marshaling element `block` (block.cc:29).
pub const ELEM_BLOCK: ElementId = ElementId::new("block", 103);
/// Marshaling element `blockedge` (block.cc:30).
pub const ELEM_BLOCKEDGE: ElementId = ElementId::new("blockedge", 104);
/// Marshaling element `edge` (block.cc:31).
pub const ELEM_EDGE: ElementId = ElementId::new("edge", 105);

/// The attribute ids of `block.cc`.
pub static BLOCK_ATTRIBUTES: &[AttributeId] = &[
    ATTRIB_ALTINDEX,
    ATTRIB_DEPTH,
    ATTRIB_END,
    ATTRIB_OPCODE,
    ATTRIB_REV,
];
/// The element ids of `block.cc`.
pub static BLOCK_ELEMENTS: &[ElementId] = &[ELEM_BHEAD, ELEM_BLOCK, ELEM_BLOCKEDGE, ELEM_EDGE];

fn dec(e: &bk_marshal::DecodeError) -> CfgError {
    CfgError::Decode(e.to_string())
}

fn write_edges(g: &Graph, enc: &mut dyn Encoder, ins: &[Edge]) {
    for e in ins {
        enc.open_element(ELEM_EDGE);
        enc.write_signed(ATTRIB_END, i64::from(g.node(e.other).index));
        enc.write_signed(ATTRIB_REV, i64::from(e.rev));
        enc.close_element(ELEM_EDGE);
    }
}

fn write_bheads(g: &Graph, enc: &mut dyn Encoder, comps: &[NodeId]) -> Result<(), CfgError> {
    for &c in comps {
        let node = g.node(c);
        enc.open_element(ELEM_BHEAD);
        enc.write_signed(ATTRIB_INDEX, i64::from(node.index));
        enc.write_string(ATTRIB_TYPE, node.kind.type_name())
            .map_err(|e| CfgError::Decode(e.to_string()))?;
        enc.close_element(ELEM_BHEAD);
    }
    Ok(())
}

fn write_target(g: &Graph, enc: &mut dyn Encoder, target: NodeId, goto_type: Option<u32>) {
    let leaf = g.front_leaf(target);
    let depth = g.calc_depth(target, leaf);
    enc.open_element(ELEM_TARGET);
    enc.write_signed(ATTRIB_INDEX, i64::from(leaf.map_or(0, |l| g.node(l).index)));
    enc.write_signed(ATTRIB_DEPTH, i64::from(depth));
    if let Some(t) = goto_type {
        enc.write_unsigned(ATTRIB_TYPE, u64::from(t));
    }
    enc.close_element(ELEM_TARGET);
}

enum Step {
    Enter(NodeId),
    Exit(NodeId),
}

/// `BlockGraph::encode` of the top-level graph of `h` (what `structure
/// blocks` writes). `orig_index` gives each copy's `altindex`, the index of
/// its original block.
pub(crate) fn encode_hierarchy(
    h: &Hierarchy,
    orig_index: &dyn Fn(NodeId) -> i32,
    enc: &mut dyn Encoder,
) -> Result<(), CfgError> {
    let g = &h.g;
    enc.open_element(ELEM_BLOCK);
    enc.write_signed(ATTRIB_INDEX, i64::from(h.root_index()));
    write_bheads(g, enc, &g.list)?;
    let mut stack: Vec<Step> = g.list.iter().rev().map(|&n| Step::Enter(n)).collect();
    while let Some(step) = stack.pop() {
        match step {
            Step::Enter(n) => {
                let node = g.node(n);
                enc.open_element(ELEM_BLOCK);
                enc.write_signed(ATTRIB_INDEX, i64::from(node.index));
                match (node.kind, &node.data) {
                    (Kind::Copy, _) => {
                        enc.write_signed(ATTRIB_ALTINDEX, i64::from(orig_index(n)));
                    }
                    (Kind::Condition, KindData::Condition(op)) => {
                        enc.write_string(ATTRIB_OPCODE, op.name())
                            .map_err(|e| CfgError::Decode(e.to_string()))?;
                    }
                    _ => {}
                }
                if node.kind.is_structured() {
                    write_bheads(g, enc, &node.comps)?;
                    stack.push(Step::Exit(n));
                    stack.extend(node.comps.iter().rev().map(|&c| Step::Enter(c)));
                } else {
                    write_edges(g, enc, &node.ins);
                    enc.close_element(ELEM_BLOCK);
                }
            }
            Step::Exit(n) => {
                let node = g.node(n);
                match (&node.kind, &node.data) {
                    (Kind::Goto | Kind::IfGoto, &KindData::Goto { target, goto_type }) => {
                        write_target(g, enc, target, Some(goto_type));
                    }
                    (Kind::MultiGoto, KindData::MultiGoto { targets, .. }) => {
                        for &t in targets {
                            write_target(g, enc, t, None);
                        }
                    }
                    _ => {}
                }
                write_edges(g, enc, &node.ins);
                enc.close_element(ELEM_BLOCK);
            }
        }
    }
    enc.close_element(ELEM_BLOCK);
    Ok(())
}

/// Writes a flat graph as a block document (`BlockGraph::encode` of a graph
/// of plain blocks): what `structure blocks` reads.
pub(crate) fn encode_cfg(cfg: &Cfg, enc: &mut dyn Encoder) -> Result<(), CfgError> {
    let g = &cfg.g;
    enc.open_element(ELEM_BLOCK);
    enc.write_signed(ATTRIB_INDEX, i64::from(g.root_index.unwrap_or(0)));
    write_bheads(g, enc, &g.list)?;
    for &n in &g.list {
        enc.open_element(ELEM_BLOCK);
        enc.write_signed(ATTRIB_INDEX, i64::from(g.node(n).index));
        write_edges(g, enc, &g.node(n).ins);
        enc.close_element(ELEM_BLOCK);
    }
    enc.close_element(ELEM_BLOCK);
    Ok(())
}

/// `BlockMap::findBlock` (block.cc:3808): binary search of `sortlist` by
/// the blocks' current indices.
fn find_block(g: &Graph, sortlist: &[NodeId], ind: i64) -> Option<NodeId> {
    let mut min: i64 = 0;
    let mut max: i64 = sortlist.len() as i64 - 1;
    while min <= max {
        let mid = min.midpoint(max);
        let block = *sortlist.get(usize::try_from(mid).ok()?)?;
        let bi = i64::from(g.node(block).index);
        if bi == ind {
            return Some(block);
        }
        if bi < ind {
            min = mid + 1;
        } else {
            max = mid - 1;
        }
    }
    None
}

fn to_index(v: i64) -> Result<i32, CfgError> {
    i32::try_from(v).map_err(|_err| CfgError::BadDocument(format!("block index {v} out of range")))
}

/// `BlockGraph::decode` of a bare graph (block.cc:1434): the blocks in
/// `<bhead>` order, with their indices and in-edges. Labels decode as 0.
/// Basilisk rejects a document with nested graph or copy blocks, two
/// blocks of one index, or out-edge slots not named exactly once
/// (`docs/GHIDRA-BUGS.md` entry 26).
pub(crate) fn decode_cfg(xml: &str, limits: &Limits) -> Result<Cfg, CfgError> {
    let doc = Document::parse(xml).map_err(|e| CfgError::Decode(e.to_string()))?;
    let ids = IdTable::new(&[ATTRIBUTES, BLOCK_ATTRIBUTES], &[ELEMENTS, BLOCK_ELEMENTS])
        .map_err(|e| CfgError::Decode(e.to_string()))?;
    let mut d = XmlDecoder::new(&doc, &ids, &NoSpaces);
    let root = d.open_element_expecting(ELEM_BLOCK).map_err(|e| dec(&e))?;
    d.read_signed_attr(ATTRIB_INDEX).map_err(|e| dec(&e))?;
    let mut cfg = Cfg::new();
    let mut sortlist: Vec<NodeId> = Vec::new();
    while d.peek_element() == Some(ELEM_BHEAD.code()) {
        let el = d
            .open_element()
            .map_err(|e| dec(&e))?
            .ok_or(CfgError::Internal("bhead"))?;
        let index = to_index(d.read_signed_attr(ATTRIB_INDEX).map_err(|e| dec(&e))?)?;
        let ty = d.read_string_attr(ATTRIB_TYPE).map_err(|e| dec(&e))?;
        match name_to_kind(ty) {
            Some(Kind::Plain) => {}
            _ => return Err(CfgError::BadDocument(format!("nested block of type {ty}"))),
        }
        d.close_element(el).map_err(|e| dec(&e))?;
        if sortlist.len() as u64 >= limits.max_nodes {
            return Err(CfgError::LimitExceeded {
                what: LimitKind::Nodes,
                limit: limits.max_nodes,
            });
        }
        let id = cfg.g.new_plain(0)?;
        cfg.g.node_mut(id).index = index;
        sortlist.push(id);
    }
    // `BlockMap::sortList`, stably; equal indices are rejected.
    sortlist.sort_by_key(|&n| cfg.g.node(n).index);
    if sortlist
        .windows(2)
        .any(|w| matches!(w, [a, b] if cfg.g.node(*a).index == cfg.g.node(*b).index))
    {
        return Err(CfgError::BadDocument("two blocks with one index".into()));
    }
    let order = cfg.g.list.clone();
    let mut filled: Vec<Vec<bool>> = vec![Vec::new(); cfg.g.nodes.len()];
    let mut edges = 0u64;
    for &this in &order {
        let el = d.open_element_expecting(ELEM_BLOCK).map_err(|e| dec(&e))?;
        let index = to_index(d.read_signed_attr(ATTRIB_INDEX).map_err(|e| dec(&e))?)?;
        cfg.g.node_mut(this).index = index;
        while d.peek_element() == Some(ELEM_EDGE.code()) {
            let eel = d
                .open_element()
                .map_err(|e| dec(&e))?
                .ok_or(CfgError::Internal("edge"))?;
            let end = d.read_signed_attr(ATTRIB_END).map_err(|e| dec(&e))?;
            let src = find_block(&cfg.g, &sortlist, end).ok_or(CfgError::SerializedEdge)?;
            let rev = d.read_signed_attr(ATTRIB_REV).map_err(|e| dec(&e))?;
            d.close_element(eel).map_err(|e| dec(&e))?;
            edges += 1;
            if edges > limits.max_edges {
                return Err(CfgError::LimitExceeded {
                    what: LimitKind::Edges,
                    limit: limits.max_edges,
                });
            }
            let slot = usize::try_from(rev)
                .ok()
                .filter(|&r| (r as u64) < limits.max_edges)
                .ok_or(CfgError::BadEdgeSlots {
                    block: end,
                    slot: rev,
                })?;
            let inslot = to_u32(cfg.g.size_in(this))?;
            cfg.g.node_mut(this).ins.push(Edge {
                label: 0,
                other: src,
                rev: to_u32(slot)?,
            });
            let f = filled
                .get_mut(src.index())
                .ok_or(CfgError::Internal("filled"))?;
            if f.len() <= slot {
                f.resize(slot + 1, false);
            }
            let outs = &mut cfg.g.node_mut(src).outs;
            while outs.len() <= slot {
                outs.push(Edge {
                    label: 0,
                    other: src,
                    rev: 0,
                });
            }
            let already = f.get(slot).copied().unwrap_or(false);
            if already {
                return Err(CfgError::BadEdgeSlots {
                    block: end,
                    slot: rev,
                });
            }
            if let Some(x) = f.get_mut(slot) {
                *x = true;
            }
            if let Some(o) = outs.get_mut(slot) {
                *o = Edge {
                    label: 0,
                    other: this,
                    rev: inslot,
                };
            }
        }
        d.close_element(el).map_err(|e| dec(&e))?;
    }
    d.close_element(root).map_err(|e| dec(&e))?;
    // The graph's own index follows `addBlock`, after each block's header
    // was read: the minimum.
    cfg.g.root_index = order.iter().map(|&n| cfg.g.node(n).index).min();
    for &n in &order {
        let f = filled.get(n.index()).map_or(&[][..], Vec::as_slice);
        if let Some(slot) = f.iter().position(|&x| !x) {
            return Err(CfgError::BadEdgeSlots {
                block: i64::from(cfg.g.node(n).index),
                slot: slot as i64,
            });
        }
    }
    Ok(cfg)
}
