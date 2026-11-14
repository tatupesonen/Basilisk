//! Behavioural comparison of two decision trees of the same table.
//!
//! Where two trees differ (same path, different field tested at a node N),
//! the subtrees under N are compared as functions from (instruction bytes,
//! context) to the constructor `DecisionNode::resolve` returns. Only the
//! bits some pattern under N constrains matter: the compiler only splits
//! on fields at least one pattern fully specifies, and a pattern match
//! reads only its mask bits. So the subtrees are equal on every input iff
//! they are equal on every assignment of the union U of those bits (the
//! bits the path above N tests are fixed to the path's values). If U has at
//! most `EXHAUSTIVE_BITS` bits every assignment is tried; otherwise a fixed
//! number of pseudo-random assignments.
//!
//! Bit conventions are Ghidra's (`context.cc`): instruction bit i is bit
//! `7 - i % 8` of byte `i / 8`; context words are big-endian 32-bit, so the
//! context is a byte string the same way; a pattern block's word j covers
//! bytes `offset + 4j ..+4`, most significant byte first.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use bk_sla::{DecisionId, DecisionNode, DisjointPattern, Sla, SymbolKind};

const EXHAUSTIVE_BITS: usize = 26;
const SAMPLES: u64 = 4_000_000;
const BUF: usize = 64;

/// An input: instruction bytes and context bytes.
#[derive(Clone)]
struct Input {
    ins: [u8; BUF],
    ctx: [u8; BUF],
}

fn get_bit(buf: &[u8; BUF], bit: usize) -> u32 {
    buf.get(bit / 8).map_or(0, |b| u32::from(b >> (7 - bit % 8)) & 1)
}

fn set_bit(buf: &mut [u8; BUF], bit: usize, v: u32) {
    if let Some(b) = buf.get_mut(bit / 8) {
        let m = 0x80u8 >> (bit % 8);
        if v != 0 {
            *b |= m;
        } else {
            *b &= !m;
        }
    }
}

fn field(buf: &[u8; BUF], start: usize, size: usize) -> u32 {
    (start..start + size).fold(0, |acc, bit| (acc << 1) | get_bit(buf, bit))
}

fn block_matches(sla: &Sla, id: bk_sla::BlockId, buf: &[u8; BUF]) -> bool {
    let Some(block) = sla.block(id) else { return false };
    if block.nonzero <= 0 {
        return block.nonzero == 0;
    }
    let mut off = usize::try_from(block.offset).unwrap_or(0);
    for w in sla.block_words(block) {
        let data = (0..4).fold(0u32, |acc, i| (acc << 8) | u32::from(*buf.get(off + i).unwrap_or(&0)));
        if data & w.mask != w.value {
            return false;
        }
        off += 4;
    }
    true
}

fn pattern_matches(sla: &Sla, p: &DisjointPattern, x: &Input) -> bool {
    match *p {
        DisjointPattern::Instruction(b) => block_matches(sla, b, &x.ins),
        DisjointPattern::Context(b) => block_matches(sla, b, &x.ctx),
        DisjointPattern::Combine {
            context,
            instruction,
        } => block_matches(sla, context, &x.ctx) && block_matches(sla, instruction, &x.ins),
    }
}

/// `DecisionNode::resolve`: the constructor index, or None ("Unable to
/// resolve constructor").
fn resolve(sla: &Sla, node: &DecisionNode, x: &Input) -> Option<u32> {
    if node.is_leaf() {
        return sla
            .pairs(node)
            .iter()
            .find(|p| pattern_matches(sla, &p.pattern, x))
            .map(|p| p.constructor);
    }
    let buf = if node.context { &x.ctx } else { &x.ins };
    let v = field(buf, usize::try_from(node.start_bit).ok()?, usize::from(node.size));
    let child = sla.decision_child(node, v)?;
    resolve(sla, sla.decision(child)?, x)
}

/// Bits (context?, absolute bit) constrained by a block.
fn block_bits(sla: &Sla, id: bk_sla::BlockId, context: bool, out: &mut BTreeSet<(bool, usize)>) {
    let Some(block) = sla.block(id) else { return };
    let base = usize::try_from(block.offset).unwrap_or(0) * 8;
    for (j, w) in sla.block_words(block).iter().enumerate() {
        for b in 0..32 {
            if w.mask & (1u32 << (31 - b)) != 0 {
                out.insert((context, base + 32 * j + b));
            }
        }
    }
}

fn subtree_pairs(sla: &Sla, id: DecisionId, pairs: &mut BTreeSet<String>, bits: &mut BTreeSet<(bool, usize)>) {
    let Some(n) = sla.decision(id) else { return };
    for p in sla.pairs(n) {
        pairs.insert(crate::trees::pair_text(sla, p));
        match p.pattern {
            DisjointPattern::Instruction(b) => block_bits(sla, b, false, bits),
            DisjointPattern::Context(b) => block_bits(sla, b, true, bits),
            DisjointPattern::Combine {
                context,
                instruction,
            } => {
                block_bits(sla, context, true, bits);
                block_bits(sla, instruction, false, bits);
            }
        }
    }
    for c in sla.children(n) {
        subtree_pairs(sla, c, pairs, bits);
    }
}

/// A node where the trees differ: its ids in both models and the fields
/// and values tested on the path to it.
struct Split {
    path: String,
    a: DecisionId,
    b: DecisionId,
    fixed: Vec<(bool, usize, usize, u32)>,
}

fn find_splits(
    a: &Sla,
    ia: DecisionId,
    b: &Sla,
    ib: DecisionId,
    path: &str,
    fixed: &mut Vec<(bool, usize, usize, u32)>,
    out: &mut Vec<Split>,
) {
    let (Some(x), Some(y)) = (a.decision(ia), b.decision(ib)) else { return };
    let same_head = x.context == y.context && x.start_bit == y.start_bit && x.size == y.size;
    if !same_head {
        out.push(Split {
            path: path.to_owned(),
            a: ia,
            b: ib,
            fixed: fixed.clone(),
        });
        return;
    }
    let ca: Vec<_> = a.children(x).collect();
    let cb: Vec<_> = b.children(y).collect();
    for (v, (cx, cy)) in ca.iter().zip(&cb).enumerate() {
        fixed.push((
            x.context,
            usize::try_from(x.start_bit).unwrap_or(0),
            usize::from(x.size),
            u32::try_from(v).unwrap_or(0),
        ));
        find_splits(a, *cx, b, *cy, &format!("{path}/{v}"), fixed, out);
        fixed.pop();
    }
}

/// Compares, behaviourally, every subtree where the decision trees of
/// tables with the same name differ.
pub fn compare(a: &Sla, b: &Sla) -> String {
    let mut out = String::new();
    let tables = |sla: &Sla| -> Vec<(String, bk_sla::Subtable)> {
        sla.symbols()
            .iter()
            .filter_map(|s| match s.kind {
                SymbolKind::Subtable(t) => Some((sla.text(s.name).to_owned(), t)),
                _ => None,
            })
            .collect()
    };
    let tb = tables(b);
    let (mut proven, mut sampled, mut differing) = (0, 0, 0);
    for (name, ta) in tables(a) {
        let Some((_, tbb)) = tb.iter().find(|(n, _)| *n == name) else { continue };
        let mut splits = Vec::new();
        find_splits(a, ta.decision, b, tbb.decision, "root", &mut Vec::new(), &mut splits);
        for s in splits {
            let (mut pa, mut pb) = (BTreeSet::new(), BTreeSet::new());
            let (mut bits, mut bits_b) = (BTreeSet::new(), BTreeSet::new());
            subtree_pairs(a, s.a, &mut pa, &mut bits);
            subtree_pairs(b, s.b, &mut pb, &mut bits_b);
            bits.extend(bits_b);
            // Path bits are fixed, not enumerated.
            let mut base = Input { ins: [0; BUF], ctx: [0; BUF] };
            for &(ctx, start, size, v) in &s.fixed {
                for i in 0..size {
                    let bit = (v >> (size - 1 - i)) & 1;
                    set_bit(if ctx { &mut base.ctx } else { &mut base.ins }, start + i, bit);
                    bits.remove(&(ctx, start + i));
                }
            }
            let bits: Vec<(bool, usize)> = bits.into_iter().collect();
            let (Some(na), Some(nb)) = (a.decision(s.a), b.decision(s.b)) else { continue };
            let exhaustive = bits.len() <= EXHAUSTIVE_BITS;
            let count: u64 = if exhaustive { 1u64 << bits.len() } else { SAMPLES };
            let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
            let mut mismatches = 0u64;
            let mut example = String::new();
            let mut resolved = 0u64;
            for i in 0..count {
                let assign = if exhaustive {
                    i
                } else {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    rng
                };
                let mut x = base.clone();
                for (k, &(ctx, bit)) in bits.iter().enumerate() {
                    let v = if k < 64 { ((assign >> k) & 1) as u32 } else { 0 };
                    set_bit(if ctx { &mut x.ctx } else { &mut x.ins }, bit, v);
                }
                if !exhaustive && bits.len() > 64 {
                    // more bits than one draw: fill the rest from further draws
                    for (k, &(ctx, bit)) in bits.iter().enumerate().skip(64) {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        let _ = k;
                        set_bit(if ctx { &mut x.ctx } else { &mut x.ins }, bit, (rng & 1) as u32);
                    }
                }
                let ra = resolve(a, na, &x);
                let rb = resolve(b, nb, &x);
                if ra.is_some() {
                    resolved += 1;
                }
                if ra != rb {
                    mismatches += 1;
                    if example.is_empty() {
                        example = format!("assignment {assign:#x}: {ra:?} vs {rb:?}");
                    }
                }
            }
            if mismatches > 0 {
                differing += 1;
            } else if exhaustive {
                proven += 1;
            } else {
                sampled += 1;
            }
            let _ = writeln!(
                out,
                "  table {name} {}: {} patterns ({}), {} free bits, {} {} inputs ({} resolve), {} mismatches {}",
                s.path,
                pa.len(),
                if pa == pb { "same set" } else { "DIFFERENT sets" },
                bits.len(),
                if exhaustive { "all" } else { "sampled" },
                count,
                resolved,
                mismatches,
                example
            );
        }
    }
    let _ = writeln!(
        out,
        "  equivalence: {proven} subtrees equal on every input, {sampled} equal on all samples, {differing} differ"
    );
    out
}
