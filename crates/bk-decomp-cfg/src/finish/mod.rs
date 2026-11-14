//! Finishing a structured hierarchy: order, breaks, gotos, labels.
//!
//! Ghidra: what `ActionFinalStructure::apply` (blockaction.cc:2195) does
//! after structuring: `orderBlocks` (block.hh:447), the case sort of
//! `BlockSwitch::finalizePrinting` (block.cc:3679, with the labels given as
//! input; the op-level part is D15's), `scopeBreak(-1,-1)` (block.cc:1284,
//! 2928, 2980, 3096, 3129, 3153, 3184, 3236, 3444, 3557, 3585, 3736),
//! `markUnstructured` (1263, 2918, 3251, 3726) and `markLabelBumpUp(false)`
//! (263, 1272, 3436, 3549, 3577). Ghidra recurses over the hierarchy; these
//! walk it with an explicit stack (the visiting order does not matter: each
//! step reads only indices and the structure, which none of them change).

use crate::facts::BlockFacts;
use crate::flags::{Kind, node_flags};
use crate::graph::{Graph, KindData, NodeId};
use crate::hierarchy::Hierarchy;
use crate::hierarchy::switch::order_cases;

/// The case labels of the function's jump tables, for the case order of
/// switches (`BlockSwitch::finalizePrinting`).
pub trait CaseLabels {
    /// The first label of the jump table of `switch_block` (the input node
    /// ending in the switch) for `case_block` (an input node), or `None`
    /// when the table has no index for it (`numIndicesByBlock == 0`).
    fn first_label(&self, switch_block: NodeId, case_block: NodeId) -> Option<u64>;
}

/// What [`finish`] counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FinishMeasure {
    /// Gotos that print: goto nodes still of goto type whose goto prints,
    /// if-goto nodes of goto type, and switch cases of goto type.
    pub printed_gotos: u32,
    /// Gotos that became `break`.
    pub breaks: u32,
}

/// `FlowBlock::compareFinalOrder` (block.cc:718) as a key, sorted stably
/// (ADR-040): the entry (index 0) first, then nodes not ending in `RETURN`
/// by index, then those ending in `RETURN` in list order.
fn final_order_key(g: &Graph, facts: &BlockFacts, n: NodeId) -> (bool, bool, i32) {
    let index = g.node(n).index;
    if index == 0 {
        return (false, false, 0);
    }
    let ret = g.ends_in_return(n, facts);
    (true, ret, if ret { 0 } else { index })
}

/// `BlockGraph::orderBlocks` (block.hh:447) on the top-level list of `g`.
pub(crate) fn order_blocks(g: &mut Graph, facts: &BlockFacts) {
    if g.list.len() == 1 {
        return;
    }
    let mut list = std::mem::take(&mut g.list);
    list.sort_by_cached_key(|&n| final_order_key(g, facts, n));
    g.list = list;
}

fn scope_break(g: &mut Graph) -> u32 {
    let mut breaks = 0;
    let mut stack: Vec<(NodeId, i32, i32)> = Vec::new();
    push_sequence(g, &g.list.clone(), -1, -1, &mut stack);
    while let Some((bl, curexit, curloopexit)) = stack.pop() {
        let kind = g.node(bl).kind;
        let comps = g.node(bl).comps.clone();
        let idx = |i: usize| comps.get(i).map_or(-1, |&c| g.node(c).index);
        let push = |i: usize, e: i32, l: i32, stack: &mut Vec<(NodeId, i32, i32)>| {
            if let Some(&c) = comps.get(i) {
                stack.push((c, e, l));
            }
        };
        match kind {
            Kind::Copy | Kind::Plain => {}
            Kind::List => push_sequence(g, &comps, curexit, curloopexit, &mut stack),
            Kind::Goto => {
                if let KindData::Goto { target, .. } = g.node(bl).data {
                    let tindex = g.node(target).index;
                    push(0, tindex, curloopexit, &mut stack);
                    if curloopexit == tindex {
                        if let KindData::Goto { goto_type, .. } = &mut g.node_mut(bl).data {
                            *goto_type = node_flags::BREAK_GOTO;
                        }
                        breaks += 1;
                    }
                }
            }
            Kind::MultiGoto => push(0, -1, curloopexit, &mut stack),
            Kind::Condition => {
                push(0, -1, curloopexit, &mut stack);
                push(1, -1, curloopexit, &mut stack);
            }
            Kind::If => {
                push(0, -1, curloopexit, &mut stack);
                push(1, curexit, curloopexit, &mut stack);
            }
            Kind::IfElse => {
                push(0, -1, curloopexit, &mut stack);
                push(1, curexit, curloopexit, &mut stack);
                push(2, curexit, curloopexit, &mut stack);
            }
            Kind::IfNoExit => {
                push(0, -1, curloopexit, &mut stack);
                push(1, idx(2), curloopexit, &mut stack);
                push(2, curexit, curloopexit, &mut stack);
            }
            Kind::IfGoto => {
                push(0, -1, curloopexit, &mut stack);
                if let KindData::Goto { target, .. } = g.node(bl).data
                    && g.node(target).index == curloopexit
                {
                    if let KindData::Goto { goto_type, .. } = &mut g.node_mut(bl).data {
                        *goto_type = node_flags::BREAK_GOTO;
                    }
                    breaks += 1;
                }
            }
            Kind::WhileDo => {
                push(0, -1, curexit, &mut stack);
                push(1, idx(0), curexit, &mut stack);
            }
            Kind::DoWhile => push(0, -1, curexit, &mut stack),
            Kind::InfLoop => push(0, idx(0), curexit, &mut stack),
            Kind::Switch => {
                push(0, -1, curexit, &mut stack);
                let mut cases = match &g.node(bl).data {
                    KindData::Switch(c) => c.clone(),
                    _ => Vec::new(),
                };
                for case in &mut cases {
                    if case.gototype != 0 {
                        if g.node(case.block).index == curexit {
                            case.gototype = node_flags::BREAK_GOTO;
                            breaks += 1;
                        }
                    } else {
                        stack.push((case.block, curexit, curexit));
                    }
                }
                if let KindData::Switch(c) = &mut g.node_mut(bl).data {
                    *c = cases;
                }
            }
        }
    }
    breaks
}

/// `BlockGraph::scopeBreak` for a sequence: each component's exit is the
/// next component's index, the last one's is `curexit`.
fn push_sequence(
    g: &Graph,
    comps: &[NodeId],
    curexit: i32,
    curloopexit: i32,
    stack: &mut Vec<(NodeId, i32, i32)>,
) {
    for (i, &c) in comps.iter().enumerate() {
        let ind = comps.get(i + 1).map_or(curexit, |&n| g.node(n).index);
        stack.push((c, ind, curloopexit));
    }
}

/// `markCopyBlock` (block.cc:1246): sets `fl` on the front leaf of `bl`.
fn mark_copy_block(g: &mut Graph, bl: NodeId, fl: u32) {
    if let Some(leaf) = g.front_leaf(bl) {
        g.node_mut(leaf).flags |= fl;
    }
}

fn all_nodes(g: &Graph) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut stack: Vec<NodeId> = g.list.iter().rev().copied().collect();
    while let Some(n) = stack.pop() {
        out.push(n);
        stack.extend(g.node(n).comps.iter().rev().copied());
    }
    out
}

fn mark_unstructured(g: &mut Graph) -> u32 {
    let mut printed = 0;
    for bl in all_nodes(g) {
        match (g.node(bl).kind, &g.node(bl).data) {
            (Kind::Goto, &KindData::Goto { target, goto_type }) => {
                if goto_type == node_flags::GOTO_GOTO && g.goto_prints(bl) {
                    mark_copy_block(g, target, node_flags::UNSTRUCTURED_TARG);
                    printed += 1;
                }
            }
            (Kind::IfGoto, &KindData::Goto { target, goto_type }) => {
                if goto_type == node_flags::GOTO_GOTO {
                    mark_copy_block(g, target, node_flags::UNSTRUCTURED_TARG);
                    printed += 1;
                }
            }
            (Kind::Switch, KindData::Switch(cases)) => {
                let targets: Vec<NodeId> = cases
                    .iter()
                    .filter(|c| c.gototype == node_flags::GOTO_GOTO)
                    .map(|c| c.block)
                    .collect();
                for t in targets {
                    mark_copy_block(g, t, node_flags::UNSTRUCTURED_TARG);
                    printed += 1;
                }
            }
            _ => {}
        }
    }
    printed
}

fn mark_label_bump_up(g: &mut Graph) {
    let mut stack: Vec<(NodeId, bool)> = g.list.iter().map(|&n| (n, false)).collect();
    while let Some((bl, bump)) = stack.pop() {
        let kind = g.node(bl).kind;
        let is_loop = matches!(kind, Kind::WhileDo | Kind::DoWhile | Kind::InfLoop);
        let first_bump = if is_loop { true } else { bump };
        if is_loop {
            if bump {
                g.node_mut(bl).flags |= node_flags::LABEL_BUMPUP;
            } else {
                g.node_mut(bl).flags &= !node_flags::LABEL_BUMPUP;
            }
        } else if bump {
            g.node_mut(bl).flags |= node_flags::LABEL_BUMPUP;
        }
        let comps = &g.node(bl).comps;
        for (i, &c) in comps.iter().enumerate() {
            stack.push((c, i == 0 && first_bump));
        }
    }
}

/// Finishes `h` as `ActionFinalStructure` does, minus the op-level
/// `finalizePrinting` (`docs/features/decomp-cfg.md` 4.9): orders the top
/// level, sorts switch cases by `case_labels` (left as structured when
/// `None`), marks breaks, unstructured targets and label bump-ups.
pub fn finish(
    h: &mut Hierarchy,
    facts: &BlockFacts,
    case_labels: Option<&dyn CaseLabels>,
) -> FinishMeasure {
    let g = &mut h.g;
    order_blocks(g, facts);
    if let Some(labels) = case_labels {
        for bl in all_nodes(g) {
            if g.node(bl).kind != Kind::Switch {
                continue;
            }
            let Some(switch_leaf) = g.node(bl).comps.first().and_then(|&c| g.exit_leaf(c)) else {
                continue;
            };
            if let KindData::Switch(cases) = &mut g.node_mut(bl).data {
                order_cases(cases, &|case_block| {
                    labels.first_label(switch_leaf, case_block)
                });
            }
        }
    }
    let breaks = scope_break(g);
    let printed_gotos = mark_unstructured(g);
    mark_label_bump_up(g);
    FinishMeasure {
        printed_gotos,
        breaks,
    }
}
