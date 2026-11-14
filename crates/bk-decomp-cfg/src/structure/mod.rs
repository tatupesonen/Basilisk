//! The structurer: ADR-025 item 3b's `structure(graph, facts, options)`.
//!
//! Ghidra: `CollapseStructure` (blockaction.cc:1052–1904), driven as
//! `ActionBlockStructure::apply` (2178) does in the pipeline and as
//! `IfcStructureBlocks::execute` (ifacedecomp.cc:3219) does on a bare graph.
//! The input graph is borrowed and never changed; the structurer works on
//! its own copy (`buildCopy`, block.cc:1943) and returns the hierarchy, the
//! condition flips and goto marks it wants applied to the basic blocks, the
//! data-flow change count and a measure.

pub(crate) mod collapse;
mod rules;
mod switch_rules;

use crate::cfg::Cfg;
use crate::error::CfgError;
use crate::facts::BlockFacts;
use crate::flags::{Kind, edge_labels, node_flags};
use crate::gotos::selector::GotoSelector;
use crate::graph::{Graph, Node, NodeId};
use crate::hierarchy::Hierarchy;
use crate::limits::{Budget, Limits};
use collapse::Collapse;

/// The name of the goto-selection unit for the unit table (D05/D07).
pub const UNIT_SELECTGOTO: &str = "selectgoto";
/// Rule name of `ruleBlockGoto`.
pub const RULE_BLOCKGOTO: &str = "blockgoto";
/// Rule name of `ruleBlockCat`.
pub const RULE_BLOCKCAT: &str = "blockcat";
/// Rule name of `ruleBlockOr`.
pub const RULE_BLOCKOR: &str = "blockor";
/// Rule name of `ruleBlockProperIf`.
pub const RULE_BLOCKPROPERIF: &str = "blockproperif";
/// Rule name of `ruleBlockIfElse`.
pub const RULE_BLOCKIFELSE: &str = "blockifelse";
/// Rule name of `ruleBlockWhileDo`.
pub const RULE_BLOCKWHILEDO: &str = "blockwhiledo";
/// Rule name of `ruleBlockDoWhile`.
pub const RULE_BLOCKDOWHILE: &str = "blockdowhile";
/// Rule name of `ruleBlockInfLoop`.
pub const RULE_BLOCKINFLOOP: &str = "blockinfloop";
/// Rule name of `ruleBlockSwitch`.
pub const RULE_BLOCKSWITCH: &str = "blockswitch";
/// Rule name of `ruleBlockIfNoExit`.
pub const RULE_BLOCKIFNOEXIT: &str = "blockifnoexit";
/// Rule name of `ruleCaseFallthru`.
pub const RULE_CASEFALLTHRU: &str = "casefallthru";

/// Whether the structurer takes the graph's analyses as given or computes
/// them on its copy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Analyse {
    /// Structure the graph with its labels, order, indices and dominators as
    /// passed (`ActionBlockStructure`).
    #[default]
    AsGiven,
    /// Run `structureLoops` and `calcForwardDominator` on the copy first
    /// (`structure blocks`).
    Recompute,
}

/// Whether to record rule applications.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Record {
    /// Record nothing beyond the result.
    #[default]
    None,
    /// Record every rule application ([`TraceRecord`]).
    Trace,
}

/// Options of one structuring call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StructureOptions {
    /// Analyses as given or recomputed.
    pub analyse: Analyse,
    /// Limits against hostile input.
    pub limits: Limits,
    /// What to record.
    pub record: Record,
}

/// Why an edge was marked as a goto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GotoCause {
    /// Chosen by the goto selector (`selectGoto` returned a block).
    Selected,
    /// Marked by `clipExtraRoots` (`selectGoto` returned null).
    ClippedRoot,
    /// Marked by `checkSwitchSkips` inside `ruleBlockSwitch`.
    SwitchSkip,
    /// Marked by `ruleCaseFallthru`.
    CaseFallthru,
}

impl GotoCause {
    /// The cause's name in the structure dump (`docs/features/decomp-oracle.md`
    /// 4.7).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::ClippedRoot => "clipped",
            Self::SwitchSkip => "switchskip",
            Self::CaseFallthru => "fallthru",
        }
    }
}

/// One edge newly labelled goto (`setGotoBranch`), in the order the oracle
/// lists them: per marking event, by the source's list position and the
/// out-slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GotoMark {
    /// The source node at the time of marking.
    pub source: NodeId,
    /// The out-slot of the edge at the time of marking.
    pub slot: u32,
    /// The target node at the time of marking.
    pub target: NodeId,
    /// Why it was marked.
    pub cause: GotoCause,
}

/// One rule application (`Record::Trace`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TraceRecord {
    /// The rule's name (`RULE_*`).
    pub rule: &'static str,
    /// The node the rule was applied to (`bl`).
    pub node: NodeId,
}

/// Goto marks counted by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GotoCounts {
    /// [`GotoCause::Selected`].
    pub selected: u32,
    /// [`GotoCause::ClippedRoot`].
    pub clipped_root: u32,
    /// [`GotoCause::SwitchSkip`].
    pub switch_skip: u32,
    /// [`GotoCause::CaseFallthru`].
    pub case_fallthru: u32,
}

impl GotoCounts {
    /// The total number of marks.
    pub const fn total(&self) -> u32 {
        self.selected + self.clipped_root + self.switch_skip + self.case_fallthru
    }
}

/// A measure of a structuring result (ADR-025 3b).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measure {
    /// Goto marks by cause.
    pub goto_marks: GotoCounts,
    /// Edges labelled goto in the input.
    pub input_gotos: u32,
    /// The largest structure depth of a top-level node.
    pub depth: i32,
    /// The number of leaves (input nodes structured).
    pub leaves: u32,
    /// Structured nodes created, by kind name ([`Kind::dump_name`]), in a
    /// fixed order.
    pub nodes_by_kind: Vec<(&'static str, u32)>,
    /// Flip events.
    pub flips: u32,
    /// Data-flow changes (`dataflow_changecount`).
    pub dataflow_changes: u32,
    /// Work steps taken.
    pub steps: u64,
}

/// The result of [`structure`].
#[derive(Clone, Debug)]
pub struct Structured {
    /// The hierarchy.
    pub hierarchy: Hierarchy,
    /// Flip events on leaves, in order: the input nodes whose condition the
    /// pipeline must negate (by parity) and whose two out-edges it must swap.
    pub flips: Vec<NodeId>,
    /// Every edge newly labelled goto.
    pub goto_edges: Vec<GotoMark>,
    /// `CollapseStructure::getChangeCount`.
    pub dataflow_changes: u32,
    /// The measure.
    pub measure: Measure,
    /// Rule applications, when asked for.
    pub trace: Option<Vec<TraceRecord>>,
}

/// `BlockGraph::newBlockCopy` (block.cc:1686) for every node of `source`'s
/// list, in list order, into a new arena whose leaf ids equal the input ids.
fn build_copy(source: &Graph, input: &Graph, facts: &BlockFacts) -> Graph {
    let mut g = Graph {
        nodes: Vec::with_capacity(source.nodes.len() + source.list.len()),
        list: Vec::with_capacity(source.list.len()),
        root_index: None,
    };
    for _ in 0..source.nodes.len() {
        let mut n = Node::new(Kind::Copy);
        n.removed = true;
        g.nodes.push(n);
    }
    for &id in &source.list {
        let src = source.node(id);
        let fact = facts.get(id.index());
        let node = g.node_mut(id);
        node.ins.clone_from(&src.ins);
        node.outs.clone_from(&src.outs);
        node.idom = src.idom;
        node.index = src.index;
        node.numdesc = src.numdesc;
        node.flags |= src.flags;
        if fact.switch_out {
            node.flags |= node_flags::SWITCH_OUT;
        }
        if node.outs.len() > 2 {
            node.flags |= node_flags::SWITCH_OUT;
        }
        node.removed = false;
        g.add_block_root(id);
    }
    // `buildCopy` runs before the bare-graph analyses, so the graph's own
    // index is the minimum of the indices the input had.
    g.root_index = input.list.iter().map(|&n| input.node(n).index).min();
    g
}

/// Structures `graph` (ADR-025 3b; `docs/features/decomp-cfg.md` 4.3–4.8).
///
/// `facts` are indexed by input node id. The goto selector is the
/// replaceable unit `selectgoto`; [`GhidraGotoSelector`](crate::GhidraGotoSelector)
/// is Ghidra's. On error the input is untouched (it is borrowed).
pub fn structure(
    graph: &Cfg,
    facts: &BlockFacts,
    options: &StructureOptions,
    goto_selector: &mut dyn GotoSelector,
) -> Result<Structured, CfgError> {
    let input = &graph.g;
    let mut budget: Budget = options
        .limits
        .budget(input.list.len(), input.edge_count())?;
    let analysed;
    let source = match options.analyse {
        Analyse::AsGiven => input,
        Analyse::Recompute => {
            let mut copy = input.clone();
            copy.analyse(&mut budget)?;
            analysed = copy;
            &analysed
        }
    };
    let work = build_copy(source, input, facts);
    let mut c = Collapse::new(work, input, facts, budget, options.record == Record::Trace);
    c.collapse_all(goto_selector)?;

    let input_gotos = input
        .list
        .iter()
        .flat_map(|&n| input.node(n).outs.iter())
        .filter(|e| e.label & edge_labels::GOTO != 0)
        .count();
    let measure = c.measure(input_gotos);
    let input_out_degree = (0..input.nodes.len())
        .map(|i| input.nodes.get(i).map_or(0, |n| n.outs.len() as u32))
        .collect();
    let Collapse {
        g,
        flips,
        marks,
        trace,
        dataflow_changes,
        ..
    } = c;
    Ok(Structured {
        hierarchy: Hierarchy {
            g,
            inputs: input.nodes.len(),
            input_out_degree,
            input_index: input.nodes.iter().map(|n| n.index).collect(),
        },
        flips,
        goto_edges: marks,
        dataflow_changes,
        measure,
        trace,
    })
}
