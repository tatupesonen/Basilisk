//! The collapse loop.
//!
//! Ghidra: `CollapseStructure::collapseAll` (blockaction.cc:1885),
//! `collapseInternal` (1776) and `collapseConditions` (1862). The sweeps run
//! by index over a list that shrinks and grows as rules apply; after a rule
//! applies the sweep continues at the same index, as in Ghidra.

use super::{
    GotoCause, GotoCounts, GotoMark, Measure, RULE_BLOCKCAT, RULE_BLOCKDOWHILE, RULE_BLOCKGOTO,
    RULE_BLOCKIFELSE, RULE_BLOCKIFNOEXIT, RULE_BLOCKINFLOOP, RULE_BLOCKOR, RULE_BLOCKPROPERIF,
    RULE_BLOCKSWITCH, RULE_BLOCKWHILEDO, RULE_CASEFALLTHRU, TraceRecord,
};
use crate::error::CfgError;
use crate::facts::BlockFacts;
use crate::flags::{Kind, edge_labels};
use crate::gotos::selector::{CollapseView, GotoSelector};
use crate::graph::{Graph, NodeId, to_u32};
use crate::limits::Budget;

/// The state of one structuring run.
pub(crate) struct Collapse<'a> {
    /// The working graph (`CollapseStructure::graph`, a copy).
    pub(crate) g: Graph,
    /// The input graph: the "original" basic blocks behind the copies.
    pub(crate) orig: &'a Graph,
    pub(crate) facts: &'a BlockFacts,
    pub(crate) budget: Budget,
    pub(crate) flips: Vec<NodeId>,
    pub(crate) marks: Vec<GotoMark>,
    pub(crate) trace: Option<Vec<TraceRecord>>,
    pub(crate) dataflow_changes: u32,
    /// Start of the current batch of goto marks in `marks`.
    batch_start: usize,
    /// Reused storage (no allocation per rule attempt).
    pub(crate) scratch: Vec<NodeId>,
    pub(crate) nodes: Vec<NodeId>,
    pub(crate) stack: Vec<NodeId>,
}

const KINDS: [Kind; 12] = [
    Kind::Goto,
    Kind::MultiGoto,
    Kind::List,
    Kind::Condition,
    Kind::If,
    Kind::IfElse,
    Kind::IfNoExit,
    Kind::IfGoto,
    Kind::WhileDo,
    Kind::DoWhile,
    Kind::InfLoop,
    Kind::Switch,
];

impl<'a> Collapse<'a> {
    pub(crate) fn new(
        g: Graph,
        orig: &'a Graph,
        facts: &'a BlockFacts,
        budget: Budget,
        trace: bool,
    ) -> Self {
        Self {
            g,
            orig,
            facts,
            budget,
            flips: Vec::new(),
            marks: Vec::new(),
            trace: trace.then(Vec::new),
            dataflow_changes: 0,
            batch_start: 0,
            scratch: Vec::new(),
            nodes: Vec::new(),
            stack: Vec::new(),
        }
    }

    /// Runs a factory with the reusable scratch vector.
    pub(crate) fn build<R>(
        &mut self,
        f: impl FnOnce(&mut Graph, &mut Vec<NodeId>) -> Result<R, CfgError>,
    ) -> Result<R, CfgError> {
        let mut scratch = std::mem::take(&mut self.scratch);
        let r = f(&mut self.g, &mut scratch);
        self.scratch = scratch;
        r
    }

    /// `negateCondition(true)` at a rule site, counting a data-flow change.
    pub(crate) fn negate(&mut self, bl: NodeId) -> Result<(), CfgError> {
        if self
            .g
            .negate_condition(bl, self.facts, &mut self.flips, &mut self.stack)?
        {
            self.dataflow_changes += 1;
        }
        Ok(())
    }

    /// `setGotoBranch(slot)` on `bl`, recording the mark if the edge was not
    /// a goto before.
    pub(crate) fn set_goto_branch(
        &mut self,
        bl: NodeId,
        slot: usize,
        cause: GotoCause,
    ) -> Result<(), CfgError> {
        let before = self
            .g
            .out_edge(bl, slot)
            .map_err(|_err| CfgError::GotoBranch)?;
        self.g.set_goto_branch(bl, slot)?;
        if before.label & edge_labels::GOTO == 0 {
            self.marks.push(GotoMark {
                source: bl,
                slot: to_u32(slot)?,
                target: before.other,
                cause,
            });
        }
        Ok(())
    }

    /// Starts a batch of goto marks (one marking event).
    pub(crate) fn begin_batch(&mut self) {
        self.batch_start = self.marks.len();
    }

    /// Ends a batch: its marks are put in the order the oracle scans for
    /// them (list position of the source, then out-slot).
    pub(crate) fn end_batch(&mut self) {
        let Some(batch) = self.marks.get_mut(self.batch_start..) else {
            return;
        };
        if batch.len() > 1 {
            let list = &self.g.list;
            batch.sort_by_key(|m| {
                (
                    list.iter()
                        .position(|&n| n == m.source)
                        .unwrap_or(usize::MAX),
                    m.slot,
                )
            });
        }
        self.batch_start = self.marks.len();
    }

    fn record(&mut self, rule: &'static str, node: NodeId) {
        if let Some(t) = &mut self.trace {
            t.push(TraceRecord { rule, node });
        }
    }

    /// `CollapseStructure::collapseConditions` (blockaction.cc:1862).
    fn collapse_conditions(&mut self) -> Result<(), CfgError> {
        loop {
            let mut change = false;
            let mut i = 0;
            while let Some(&bl) = self.g.list.get(i) {
                if self.rule_block_or(bl)? {
                    self.record(RULE_BLOCKOR, bl);
                    change = true;
                }
                i += 1;
            }
            if !change {
                return Ok(());
            }
        }
    }

    /// The rules of the inner sweep, in Ghidra's order; the name of the
    /// first that applies.
    fn try_rules(&mut self, bl: NodeId) -> Result<Option<&'static str>, CfgError> {
        if self.rule_block_goto(bl)? {
            return Ok(Some(RULE_BLOCKGOTO));
        }
        if self.rule_block_cat(bl)? {
            return Ok(Some(RULE_BLOCKCAT));
        }
        if self.rule_block_proper_if(bl)? {
            return Ok(Some(RULE_BLOCKPROPERIF));
        }
        if self.rule_block_if_else(bl)? {
            return Ok(Some(RULE_BLOCKIFELSE));
        }
        if self.rule_block_while_do(bl)? {
            return Ok(Some(RULE_BLOCKWHILEDO));
        }
        if self.rule_block_do_while(bl)? {
            return Ok(Some(RULE_BLOCKDOWHILE));
        }
        if self.rule_block_inf_loop(bl)? {
            return Ok(Some(RULE_BLOCKINFLOOP));
        }
        if self.rule_block_switch(bl)? {
            return Ok(Some(RULE_BLOCKSWITCH));
        }
        Ok(None)
    }

    /// `CollapseStructure::collapseInternal` (blockaction.cc:1776): returns
    /// the number of isolated nodes.
    fn collapse_internal(&mut self, mut target: Option<NodeId>) -> Result<usize, CfgError> {
        let mut isolated;
        loop {
            loop {
                let mut change = false;
                let mut index = 0;
                isolated = 0;
                while index < self.g.list.len() {
                    let bl = if let Some(t) = target.take() {
                        change = true;
                        index = self.g.list.len();
                        t
                    } else {
                        let b = *self
                            .g
                            .list
                            .get(index)
                            .ok_or(CfgError::Internal("list index"))?;
                        index += 1;
                        b
                    };
                    if self.g.size_in(bl) == 0 && self.g.size_out(bl) == 0 {
                        isolated += 1;
                        continue;
                    }
                    if let Some(rule) = self.try_rules(bl)? {
                        self.record(rule, bl);
                        change = true;
                    }
                }
                if !change {
                    break;
                }
            }
            let mut fullchange = false;
            let mut index = 0;
            while let Some(&bl) = self.g.list.get(index) {
                if self.rule_block_if_no_exit(bl)? {
                    self.record(RULE_BLOCKIFNOEXIT, bl);
                    fullchange = true;
                    break;
                }
                if self.rule_case_fallthru(bl)? {
                    self.record(RULE_CASEFALLTHRU, bl);
                    fullchange = true;
                    break;
                }
                index += 1;
            }
            if !fullchange {
                return Ok(isolated);
            }
        }
    }

    /// `CollapseStructure::collapseAll` (blockaction.cc:1885).
    pub(crate) fn collapse_all(&mut self, selector: &mut dyn GotoSelector) -> Result<(), CfgError> {
        self.g.clear_visit_count();
        selector.start(&mut CollapseView { c: self })?;
        self.collapse_conditions()?;
        let mut isolated = self.collapse_internal(None)?;
        while isolated < self.g.list.len() {
            self.begin_batch();
            let target = selector.select(&mut CollapseView { c: self })?;
            self.end_batch();
            isolated = self.collapse_internal(target)?;
        }
        Ok(())
    }

    /// The measure of the finished run.
    pub(crate) fn measure(&self, input_gotos: usize) -> Measure {
        let mut goto_marks = GotoCounts::default();
        for m in &self.marks {
            match m.cause {
                GotoCause::Selected => goto_marks.selected += 1,
                GotoCause::ClippedRoot => goto_marks.clipped_root += 1,
                GotoCause::SwitchSkip => goto_marks.switch_skip += 1,
                GotoCause::CaseFallthru => goto_marks.case_fallthru += 1,
            }
        }
        let mut counts = [0u32; KINDS.len()];
        let mut leaves = 0u32;
        for n in &self.g.nodes {
            if n.kind == Kind::Copy {
                if !n.removed {
                    leaves += 1;
                }
                continue;
            }
            if let Some(k) = KINDS.iter().position(|&k| k == n.kind)
                && let Some(c) = counts.get_mut(k)
            {
                *c += 1;
            }
        }
        let depth = self
            .g
            .list
            .iter()
            .map(|&n| self.g.node(n).depth)
            .max()
            .unwrap_or(0);
        Measure {
            goto_marks,
            input_gotos: u32::try_from(input_gotos).unwrap_or(u32::MAX),
            depth,
            leaves,
            nodes_by_kind: KINDS.iter().map(|k| k.dump_name()).zip(counts).collect(),
            flips: u32::try_from(self.flips.len()).unwrap_or(u32::MAX),
            dataflow_changes: self.dataflow_changes,
            steps: self.budget.used(),
        }
    }
}
