//! Loop bodies.
//!
//! Ghidra: `FloatingEdge` (blockaction.hh:30; blockaction.cc:27) and
//! `LoopBody` (blockaction.cc:46–498, 1021–1044). Loop bodies live in a
//! vector with stable indices; `immed_container` is such an index.

use crate::error::CfgError;
use crate::flags::edge_labels;
use crate::graph::{Graph, NodeId};
use crate::limits::Budget;

/// `FloatingEdge::getCurrentEdge` (blockaction.cc:27): lifts both ends to
/// the top level (updating them in place) and returns the current source
/// and out-slot, or `None` if the edge no longer exists.
pub(crate) fn current_edge(g: &Graph, edge: &mut (NodeId, NodeId)) -> Option<(NodeId, usize)> {
    edge.0 = lift(g, edge.0);
    edge.1 = lift(g, edge.1);
    let slot = g.out_index(edge.0, edge.1)?;
    Some((edge.0, slot))
}

/// Moves `n` up the parent chain to the top level.
pub(crate) fn lift(g: &Graph, mut n: NodeId) -> NodeId {
    let mut guard = g.nodes.len();
    while let Some(p) = g.node(n).parent {
        if guard == 0 {
            break;
        }
        guard -= 1;
        n = p;
    }
    n
}

/// A loop: its head, its tails (sources of back edges into the head), and
/// what `orderLoopBodies` works out about it (`LoopBody`).
#[derive(Clone, Debug)]
pub(crate) struct LoopBody {
    /// The head, `None` once merged into another body.
    pub(crate) head: Option<NodeId>,
    pub(crate) tails: Vec<NodeId>,
    pub(crate) depth: i32,
    pub(crate) uniquecount: usize,
    pub(crate) exitblock: Option<NodeId>,
    /// `exitedges`, as (top, bottom) floating edges.
    pub(crate) exitedges: Vec<(NodeId, NodeId)>,
    pub(crate) immed_container: Option<usize>,
}

impl LoopBody {
    pub(crate) fn new(head: NodeId) -> Self {
        Self {
            head: Some(head),
            tails: Vec::new(),
            depth: 0,
            uniquecount: 0,
            exitblock: None,
            exitedges: Vec::new(),
            immed_container: None,
        }
    }

    fn head(&self) -> Result<NodeId, CfgError> {
        self.head.ok_or(CfgError::Internal("merged loop body"))
    }

    /// `LoopBody::update` (blockaction.cc:94): lifts head and tails to the
    /// top level; the first tail that is not the head, else the head if it
    /// loops to itself, else `None` (the loop is collapsed).
    pub(crate) fn update(&mut self, g: &Graph) -> Result<Option<NodeId>, CfgError> {
        let head = lift(g, self.head()?);
        self.head = Some(head);
        for t in &mut self.tails {
            let bottom = lift(g, *t);
            *t = bottom;
            if bottom != head {
                return Ok(Some(bottom));
            }
        }
        for i in (0..g.size_out(head)).rev() {
            if g.out(head, i)? == head {
                return Ok(Some(head));
            }
        }
        Ok(None)
    }

    /// `LoopBody::findBase` (blockaction.cc:119): marks and collects the
    /// nodes that reach a tail without passing the head.
    pub(crate) fn find_base(
        &mut self,
        g: &mut Graph,
        body: &mut Vec<NodeId>,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        let head = self.head()?;
        g.set_mark(head);
        body.push(head);
        for &tail in &self.tails {
            if !g.node(tail).is_mark() {
                g.set_mark(tail);
                body.push(tail);
            }
        }
        self.uniquecount = body.len();
        let mut i = 1;
        while let Some(&cur) = body.get(i) {
            i += 1;
            for k in 0..g.size_in(cur) {
                budget.step()?;
                if g.is_goto_in(cur, k)? {
                    continue;
                }
                let bl = g.in_(cur, k)?;
                if g.node(bl).is_mark() {
                    continue;
                }
                g.set_mark(bl);
                body.push(bl);
            }
        }
        Ok(())
    }

    /// `LoopBody::extendToContainer` (blockaction.cc:46): marks and collects
    /// the nodes of `container`'s body that are not yet marked.
    pub(crate) fn extend_to_container(
        &self,
        container_head: NodeId,
        container_tails: &[NodeId],
        g: &mut Graph,
        body: &mut Vec<NodeId>,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        let head = self.head()?;
        let mut i = 0;
        if !g.node(container_head).is_mark() {
            g.set_mark(container_head);
            body.push(container_head);
            i = 1;
        }
        for &tail in container_tails {
            if !g.node(tail).is_mark() {
                g.set_mark(tail);
                body.push(tail);
            }
        }
        if head != container_head {
            for k in 0..g.size_in(head) {
                if g.is_goto_in(head, k)? {
                    continue;
                }
                let bl = g.in_(head, k)?;
                if g.node(bl).is_mark() {
                    continue;
                }
                g.set_mark(bl);
                body.push(bl);
            }
        }
        while let Some(&cur) = body.get(i) {
            i += 1;
            for k in 0..g.size_in(cur) {
                budget.step()?;
                if g.is_goto_in(cur, k)? {
                    continue;
                }
                let bl = g.in_(cur, k)?;
                if g.node(bl).is_mark() {
                    continue;
                }
                g.set_mark(bl);
                body.push(bl);
            }
        }
        Ok(())
    }

    /// `LoopBody::extend` (blockaction.cc:150): adds the nodes all of whose
    /// in-edges come from the body (never the exit), through non-goto edges.
    pub(crate) fn extend(
        &self,
        g: &mut Graph,
        body: &mut Vec<NodeId>,
        trial: &mut Vec<NodeId>,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        trial.clear();
        let mut i = 0;
        while let Some(&bl) = body.get(i) {
            i += 1;
            for j in 0..g.size_out(bl) {
                budget.step()?;
                if g.is_goto_out(bl, j)? {
                    continue;
                }
                let curbl = g.out(bl, j)?;
                if g.node(curbl).is_mark() || Some(curbl) == self.exitblock {
                    continue;
                }
                let mut count = g.node(curbl).visit;
                if count == 0 {
                    trial.push(curbl);
                }
                count += 1;
                g.node_mut(curbl).visit = count;
                if usize::try_from(count).ok() == Some(g.size_in(curbl)) {
                    g.set_mark(curbl);
                    body.push(curbl);
                }
            }
        }
        for &t in trial.iter() {
            g.node_mut(t).visit = 0;
        }
        trial.clear();
        Ok(())
    }

    /// The exit candidates of `findExit` (blockaction.cc:182) before the
    /// container is consulted: with no container the first one found is
    /// the exit (returned as `Ok(Some(exit))` with `trialexit` unused).
    pub(crate) fn find_exit_candidates(
        &self,
        g: &Graph,
        body: &[NodeId],
        has_container: bool,
        trialexit: &mut Vec<NodeId>,
    ) -> Result<Option<NodeId>, CfgError> {
        trialexit.clear();
        for &tail in &self.tails {
            for i in 0..g.size_out(tail) {
                if g.is_goto_out(tail, i)? {
                    continue;
                }
                let curbl = g.out(tail, i)?;
                if !g.node(curbl).is_mark() {
                    if !has_container {
                        return Ok(Some(curbl));
                    }
                    trialexit.push(curbl);
                }
            }
        }
        for (i, &bl) in body.iter().enumerate() {
            if i > 0 && i < self.uniquecount {
                continue;
            }
            for j in 0..g.size_out(bl) {
                if g.is_goto_out(bl, j)? {
                    continue;
                }
                let curbl = g.out(bl, j)?;
                if !g.node(curbl).is_mark() {
                    if !has_container {
                        return Ok(Some(curbl));
                    }
                    trialexit.push(curbl);
                }
            }
        }
        Ok(None)
    }

    /// `LoopBody::orderTails` (blockaction.cc:245): the first tail with an
    /// edge to the exit is swapped to the front.
    pub(crate) fn order_tails(&mut self, g: &Graph) {
        if self.tails.len() <= 1 {
            return;
        }
        let Some(exit) = self.exitblock else {
            return;
        };
        let pref = self
            .tails
            .iter()
            .position(|&t| g.out_index(t, exit).is_some());
        if let Some(p) = pref
            && p != 0
        {
            self.tails.swap(0, p);
        }
    }

    fn push_exits_of(
        &mut self,
        g: &Graph,
        cur: NodeId,
        toexitblock: &mut Vec<NodeId>,
    ) -> Result<(), CfgError> {
        for k in 0..g.size_out(cur) {
            if g.is_goto_out(cur, k)? {
                continue;
            }
            let bl = g.out(cur, k)?;
            if Some(bl) == self.exitblock {
                toexitblock.push(cur);
                continue;
            }
            if !g.node(bl).is_mark() {
                self.exitedges.push((cur, bl));
            }
        }
        Ok(())
    }

    /// `LoopBody::labelExitEdges` (blockaction.cc:270): exits of the
    /// non-head/tail body nodes, then of the head, then of the tails from
    /// last to first; edges to the exit block go last.
    pub(crate) fn label_exit_edges(&mut self, g: &Graph, body: &[NodeId]) -> Result<(), CfgError> {
        let mut toexitblock = Vec::new();
        for &cur in body.iter().skip(self.uniquecount) {
            self.push_exits_of(g, cur, &mut toexitblock)?;
        }
        if let Some(head) = self.head {
            self.push_exits_of(g, head, &mut toexitblock)?;
        }
        for i in (0..self.tails.len()).rev() {
            let Some(&cur) = self.tails.get(i) else {
                continue;
            };
            if Some(cur) == self.head {
                continue;
            }
            self.push_exits_of(g, cur, &mut toexitblock)?;
        }
        if let Some(exit) = self.exitblock {
            for bl in toexitblock {
                self.exitedges.push((bl, exit));
            }
        }
        Ok(())
    }

    /// `LoopBody::emitLikelyEdges` (blockaction.cc:364).
    pub(crate) fn emit_likely_edges(
        &mut self,
        likely: &mut Vec<(NodeId, NodeId)>,
        g: &Graph,
    ) -> Result<(), CfgError> {
        let head = lift(g, self.head()?);
        self.head = Some(head);
        if let Some(e) = self.exitblock {
            self.exitblock = Some(lift(g, e));
        }
        for i in 0..self.tails.len() {
            let Some(t) = self.tails.get_mut(i) else {
                continue;
            };
            *t = lift(g, *t);
            if Some(*t) == self.exitblock {
                self.exitblock = None;
            }
        }
        let mut hold: Option<(NodeId, NodeId)> = None;
        let n = self.exitedges.len();
        for k in 0..n {
            let Some(edge) = self.exitedges.get_mut(k) else {
                continue;
            };
            let Some((inbl, outedge)) = current_edge(g, edge) else {
                continue;
            };
            let outbl = g.out(inbl, outedge)?;
            if k + 1 == n && Some(outbl) == self.exitblock {
                hold = Some((inbl, outbl));
                break;
            }
            likely.push((inbl, outbl));
        }
        for i in (0..self.tails.len()).rev() {
            if i == 0
                && let Some(h) = hold
            {
                likely.push(h);
            }
            let Some(&tail) = self.tails.get(i) else {
                continue;
            };
            for j in 0..g.size_out(tail) {
                if g.out(tail, j)? == head {
                    likely.push((tail, head));
                }
            }
        }
        Ok(())
    }

    /// `LoopBody::setExitMarks` / `clearExitMarks` (blockaction.cc:416,
    /// 430).
    pub(crate) fn exit_marks(&mut self, g: &mut Graph, set: bool) -> Result<(), CfgError> {
        for k in 0..self.exitedges.len() {
            let Some(edge) = self.exitedges.get_mut(k) else {
                continue;
            };
            if let Some((inloop, outedge)) = current_edge(g, edge) {
                if set {
                    g.set_out_edge_flag(inloop, outedge, edge_labels::LOOP_EXIT)?;
                } else {
                    g.clear_out_edge_flag(inloop, outedge, edge_labels::LOOP_EXIT)?;
                }
            }
        }
        Ok(())
    }
}

/// `LoopBody::mergeIdenticalHeads` (blockaction.cc:446): consecutive bodies
/// of `looporder` with one head are merged into the first.
pub(crate) fn merge_identical_heads(looporder: &mut Vec<usize>, bodies: &mut [LoopBody]) {
    let Some(&first) = looporder.first() else {
        return;
    };
    let mut i = 0;
    let mut cur = first;
    for j in 1..looporder.len() {
        let Some(&next) = looporder.get(j) else {
            continue;
        };
        let (nhead, ntail) = match bodies.get(next) {
            Some(b) => (b.head, b.tails.first().copied()),
            None => continue,
        };
        let chead = bodies.get(cur).and_then(|b| b.head);
        if nhead == chead {
            if let (Some(t), Some(c)) = (ntail, bodies.get_mut(cur)) {
                c.tails.push(t);
            }
            if let Some(nb) = bodies.get_mut(next) {
                nb.head = None;
            }
        } else {
            i += 1;
            if let Some(slot) = looporder.get_mut(i) {
                *slot = next;
            }
            cur = next;
        }
    }
    looporder.truncate(i + 1);
}

/// `LoopBody::find` (blockaction.cc:1021): binary search of `looporder`
/// (sorted by head index) for the body with head `looptop`'s index.
pub(crate) fn find(
    g: &Graph,
    looptop: NodeId,
    looporder: &[usize],
    bodies: &[LoopBody],
) -> Option<usize> {
    let target = g.node(looptop).index;
    let mut min: isize = 0;
    let mut max: isize = looporder.len() as isize - 1;
    while min <= max {
        let mid = min.midpoint(max);
        let idx = *looporder.get(mid as usize)?;
        let head = bodies.get(idx)?.head?;
        let aindex = g.node(head).index;
        if aindex == target {
            return Some(idx);
        }
        if aindex < target {
            min = mid + 1;
        } else {
            max = mid - 1;
        }
    }
    None
}
