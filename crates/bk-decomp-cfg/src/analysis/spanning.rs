//! Spanning tree, irreducible edges and loop edges.
//!
//! Ghidra: `BlockGraph::findSpanningTree` (block.cc:1022),
//! `findIrreducible` (1160), `calcLoop` (2122), `structureLoops` (2212) and
//! `clearEdgeFlags` (979). All iterative, as in Ghidra.

use crate::error::CfgError;
use crate::flags::{edge_labels, node_flags};
use crate::graph::{Graph, NodeId, to_i32};
use crate::limits::Budget;

impl Graph {
    /// `BlockGraph::clearEdgeFlags` (block.cc:979): clears `fl` on both
    /// halves of every edge of the top-level nodes.
    pub(crate) fn clear_edge_flags(&mut self, fl: u32) {
        for k in 0..self.list.len() {
            let Some(&n) = self.list.get(k) else { continue };
            let node = self.node_mut(n);
            for e in &mut node.ins {
                e.label &= !fl;
            }
            for e in &mut node.outs {
                e.label &= !fl;
            }
        }
    }

    fn reset_tree_fields(&mut self) {
        for k in 0..self.list.len() {
            let Some(&n) = self.list.get(k) else { continue };
            let node = self.node_mut(n);
            node.index = -1;
            node.visit = -1;
            node.copymap = Some(n);
        }
    }

    /// `BlockGraph::findSpanningTree` (block.cc:1022): labels tree, forward,
    /// cross and back edges, numbers the nodes in reverse post-order
    /// (`index`) and pre-order (`visit`), counts descendants, fills
    /// `preorder` and `rootlist`, and replaces the list by the reverse
    /// post-order.
    pub(crate) fn find_spanning_tree(
        &mut self,
        preorder: &mut Vec<NodeId>,
        rootlist: &mut Vec<NodeId>,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        let n = self.list.len();
        if n == 0 {
            return Ok(());
        }
        let mut rpostorder: Vec<Option<NodeId>> = vec![None; n];
        let mut state: Vec<(NodeId, usize)> = Vec::with_capacity(n);
        preorder.reserve(n);
        self.reset_tree_fields();
        for k in 0..n {
            let Some(&b) = self.list.get(k) else { continue };
            if self.size_in(b) == 0 {
                rootlist.push(b);
            }
        }
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        } else if rootlist.is_empty() {
            let first = *self.list.first().ok_or(CfgError::Internal("empty list"))?;
            rootlist.push(first);
        }
        let origrootpos = rootlist.len() - 1;

        for repeat in 0..2 {
            let mut extraroots = false;
            let mut rpostcount = n;
            let mut rootindex = 0usize;
            self.clear_edge_flags(
                edge_labels::IRREDUCIBLE
                    | edge_labels::TREE
                    | edge_labels::FORWARD
                    | edge_labels::CROSS
                    | edge_labels::BACK
                    | edge_labels::LOOP
                    | edge_labels::LOOP_EXIT,
            );
            while preorder.len() < n {
                budget.step()?;
                let mut startbl = None;
                while rootindex < rootlist.len() {
                    let cand = *rootlist
                        .get(rootindex)
                        .ok_or(CfgError::Internal("rootlist"))?;
                    rootindex += 1;
                    if self.node(cand).visit == -1 {
                        startbl = Some(cand);
                        break;
                    }
                    // Not really a root (a root from the previous pass).
                    rootlist.remove(rootindex - 1);
                    rootindex -= 1;
                }
                let startbl = if let Some(s) = startbl {
                    s
                } else {
                    extraroots = true;
                    let mut pick = None;
                    for k in 0..n {
                        let Some(&b) = self.list.get(k) else { continue };
                        pick = Some(b);
                        if self.node(b).visit == -1 {
                            break;
                        }
                    }
                    let pick = pick.ok_or(CfgError::Internal("no unvisited node"))?;
                    rootlist.push(pick);
                    rootindex += 1;
                    pick
                };
                state.push((startbl, 0));
                self.node_mut(startbl).visit = to_i32(preorder.len())?;
                preorder.push(startbl);
                self.node_mut(startbl).numdesc = 1;

                while let Some(&(curbl, edgenum)) = state.last() {
                    budget.step()?;
                    if self.size_out(curbl) <= edgenum {
                        state.pop();
                        rpostcount = rpostcount
                            .checked_sub(1)
                            .ok_or(CfgError::Internal("post-order underflow"))?;
                        self.node_mut(curbl).index = to_i32(rpostcount)?;
                        if let Some(slot) = rpostorder.get_mut(rpostcount) {
                            *slot = Some(curbl);
                        }
                        let nd = self.node(curbl).numdesc;
                        if let Some(&(parent, _)) = state.last() {
                            self.node_mut(parent).numdesc += nd;
                        }
                        continue;
                    }
                    if let Some(top) = state.last_mut() {
                        top.1 += 1;
                    }
                    let e = self.out_edge(curbl, edgenum)?;
                    if e.label & edge_labels::IRREDUCIBLE != 0 {
                        continue;
                    }
                    let child = e.other;
                    let (cvisit, cindex) = {
                        let c = self.node(child);
                        (c.visit, c.index)
                    };
                    if cvisit == -1 {
                        self.set_out_edge_flag(curbl, edgenum, edge_labels::TREE)?;
                        state.push((child, 0));
                        self.node_mut(child).visit = to_i32(preorder.len())?;
                        preorder.push(child);
                        self.node_mut(child).numdesc = 1;
                    } else if cindex == -1 {
                        self.set_out_edge_flag(
                            curbl,
                            edgenum,
                            edge_labels::BACK | edge_labels::LOOP,
                        )?;
                    } else if self.node(curbl).visit < cvisit {
                        self.set_out_edge_flag(curbl, edgenum, edge_labels::FORWARD)?;
                    } else {
                        self.set_out_edge_flag(curbl, edgenum, edge_labels::CROSS)?;
                    }
                }
            }
            if !extraroots {
                break;
            }
            if repeat == 1 {
                return Err(CfgError::SpanningTree);
            }
            // Extra roots: regenerate so the entry block comes first.
            let last = rootlist.len() - 1;
            rootlist.swap(last, origrootpos);
            self.reset_tree_fields();
            preorder.clear();
            state.clear();
            rpostorder.fill(None);
        }
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        }
        let mut newlist = Vec::with_capacity(n);
        for slot in rpostorder {
            newlist.push(slot.ok_or(CfgError::Internal("incomplete post-order"))?);
        }
        self.list = newlist;
        Ok(())
    }

    /// `BlockGraph::findIrreducible` (block.cc:1160): Tarjan's reducibility
    /// test over `preorder` in reverse, labelling irreducible edges. Returns
    /// whether a tree edge was irreducible (a rebuild is needed).
    pub(crate) fn find_irreducible(
        &mut self,
        preorder: &[NodeId],
        irreduciblecount: &mut u32,
        budget: &mut Budget,
    ) -> Result<bool, CfgError> {
        let mut reachunder: Vec<NodeId> = Vec::new();
        let mut needrebuild = false;
        for &x in preorder.iter().rev() {
            budget.step()?;
            for i in 0..self.size_in(x) {
                let e = self.in_edge(x, i)?;
                if e.label & edge_labels::BACK == 0 {
                    continue;
                }
                let y = e.other;
                if y == x {
                    continue;
                }
                let fy = self.node(y).copymap.ok_or(CfgError::Internal("copymap"))?;
                reachunder.push(fy);
                self.set_mark(fy);
            }
            let (xvisit, xdesc) = {
                let n = self.node(x);
                (n.visit, n.numdesc)
            };
            let mut q = 0;
            while let Some(&t) = reachunder.get(q) {
                q += 1;
                for i in 0..self.size_in(t) {
                    budget.step()?;
                    let e = self.in_edge(t, i)?;
                    if e.label & edge_labels::IRREDUCIBLE != 0 {
                        continue;
                    }
                    let y = e.other;
                    let yprime = self.node(y).copymap.ok_or(CfgError::Internal("copymap"))?;
                    let ypvisit = self.node(yprime).visit;
                    if xvisit > ypvisit || xvisit.wrapping_add(xdesc) <= ypvisit {
                        *irreduciblecount += 1;
                        let edgeout = e.rev as usize;
                        self.set_out_edge_flag(y, edgeout, edge_labels::IRREDUCIBLE)?;
                        if e.label & edge_labels::TREE != 0 {
                            needrebuild = true;
                        } else {
                            self.clear_out_edge_flag(
                                y,
                                edgeout,
                                edge_labels::CROSS | edge_labels::FORWARD,
                            )?;
                        }
                    } else if !self.node(yprime).is_mark() && yprime != x {
                        reachunder.push(yprime);
                        self.set_mark(yprime);
                    }
                }
            }
            for &s in &reachunder {
                let node = self.node_mut(s);
                node.flags &= !node_flags::MARK;
                node.copymap = Some(x);
            }
            reachunder.clear();
        }
        Ok(needrebuild)
    }

    /// `BlockGraph::calcLoop` (block.cc:2122): depth-first from the first
    /// node, labelling as loop edge every edge into the current path.
    pub(crate) fn calc_loop(&mut self, budget: &mut Budget) -> Result<(), CfgError> {
        let Some(&first) = self.list.first() else {
            return Ok(());
        };
        let mut path: Vec<(NodeId, usize)> = vec![(first, 0)];
        self.node_mut(first).flags |= node_flags::MARK | node_flags::MARK2;
        while let Some(&(bl, i)) = path.last() {
            budget.step()?;
            if i >= self.size_out(bl) {
                self.node_mut(bl).flags &= !node_flags::MARK2;
                path.pop();
                continue;
            }
            if let Some(top) = path.last_mut() {
                top.1 += 1;
            }
            let e = self.out_edge(bl, i)?;
            if e.label & edge_labels::LOOP != 0 {
                continue;
            }
            let nextbl = e.other;
            let nf = self.node(nextbl).flags;
            if nf & node_flags::MARK2 != 0 {
                self.add_loop_edge(bl, i)?;
            } else if nf & node_flags::MARK == 0 {
                self.node_mut(nextbl).flags |= node_flags::MARK | node_flags::MARK2;
                path.push((nextbl, 0));
            }
        }
        for k in 0..self.list.len() {
            if let Some(&n) = self.list.get(k) {
                self.node_mut(n).flags &= !(node_flags::MARK | node_flags::MARK2);
            }
        }
        Ok(())
    }

    /// `BlockGraph::structureLoops` (block.cc:2212): spanning tree and
    /// irreducible edges, rebuilt while a tree edge is irreducible (at most
    /// once here; see [`CfgError::SpanningTreeRebuild`]), then `calcLoop` if
    /// any edge was irreducible. Returns the root list.
    pub(crate) fn structure_loops(&mut self, budget: &mut Budget) -> Result<Vec<NodeId>, CfgError> {
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        let mut irreduciblecount = 0u32;
        let mut rebuilds = 0;
        loop {
            self.find_spanning_tree(&mut preorder, &mut rootlist, budget)?;
            let needrebuild = self.find_irreducible(&preorder, &mut irreduciblecount, budget)?;
            if !needrebuild {
                break;
            }
            if rebuilds == 1 {
                return Err(CfgError::SpanningTreeRebuild);
            }
            rebuilds += 1;
            self.clear_edge_flags(
                edge_labels::TREE
                    | edge_labels::FORWARD
                    | edge_labels::CROSS
                    | edge_labels::BACK
                    | edge_labels::LOOP,
            );
            preorder.clear();
            rootlist.clear();
        }
        if irreduciblecount > 0 {
            self.calc_loop(budget)?;
        }
        Ok(rootlist)
    }
}
