//! Dominators and reachability.
//!
//! Ghidra: `BlockGraph::calcForwardDominator` (block.cc:1972),
//! `createVirtualRoot` (1001), `buildDomTree` (2054), `buildDomDepth`
//! (2074), `buildDomSubTree` (2098), `collectReachable` (2172), and the
//! static `FlowBlock::findCommonBlock` (745, 805), `dominates` (390),
//! `restrictedByConditional` (409), `findCondition` (848).

use crate::error::CfgError;
use crate::flags::Kind;
use crate::graph::{Graph, Node, NodeId};
use crate::limits::Budget;

impl Graph {
    /// The list position that Ghidra's arithmetic takes `index` to stand for
    /// (`numnodes - index`), checked against `len`.
    fn finger(numnodes: i64, index: i32, len: usize) -> Result<usize, CfgError> {
        let f = numnodes - i64::from(index);
        usize::try_from(f)
            .ok()
            .filter(|&f| f < len)
            .ok_or_else(|| CfgError::BadIndex {
                index: i64::from(index),
            })
    }

    /// `BlockGraph::calcForwardDominator` (block.cc:1972): Cooper, Harvey
    /// and Kennedy over the post-order implied by `index` (so
    /// `findSpanningTree` must have run). A temporary virtual root is added
    /// when there are several roots or the start node has in-edges, and
    /// removed again with all its edges.
    ///
    /// The virtual root has index 0, as `FlowBlock`'s constructor leaves it,
    /// so Ghidra's finger arithmetic maps it to list position 0; this is
    /// reproduced.
    pub(crate) fn calc_forward_dominator(
        &mut self,
        rootlist: &[NodeId],
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        if self.list.is_empty() {
            return Ok(());
        }
        let arena_len = self.nodes.len();
        let mut virtualroot = None;
        let result = self.forward_dominator_inner(rootlist, &mut virtualroot, budget);
        // Excise the virtual root even when the calculation failed.
        if let Some(vr) = virtualroot {
            while let Some(last) = self.size_out(vr).checked_sub(1) {
                self.remove_out_edge(vr, last)?;
            }
            self.nodes.truncate(arena_len);
        }
        result
    }

    fn create_virtual_root(&mut self, rootlist: &[NodeId]) -> Result<NodeId, CfgError> {
        let vr = self.push(Node::new(Kind::Plain))?;
        for &r in rootlist {
            self.add_in_edge(r, vr, 0)?;
        }
        Ok(vr)
    }

    fn forward_dominator_inner(
        &mut self,
        rootlist: &[NodeId],
        virtualroot: &mut Option<NodeId>,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        let n = self.list.len();
        let numnodes = n as i64 - 1;
        let mut postorder: Vec<NodeId> = Vec::with_capacity(n + 1);
        for k in (0..n).rev() {
            let Some(&b) = self.list.get(k) else { continue };
            postorder.push(b);
        }
        for &b in &postorder {
            self.node_mut(b).idom = None;
        }
        if rootlist.len() > 1 {
            let vr = self.create_virtual_root(rootlist)?;
            *virtualroot = Some(vr);
            postorder.push(vr);
        }
        let mut b = *postorder
            .last()
            .ok_or(CfgError::Internal("empty post-order"))?;
        if self.size_in(b) != 0 {
            if rootlist.len() != 1 || rootlist.first() != Some(&b) {
                return Err(CfgError::RootNode);
            }
            let vr = self.create_virtual_root(rootlist)?;
            *virtualroot = Some(vr);
            postorder.push(vr);
            b = vr;
        }
        self.node_mut(b).idom = Some(b);
        for i in 0..self.size_out(b) {
            let o = self.out(b, i)?;
            self.node_mut(o).idom = Some(b);
        }
        let root = b;
        let len = postorder.len();
        let mut changed = true;
        let mut new_idom: Option<NodeId> = None;
        while changed {
            changed = false;
            for i in (0..len.saturating_sub(1)).rev() {
                budget.step()?;
                let Some(&b) = postorder.get(i) else { continue };
                if self.node(b).idom == Some(root) {
                    continue;
                }
                let size_in = self.size_in(b);
                let mut j = 0;
                while j < size_in {
                    let cand = self.in_(b, j)?;
                    new_idom = Some(cand);
                    if self.node(cand).idom.is_some() {
                        break;
                    }
                    j += 1;
                }
                j += 1;
                while j < size_in {
                    let rho = self.in_(b, j)?;
                    j += 1;
                    if self.node(rho).idom.is_none() {
                        continue;
                    }
                    let cur = new_idom.ok_or(CfgError::Internal("intersection without idom"))?;
                    let mut finger1 = Self::finger(numnodes, self.node(rho).index, len)?;
                    let mut finger2 = Self::finger(numnodes, self.node(cur).index, len)?;
                    while finger1 != finger2 {
                        while finger1 < finger2 {
                            budget.step()?;
                            finger1 = self.dom_step(&postorder, finger1, numnodes)?;
                        }
                        while finger2 < finger1 {
                            budget.step()?;
                            finger2 = self.dom_step(&postorder, finger2, numnodes)?;
                        }
                    }
                    new_idom = postorder.get(finger1).copied();
                }
                if self.node(b).idom != new_idom {
                    self.node_mut(b).idom = new_idom;
                    changed = true;
                }
            }
        }
        if let Some(vr) = *virtualroot {
            for k in 0..n {
                let Some(&p) = postorder.get(k) else { continue };
                if self.node(p).idom == Some(vr) {
                    self.node_mut(p).idom = None;
                }
            }
        } else if let Some(&last) = postorder.last() {
            self.node_mut(last).idom = None;
        }
        Ok(())
    }

    /// One step up the dominator chain in finger terms:
    /// `numnodes - postorder[f]->immed_dom->index`.
    fn dom_step(&self, postorder: &[NodeId], f: usize, numnodes: i64) -> Result<usize, CfgError> {
        let p = *postorder.get(f).ok_or(CfgError::Internal("finger"))?;
        // A null dominator here is a crash in Ghidra.
        let d = self.node(p).idom.ok_or_else(|| CfgError::BadIndex {
            index: i64::from(self.node(p).index),
        })?;
        Self::finger(numnodes, self.node(d).index, postorder.len())
    }

    /// `BlockGraph::buildDomTree` (block.cc:2054): dominator children per
    /// node index; entry `list.len()` holds the nodes without a dominator.
    pub(crate) fn build_dom_tree(&self) -> Result<Vec<Vec<NodeId>>, CfgError> {
        let n = self.list.len();
        let mut child: Vec<Vec<NodeId>> = vec![Vec::new(); n + 1];
        for &bl in &self.list {
            let slot = match self.node(bl).idom {
                Some(d) => {
                    let idx = self.node(d).index;
                    usize::try_from(idx)
                        .ok()
                        .filter(|&i| i < n)
                        .ok_or_else(|| CfgError::BadIndex {
                            index: i64::from(idx),
                        })?
                }
                None => n,
            };
            if let Some(c) = child.get_mut(slot) {
                c.push(bl);
            }
        }
        Ok(child)
    }

    /// `BlockGraph::buildDomDepth` (block.cc:2074): depth per list position
    /// (1 for a node without dominator), entry `list.len()` holding 0, and
    /// the largest depth.
    pub(crate) fn build_dom_depth(&self) -> Result<(Vec<i32>, i32), CfgError> {
        let n = self.list.len();
        let mut depth = vec![0i32; n + 1];
        let mut max = 0;
        for (i, &bl) in self.list.iter().enumerate() {
            let d = match self.node(bl).idom {
                Some(dom) => {
                    let idx = self.node(dom).index;
                    let pos = usize::try_from(idx)
                        .ok()
                        .filter(|&p| p <= n)
                        .ok_or_else(|| CfgError::BadIndex {
                            index: i64::from(idx),
                        })?;
                    depth.get(pos).copied().unwrap_or(0).saturating_add(1)
                }
                None => 1,
            };
            if let Some(slot) = depth.get_mut(i) {
                *slot = d;
            }
            max = max.max(d);
        }
        if let Some(last) = depth.last_mut() {
            *last = 0;
        }
        Ok((depth, max))
    }

    /// `BlockGraph::buildDomSubTree` (block.cc:2098): the nodes of the
    /// dominator subtree at `root`, relying on the list being in dominator
    /// order from `root`'s index on.
    pub(crate) fn build_dom_sub_tree(&self, root: NodeId) -> Vec<NodeId> {
        let rootindex = self.node(root).index;
        let mut res = vec![root];
        let start = usize::try_from(rootindex.saturating_add(1)).unwrap_or(0);
        for &bl in self.list.iter().skip(start) {
            let Some(dombl) = self.node(bl).idom else {
                break;
            };
            if self.node(dombl).index > rootindex {
                break;
            }
            res.push(bl);
        }
        res
    }

    /// `BlockGraph::collectReachable` (block.cc:2172): the nodes reachable
    /// from `bl` in breadth-first order, or with `un` the top-level nodes
    /// that are not, in list order.
    pub(crate) fn collect_reachable(&mut self, bl: NodeId, un: bool) -> Vec<NodeId> {
        let mut res = vec![bl];
        self.set_mark(bl);
        let mut total = 0;
        while let Some(&blk) = res.get(total) {
            total += 1;
            for j in 0..self.size_out(blk) {
                let Ok(blk2) = self.out(blk, j) else { continue };
                if self.node(blk2).is_mark() {
                    continue;
                }
                self.set_mark(blk2);
                res.push(blk2);
            }
        }
        if un {
            let mut out = Vec::new();
            for k in 0..self.list.len() {
                let Some(&blk) = self.list.get(k) else {
                    continue;
                };
                if self.node(blk).is_mark() {
                    self.clear_mark(blk);
                } else {
                    out.push(blk);
                }
            }
            for &r in &res {
                self.clear_mark(r);
            }
            out
        } else {
            for &r in &res {
                self.clear_mark(r);
            }
            res
        }
    }

    /// `FlowBlock::dominates` (block.cc:390): whether `this` dominates `sub`
    /// (or equals it), assuming reverse-post-order indices.
    pub(crate) fn dominates(&self, this: NodeId, sub: NodeId) -> bool {
        let index = self.node(this).index;
        let mut cur = Some(sub);
        let mut guard = self.nodes.len();
        while let Some(s) = cur {
            if index > self.node(s).index || guard == 0 {
                break;
            }
            if s == this {
                return true;
            }
            guard -= 1;
            cur = self.node(s).idom;
        }
        false
    }

    /// `FlowBlock::restrictedByConditional` (block.cc:409).
    pub(crate) fn restricted_by_conditional(&self, this: NodeId, cond: NodeId) -> bool {
        if self.size_in(this) == 1 {
            return true;
        }
        if self.node(this).idom != Some(cond) {
            return false;
        }
        let mut seen_cond = false;
        for e in &self.node(this).ins {
            let mut in_block = e.other;
            if in_block == cond {
                if seen_cond {
                    return false;
                }
                seen_cond = true;
                continue;
            }
            let mut guard = self.nodes.len();
            while in_block != this {
                if in_block == cond || guard == 0 {
                    return false;
                }
                guard -= 1;
                match self.node(in_block).idom {
                    Some(d) => in_block = d,
                    // Ghidra dereferences null here; no path through the
                    // sibling was found.
                    None => return false,
                }
            }
        }
        true
    }

    /// `FlowBlock::findCommonBlock(bl1, bl2)` (block.cc:745): the nearest
    /// common dominator of two nodes, or `None`.
    pub(crate) fn find_common_block(&mut self, bl1: NodeId, bl2: NodeId) -> Option<NodeId> {
        let mut common = None;
        let mut b1 = Some(bl1);
        let mut b2 = Some(bl2);
        let mut guard = 2 * self.nodes.len() + 2;
        loop {
            if guard == 0 {
                break;
            }
            guard -= 1;
            let Some(x2) = b2 else {
                while let Some(x1) = b1 {
                    if self.node(x1).is_mark() {
                        common = Some(x1);
                        break;
                    }
                    b1 = self.node(x1).idom;
                    if guard == 0 {
                        break;
                    }
                    guard -= 1;
                }
                break;
            };
            let Some(x1) = b1 else {
                let mut y = Some(x2);
                while let Some(x) = y {
                    if self.node(x).is_mark() {
                        common = Some(x);
                        break;
                    }
                    y = self.node(x).idom;
                    if guard == 0 {
                        break;
                    }
                    guard -= 1;
                }
                break;
            };
            if self.node(x1).is_mark() {
                common = Some(x1);
                break;
            }
            self.set_mark(x1);
            if self.node(x2).is_mark() {
                common = Some(x2);
                break;
            }
            self.set_mark(x2);
            b1 = self.node(x1).idom;
            b2 = self.node(x2).idom;
        }
        for start in [bl1, bl2] {
            let mut c = Some(start);
            while let Some(x) = c {
                if !self.node(x).is_mark() {
                    break;
                }
                self.clear_mark(x);
                c = self.node(x).idom;
            }
        }
        common
    }

    /// `FlowBlock::findCommonBlock(blockSet)` (block.cc:805): the nearest
    /// common dominator of a non-empty set.
    pub(crate) fn find_common_block_set(&mut self, set: &[NodeId]) -> Option<NodeId> {
        let &first = set.first()?;
        let mut marked = Vec::new();
        let mut res = first;
        let mut best = self.node(res).index;
        let mut bl = Some(first);
        while let Some(x) = bl {
            if self.node(x).is_mark() {
                break;
            }
            self.set_mark(x);
            marked.push(x);
            bl = self.node(x).idom;
        }
        for &start in set.iter().skip(1) {
            if best == 0 {
                break;
            }
            let mut x = start;
            loop {
                if self.node(x).is_mark() {
                    break;
                }
                self.set_mark(x);
                marked.push(x);
                match self.node(x).idom {
                    Some(d) => x = d,
                    // Ghidra dereferences null here.
                    None => break,
                }
            }
            if self.node(x).index < best {
                res = x;
                best = self.node(res).index;
            }
        }
        for m in marked {
            self.clear_mark(m);
        }
        Some(res)
    }

    /// `FlowBlock::findCondition` (block.cc:848): the conditional node
    /// deciding between in-edge `edge1` of `bl1` and in-edge `edge2` of
    /// `bl2`, with the out-slot leading to the first; `None` if there is no
    /// unique one.
    pub(crate) fn find_condition(
        &self,
        mut bl1: NodeId,
        mut edge1: usize,
        mut bl2: NodeId,
        mut edge2: usize,
    ) -> Result<Option<(NodeId, usize)>, CfgError> {
        let mut cond = self.in_(bl1, edge1)?;
        let mut guard = self.nodes.len() + 1;
        while self.size_out(cond) != 2 {
            if self.size_out(cond) != 1 || guard == 0 {
                return Ok(None);
            }
            guard -= 1;
            bl1 = cond;
            edge1 = 0;
            cond = self.in_(bl1, 0)?;
        }
        let mut guard = self.nodes.len() + 1;
        while cond != self.in_(bl2, edge2)? {
            if guard == 0 {
                return Ok(None);
            }
            guard -= 1;
            bl2 = self.in_(bl2, edge2)?;
            if self.size_out(bl2) != 1 {
                return Ok(None);
            }
            edge2 = 0;
        }
        let slot1 = self.in_edge(bl1, edge1)?.rev as usize;
        Ok(Some((cond, slot1)))
    }

    /// Runs `structureLoops` and `calcForwardDominator` as the bare-graph
    /// path (`structure blocks`) does. Returns the root list.
    pub(crate) fn analyse(&mut self, budget: &mut Budget) -> Result<Vec<NodeId>, CfgError> {
        let roots = self.structure_loops(budget)?;
        self.calc_forward_dominator(&roots, budget)?;
        Ok(roots)
    }
}
