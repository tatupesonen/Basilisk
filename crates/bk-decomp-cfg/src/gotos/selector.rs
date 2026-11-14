//! Goto selection: the replaceable unit `selectgoto` (ADR-025 item 1).
//!
//! Ghidra: `CollapseStructure::onlyReachableFromRoot` (blockaction.cc:1052),
//! `markExitsAsGotos` (1083), `clipExtraRoots` (1108), `labelLoops` (1126),
//! `orderLoopBodies` (1148), `updateLoopBody` (1193) and `selectGoto`
//! (1260). [`GhidraGotoSelector`] is exactly these.

use super::loopbody::{self, LoopBody, current_edge};
use super::tracedag::TraceDag;
use crate::error::CfgError;
use crate::flags::edge_labels;
use crate::graph::{Graph, NodeId};
use crate::structure::GotoCause;
use crate::structure::collapse::Collapse;

/// What a goto selector sees of a structuring run in progress: the current
/// top level of the working graph, and the means to mark gotos.
pub struct CollapseView<'v, 'a> {
    pub(crate) c: &'v mut Collapse<'a>,
}

impl std::fmt::Debug for CollapseView<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollapseView")
            .field("top_level", &self.c.g.list.len())
            .finish_non_exhaustive()
    }
}

impl CollapseView<'_, '_> {
    /// The current top-level nodes in list order.
    pub fn top_level(&self) -> &[NodeId] {
        &self.c.g.list
    }

    /// The out-edges of `n` as (target, label), in order.
    pub fn out_edges(&self, n: NodeId) -> Vec<(NodeId, u32)> {
        match self.c.g.check(n) {
            Ok(n) => self
                .c
                .g
                .node(n)
                .outs
                .iter()
                .map(|e| (e.other, e.label))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The in-edges of `n` as (source, label), in order.
    pub fn in_edges(&self, n: NodeId) -> Vec<(NodeId, u32)> {
        match self.c.g.check(n) {
            Ok(n) => self
                .c
                .g
                .node(n)
                .ins
                .iter()
                .map(|e| (e.other, e.label))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The index of `n`.
    pub fn index(&self, n: NodeId) -> Option<i32> {
        self.c.g.check(n).ok().map(|n| self.c.g.node(n).index)
    }

    /// Marks out-edge `slot` of the top-level node `n` as a goto
    /// (`setGotoBranch`), recording the mark with `cause`.
    pub fn set_goto_branch(
        &mut self,
        n: NodeId,
        slot: usize,
        cause: GotoCause,
    ) -> Result<(), CfgError> {
        let n = self.c.g.check(n)?;
        if !self.c.g.is_member(n) {
            return Err(CfgError::GotoBranch);
        }
        self.c.set_goto_branch(n, slot, cause)
    }
}

/// The goto-selection step of the structurer: called when no rule applies
/// and nodes are left, it marks at least one edge as a goto and returns the
/// node to try first (or `None`), or fails.
pub trait GotoSelector {
    /// Called once per run, after visit counts are cleared and before any
    /// rule is tried (where Ghidra calls `orderLoopBodies`).
    fn start(&mut self, view: &mut CollapseView<'_, '_>) -> Result<(), CfgError>;

    /// `selectGoto`: marks a goto and returns the node whose edge was marked,
    /// or `None` when edges were marked without a single node to retry.
    fn select(&mut self, view: &mut CollapseView<'_, '_>) -> Result<Option<NodeId>, CfgError>;
}

/// Ghidra's goto selection: loop bodies, the DAG trace and
/// `clipExtraRoots`, exactly as `CollapseStructure` does it
/// (`docs/features/decomp-cfg.md` 4.6–4.7).
#[derive(Clone, Debug, Default)]
pub struct GhidraGotoSelector {
    finaltrace: bool,
    likelylistfull: bool,
    likelygoto: Vec<(NodeId, NodeId)>,
    likelyiter: usize,
    bodies: Vec<LoopBody>,
    /// The `loopbody` list: indices into `bodies`, in list order.
    order: Vec<usize>,
    /// `loopbodyiter`: a position in `order`.
    loopbodyiter: usize,
    body: Vec<NodeId>,
    trial: Vec<NodeId>,
}

impl GhidraGotoSelector {
    /// A selector for a new run.
    pub fn new() -> Self {
        Self::default()
    }

    /// `labelLoops` (blockaction.cc:1126): one body per back edge, and the
    /// order sorted by head then first tail index (stably).
    fn label_loops(&mut self, g: &Graph) -> Vec<usize> {
        let mut looporder = Vec::new();
        for &bl in &g.list {
            for e in &g.node(bl).ins {
                if e.label & edge_labels::BACK != 0 {
                    let mut body = LoopBody::new(bl);
                    body.tails.push(e.other);
                    self.bodies.push(body);
                    looporder.push(self.bodies.len() - 1);
                }
            }
        }
        let key = |i: &usize| {
            self.bodies.get(*i).map(|b| {
                (
                    b.head.map_or(0, |h| g.node(h).index),
                    b.tails.first().map_or(0, |t| g.node(*t).index),
                )
            })
        };
        looporder.sort_by_key(key);
        looporder
    }

    /// `orderLoopBodies` (blockaction.cc:1148).
    fn order_loop_bodies(&mut self, c: &mut Collapse<'_>) -> Result<(), CfgError> {
        let g = &mut c.g;
        let mut looporder = self.label_loops(g);
        if !self.bodies.is_empty() {
            loopbody::merge_identical_heads(&mut looporder, &mut self.bodies);
            self.order = (0..self.bodies.len())
                .filter(|&i| self.bodies.get(i).is_some_and(|b| b.head.is_some()))
                .collect();
            let mut body = std::mem::take(&mut self.body);
            for k in 0..self.order.len() {
                let Some(&bi) = self.order.get(k) else {
                    continue;
                };
                body.clear();
                let b = self
                    .bodies
                    .get_mut(bi)
                    .ok_or(CfgError::Internal("loop body"))?;
                b.find_base(g, &mut body, &mut c.budget)?;
                // `labelContainments` (blockaction.cc:327).
                let head = b.head;
                let mut containlist = Vec::new();
                for &cur in &body {
                    if Some(cur) == head {
                        continue;
                    }
                    if let Some(sub) = loopbody::find(g, cur, &looporder, &self.bodies) {
                        containlist.push(sub);
                        if let Some(s) = self.bodies.get_mut(sub) {
                            s.depth += 1;
                        }
                    }
                }
                let mydepth = self.bodies.get(bi).map_or(0, |b| b.depth);
                for lb in containlist {
                    let container_depth = self
                        .bodies
                        .get(lb)
                        .and_then(|b| b.immed_container)
                        .and_then(|ic| self.bodies.get(ic))
                        .map(|b| b.depth);
                    if container_depth.is_none_or(|d| d < mydepth)
                        && let Some(s) = self.bodies.get_mut(lb)
                    {
                        s.immed_container = Some(bi);
                    }
                }
                g.clear_marks(&body);
            }
            // `loopbody.sort()`: stable, deepest first.
            let bodies = &self.bodies;
            self.order
                .sort_by_key(|&i| std::cmp::Reverse(bodies.get(i).map_or(0, |b| b.depth)));
            let mut trial = std::mem::take(&mut self.trial);
            for k in 0..self.order.len() {
                let Some(&bi) = self.order.get(k) else {
                    continue;
                };
                body.clear();
                let container = self
                    .bodies
                    .get(bi)
                    .and_then(|b| b.immed_container)
                    .and_then(|ic| self.bodies.get(ic))
                    .map(|cb| (cb.head, cb.tails.clone()));
                let b = self
                    .bodies
                    .get_mut(bi)
                    .ok_or(CfgError::Internal("loop body"))?;
                b.find_base(g, &mut body, &mut c.budget)?;
                // `findExit` (blockaction.cc:182).
                let first = b.find_exit_candidates(g, &body, container.is_some(), &mut trial)?;
                b.exitblock = first;
                if first.is_none()
                    && let Some((Some(chead), ctails)) = &container
                    && !trial.is_empty()
                {
                    let mut extension = Vec::new();
                    b.extend_to_container(*chead, ctails, g, &mut extension, &mut c.budget)?;
                    b.exitblock = trial.iter().copied().find(|&t| g.node(t).is_mark());
                    g.clear_marks(&extension);
                }
                b.order_tails(g);
                b.extend(g, &mut body, &mut trial, &mut c.budget)?;
                b.label_exit_edges(g, &body)?;
                g.clear_marks(&body);
            }
            self.trial = trial;
            self.body = body;
        }
        self.likelylistfull = false;
        self.loopbodyiter = 0;
        Ok(())
    }

    /// `updateLoopBody` (blockaction.cc:1193): whether likely gotos remain.
    fn update_loop_body(&mut self, c: &mut Collapse<'_>) -> Result<bool, CfgError> {
        if self.finaltrace {
            return Ok(false);
        }
        let mut loopbottom = None;
        let mut looptop = None;
        while let Some(&bi) = self.order.get(self.loopbodyiter) {
            let body = self
                .bodies
                .get_mut(bi)
                .ok_or(CfgError::Internal("loop body"))?;
            loopbottom = body.update(&c.g)?;
            if let Some(bottom) = loopbottom {
                looptop = body.head;
                if Some(bottom) == looptop {
                    // A node looping to itself that no rule collapsed:
                    // likely a switch.
                    self.likelygoto.clear();
                    self.likelygoto.push((bottom, bottom));
                    self.likelyiter = 0;
                    self.likelylistfull = true;
                    return Ok(true);
                }
                if !self.likelylistfull || self.likelyiter < self.likelygoto.len() {
                    break;
                }
            }
            self.loopbodyiter += 1;
            self.likelylistfull = false;
            loopbottom = None;
        }
        if self.likelylistfull && self.likelyiter < self.likelygoto.len() {
            return Ok(true);
        }
        self.likelygoto.clear();
        let mut likely = std::mem::take(&mut self.likelygoto);
        let current = self.order.get(self.loopbodyiter).copied();
        {
            let mut tracer = TraceDag::new(&mut likely);
            match (loopbottom, looptop, current) {
                (Some(bottom), Some(top), Some(bi)) => {
                    tracer.add_root(top);
                    tracer.set_finish_block(bottom);
                    if let Some(b) = self.bodies.get_mut(bi) {
                        b.exit_marks(&mut c.g, true)?;
                    }
                }
                _ => {
                    for &bl in &c.g.list {
                        if c.g.size_in(bl) == 0 {
                            tracer.add_root(bl);
                        }
                    }
                }
            }
            tracer.initialize()?;
            tracer.push_branches(&mut c.g, &mut c.budget)?;
        }
        self.likelylistfull = true;
        if loopbottom.is_some() {
            if let Some(b) = current.and_then(|bi| self.bodies.get_mut(bi)) {
                b.emit_likely_edges(&mut likely, &c.g)?;
                b.exit_marks(&mut c.g, false)?;
            }
        } else if likely.is_empty() {
            self.likelygoto = likely;
            self.finaltrace = true;
            return Ok(false);
        }
        self.likelygoto = likely;
        self.likelyiter = 0;
        Ok(true)
    }

    /// `onlyReachableFromRoot` (blockaction.cc:1052).
    fn only_reachable_from_root(
        c: &mut Collapse<'_>,
        root: NodeId,
        body: &mut Vec<NodeId>,
        trial: &mut Vec<NodeId>,
    ) -> Result<(), CfgError> {
        let g = &mut c.g;
        trial.clear();
        g.set_mark(root);
        body.push(root);
        let mut i = 0;
        while let Some(&bl) = body.get(i) {
            i += 1;
            for j in 0..g.size_out(bl) {
                c.budget.step()?;
                let curbl = g.out(bl, j)?;
                if g.node(curbl).is_mark() {
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
        Ok(())
    }

    /// `clipExtraRoots` (blockaction.cc:1108) with `markExitsAsGotos`
    /// (1083).
    fn clip_extra_roots(&mut self, c: &mut Collapse<'_>) -> Result<bool, CfgError> {
        let mut body = std::mem::take(&mut self.body);
        let mut trial = std::mem::take(&mut self.trial);
        let result = (|| {
            let mut i = 1;
            while let Some(&bl) = c.g.list.get(i) {
                i += 1;
                if c.g.size_in(bl) != 0 {
                    continue;
                }
                body.clear();
                Self::only_reachable_from_root(c, bl, &mut body, &mut trial)?;
                let mut count = 0;
                for &b in &body {
                    for j in 0..c.g.size_out(b) {
                        let curbl = c.g.out(b, j)?;
                        if !c.g.node(curbl).is_mark() {
                            c.set_goto_branch(b, j, GotoCause::ClippedRoot)?;
                            count += 1;
                        }
                    }
                }
                c.g.clear_marks(&body);
                if count != 0 {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        self.body = body;
        self.trial = trial;
        result
    }
}

impl GotoSelector for GhidraGotoSelector {
    fn start(&mut self, view: &mut CollapseView<'_, '_>) -> Result<(), CfgError> {
        *self = Self {
            body: std::mem::take(&mut self.body),
            trial: std::mem::take(&mut self.trial),
            ..Self::default()
        };
        self.order_loop_bodies(view.c)
    }

    /// `selectGoto` (blockaction.cc:1260).
    fn select(&mut self, view: &mut CollapseView<'_, '_>) -> Result<Option<NodeId>, CfgError> {
        let c = &mut *view.c;
        while self.update_loop_body(c)? {
            while let Some(edge) = self.likelygoto.get_mut(self.likelyiter) {
                self.likelyiter += 1;
                if let Some((startbl, outedge)) = current_edge(&c.g, edge) {
                    c.set_goto_branch(startbl, outedge, GotoCause::Selected)?;
                    return Ok(Some(startbl));
                }
            }
        }
        if !self.clip_extra_roots(c)? {
            return Err(CfgError::CouldNotFinish);
        }
        Ok(None)
    }
}

/// One loop as `orderLoopBodies` leaves it (`LoopBody`), for the oracle's
/// `bk cfg analyze` (`docs/features/decomp-oracle.md` 4.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopInfo {
    /// The head.
    pub head: NodeId,
    /// The nesting depth.
    pub depth: i32,
    /// The chosen exit, if any.
    pub exit: Option<NodeId>,
    /// The number of distinct head and tail nodes.
    pub uniquecount: usize,
    /// The tails, in order.
    pub tails: Vec<NodeId>,
    /// The exit edges (top, bottom), in order.
    pub exit_edges: Vec<(NodeId, NodeId)>,
    /// The head of the immediately containing loop.
    pub immed_container: Option<NodeId>,
}

/// Runs `orderLoopBodies` (blockaction.cc:1148) on a copy of `graph`, whose
/// analyses are taken as given (run [`Cfg::structure_loops`](crate::Cfg::structure_loops) and
/// [`Cfg::forward_dominators`](crate::Cfg::forward_dominators) first for a bare graph), and returns the loop
/// bodies in Ghidra's final `loopbody` order (deepest first).
pub fn loop_bodies(
    graph: &crate::Cfg,
    facts: &crate::BlockFacts,
    limits: &crate::Limits,
) -> Result<Vec<LoopInfo>, CfgError> {
    let input = &graph.g;
    let budget = limits.budget(input.list.len(), input.edge_count())?;
    let work = crate::structure::build_copy(input, input, facts);
    let mut c = Collapse::new(work, input, facts, budget, false);
    c.g.clear_visit_count();
    let mut sel = GhidraGotoSelector::new();
    sel.order_loop_bodies(&mut c)?;
    let mut out = Vec::new();
    for &bi in &sel.order {
        let Some(b) = sel.bodies.get(bi) else {
            continue;
        };
        let Some(head) = b.head else { continue };
        out.push(LoopInfo {
            head,
            depth: b.depth,
            exit: b.exitblock,
            uniquecount: b.uniquecount,
            tails: b.tails.clone(),
            exit_edges: b.exitedges.clone(),
            immed_container: b
                .immed_container
                .and_then(|ic| sel.bodies.get(ic))
                .and_then(|cb| cb.head),
        });
    }
    Ok(out)
}
