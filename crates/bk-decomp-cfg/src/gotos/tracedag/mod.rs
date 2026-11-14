//! Choosing likely gotos by tracing the DAG.
//!
//! Ghidra: `TraceDAG` with `BranchPoint`, `BlockTrace` and `BadEdgeScore`
//! (blockaction.hh:95–186; blockaction.cc:499–1014). Branch points and
//! traces live in arenas; the active list is an index-linked list in
//! insertion order, so removal by stored position is O(1) as with Ghidra's
//! stored iterator.

use crate::error::CfgError;
use crate::flags::edge_labels;
use crate::graph::{Graph, NodeId};
use crate::limits::Budget;

mod score;

type BpId = usize;
type TrId = usize;

const ACTIVE: u8 = 1;
const TERMINAL: u8 = 2;

#[derive(Clone, Debug)]
struct BranchPoint {
    parent: Option<BpId>,
    pathout: i32,
    top: Option<NodeId>,
    paths: Vec<TrId>,
    depth: i32,
    ismark: bool,
}

#[derive(Clone, Debug)]
struct BlockTrace {
    flags: u8,
    top: BpId,
    pathout: i32,
    bottom: Option<NodeId>,
    destnode: Option<NodeId>,
    edgelump: i32,
    derivedbp: Option<BpId>,
    prev: Option<TrId>,
    next: Option<TrId>,
}

impl BlockTrace {
    fn is_active(&self) -> bool {
        self.flags & ACTIVE != 0
    }
    fn is_terminal(&self) -> bool {
        self.flags & TERMINAL != 0
    }
}

#[derive(Clone, Copy, Debug)]
struct BadEdgeScore {
    exitproto: NodeId,
    trace: TrId,
    distance: i32,
    terminal: i32,
    siblingedge: i32,
}

/// One run of the trace (`TraceDAG`).
pub(crate) struct TraceDag<'l> {
    likelygoto: &'l mut Vec<(NodeId, NodeId)>,
    rootlist: Vec<NodeId>,
    bps: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    activecount: usize,
    missedactivecount: usize,
    head: Option<TrId>,
    tail: Option<TrId>,
    finishblock: Option<NodeId>,
}

const BP: CfgError = CfgError::Internal("branch point");
const TR: CfgError = CfgError::Internal("trace");

impl<'l> TraceDag<'l> {
    /// `TraceDAG::TraceDAG`.
    pub(crate) fn new(likelygoto: &'l mut Vec<(NodeId, NodeId)>) -> Self {
        Self {
            likelygoto,
            rootlist: Vec::new(),
            bps: Vec::new(),
            traces: Vec::new(),
            activecount: 0,
            missedactivecount: 0,
            head: None,
            tail: None,
            finishblock: None,
        }
    }

    /// `addRoot`.
    pub(crate) fn add_root(&mut self, root: NodeId) {
        self.rootlist.push(root);
    }

    /// `setFinishBlock`.
    pub(crate) fn set_finish_block(&mut self, bl: NodeId) {
        self.finishblock = Some(bl);
    }

    fn bp(&self, id: BpId) -> Result<&BranchPoint, CfgError> {
        self.bps.get(id).ok_or(BP)
    }
    fn bp_mut(&mut self, id: BpId) -> Result<&mut BranchPoint, CfgError> {
        self.bps.get_mut(id).ok_or(BP)
    }
    fn tr(&self, id: TrId) -> Result<&BlockTrace, CfgError> {
        self.traces.get(id).ok_or(TR)
    }
    fn tr_mut(&mut self, id: TrId) -> Result<&mut BlockTrace, CfgError> {
        self.traces.get_mut(id).ok_or(TR)
    }

    fn new_trace(
        &mut self,
        top: BpId,
        pathout: i32,
        bottom: Option<NodeId>,
        destnode: Option<NodeId>,
    ) -> TrId {
        self.traces.push(BlockTrace {
            flags: 0,
            top,
            pathout,
            bottom,
            destnode,
            edgelump: 1,
            derivedbp: None,
            prev: None,
            next: None,
        });
        self.traces.len() - 1
    }

    /// `insertActive` (blockaction.cc:786).
    fn insert_active(&mut self, t: TrId) -> Result<(), CfgError> {
        let tail = self.tail;
        {
            let tr = self.tr_mut(t)?;
            tr.prev = tail;
            tr.next = None;
            tr.flags |= ACTIVE;
        }
        match tail {
            Some(old) => self.tr_mut(old)?.next = Some(t),
            None => self.head = Some(t),
        }
        self.tail = Some(t);
        self.activecount += 1;
        Ok(())
    }

    /// `removeActive` (blockaction.cc:798).
    fn remove_active(&mut self, t: TrId) -> Result<(), CfgError> {
        let (prev, next) = {
            let tr = self.tr_mut(t)?;
            tr.flags &= !ACTIVE;
            let pn = (tr.prev, tr.next);
            tr.prev = None;
            tr.next = None;
            pn
        };
        match prev {
            Some(p) => self.tr_mut(p)?.next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.tr_mut(n)?.prev = prev,
            None => self.tail = prev,
        }
        self.activecount = self.activecount.saturating_sub(1);
        Ok(())
    }

    /// `TraceDAG::initialize` (blockaction.cc:967).
    pub(crate) fn initialize(&mut self) -> Result<(), CfgError> {
        self.bps.push(BranchPoint {
            parent: None,
            pathout: -1,
            top: None,
            paths: Vec::new(),
            depth: 0,
            ismark: false,
        });
        let roots = std::mem::take(&mut self.rootlist);
        for &r in &roots {
            let po = i32::try_from(self.bp(0)?.paths.len()).map_err(|_err| TR)?;
            let t = self.new_trace(0, po, None, Some(r));
            self.bp_mut(0)?.paths.push(t);
            self.insert_active(t)?;
        }
        self.rootlist = roots;
        Ok(())
    }

    /// `removeTrace` (blockaction.cc:656).
    fn remove_trace(&mut self, g: &mut Graph, t: TrId) -> Result<(), CfgError> {
        let (bottom, dest, edgelump, parentbp, pathout) = {
            let tr = self.tr(t)?;
            (tr.bottom, tr.destnode, tr.edgelump, tr.top, tr.pathout)
        };
        let dest = dest.ok_or(TR)?;
        let bottom_node = bottom.ok_or(TR)?;
        self.likelygoto.push((bottom_node, dest));
        let node = g.node_mut(dest);
        node.visit = node.visit.saturating_add(edgelump);
        if bottom != self.bp(parentbp)?.top {
            let tr = self.tr_mut(t)?;
            tr.flags |= TERMINAL;
            tr.bottom = None;
            tr.destnode = None;
            tr.edgelump = 0;
            return Ok(());
        }
        self.remove_active(t)?;
        let size = self.bp(parentbp)?.paths.len();
        let start = usize::try_from(pathout + 1).map_err(|_err| TR)?;
        for i in start..size {
            let moved = *self.bp(parentbp)?.paths.get(i).ok_or(TR)?;
            let derived = {
                let m = self.tr_mut(moved)?;
                m.pathout -= 1;
                m.derivedbp
            };
            if let Some(d) = derived {
                self.bp_mut(d)?.pathout -= 1;
            }
            if let Some(slot) = self.bp_mut(parentbp)?.paths.get_mut(i - 1) {
                *slot = moved;
            }
        }
        self.bp_mut(parentbp)?.paths.pop();
        Ok(())
    }

    /// `checkOpen` (blockaction.cc:810).
    fn check_open(&self, g: &Graph, t: TrId) -> Result<bool, CfgError> {
        let tr = self.tr(t)?;
        if tr.is_terminal() {
            return Ok(false);
        }
        let mut isroot = false;
        if self.bp(tr.top)?.depth == 0 {
            if tr.bottom.is_none() {
                return Ok(true);
            }
            isroot = true;
        }
        let bl = tr.destnode.ok_or(TR)?;
        if Some(bl) == self.finishblock && !isroot {
            return Ok(false);
        }
        let ignore = i64::from(tr.edgelump) + i64::from(g.node(bl).visit);
        let mut count = 0i64;
        for e in &g.node(bl).ins {
            if e.label & edge_labels::NOT_LOOP_DAG == 0 {
                count += 1;
                if count > ignore {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// `openBranch` (blockaction.cc:839): the next trace to look at.
    fn open_branch(&mut self, g: &Graph, parent: TrId) -> Result<Option<TrId>, CfgError> {
        let (ptop, ppathout, dest) = {
            let tr = self.tr(parent)?;
            (tr.top, tr.pathout, tr.destnode.ok_or(TR)?)
        };
        let depth = self.bp(ptop)?.depth + 1;
        let newbp = self.bps.len();
        self.bps.push(BranchPoint {
            parent: Some(ptop),
            pathout: ppathout,
            top: Some(dest),
            paths: Vec::new(),
            depth,
            ismark: false,
        });
        // `BranchPoint::createTraces` (blockaction.cc:499).
        for i in 0..g.size_out(dest) {
            let e = g.out_edge(dest, i)?;
            if e.label & edge_labels::NOT_LOOP_DAG != 0 {
                continue;
            }
            let po = i32::try_from(self.bp(newbp)?.paths.len()).map_err(|_err| TR)?;
            let t = self.new_trace(newbp, po, Some(dest), Some(e.other));
            self.bp_mut(newbp)?.paths.push(t);
        }
        if self.bp(newbp)?.paths.is_empty() {
            self.bps.pop();
            let tr = self.tr_mut(parent)?;
            tr.derivedbp = None;
            tr.flags |= TERMINAL;
            tr.bottom = None;
            tr.destnode = None;
            tr.edgelump = 0;
            return Ok(Some(parent));
        }
        self.tr_mut(parent)?.derivedbp = Some(newbp);
        self.remove_active(parent)?;
        let paths = self.bp(newbp)?.paths.clone();
        for &p in &paths {
            self.insert_active(p)?;
        }
        Ok(paths.first().copied())
    }

    /// `checkRetirement` (blockaction.cc:866): `Some(exit)` when the trace's
    /// branch point can retire (`exit` is `None` when every path ended).
    #[expect(
        clippy::option_option,
        reason = "retirement with or without a shared exit block"
    )]
    fn check_retirement(&self, t: TrId) -> Result<Option<Option<NodeId>>, CfgError> {
        let tr = self.tr(t)?;
        if tr.pathout != 0 {
            return Ok(None);
        }
        let bp = self.bp(tr.top)?;
        if bp.depth == 0 {
            for &p in &bp.paths {
                let c = self.tr(p)?;
                if !c.is_active() || !c.is_terminal() {
                    return Ok(None);
                }
            }
            return Ok(Some(None));
        }
        let mut outblock = None;
        for &p in &bp.paths {
            let c = self.tr(p)?;
            if !c.is_active() {
                return Ok(None);
            }
            if c.is_terminal() {
                continue;
            }
            if outblock == c.destnode {
                continue;
            }
            if outblock.is_some() {
                return Ok(None);
            }
            outblock = c.destnode;
        }
        Ok(Some(outblock))
    }

    /// `retireBranch` (blockaction.cc:900): the next trace to look at.
    fn retire_branch(
        &mut self,
        bp: BpId,
        exitblock: Option<NodeId>,
    ) -> Result<Option<TrId>, CfgError> {
        let mut edgeout_bl = None;
        let mut edgelump_sum = 0i32;
        let paths = self.bp(bp)?.paths.clone();
        for &p in &paths {
            let c = self.tr(p)?;
            if !c.is_terminal() {
                edgelump_sum = edgelump_sum.saturating_add(c.edgelump);
                if edgeout_bl.is_none() {
                    edgeout_bl = c.bottom;
                }
            }
            self.remove_active(p)?;
        }
        let (depth, parent, pathout) = {
            let b = self.bp(bp)?;
            (b.depth, b.parent, b.pathout)
        };
        if depth == 0 {
            return Ok(self.head);
        }
        let Some(parent) = parent else {
            return Ok(self.head);
        };
        let pt = *self
            .bp(parent)?
            .paths
            .get(usize::try_from(pathout).map_err(|_err| BP)?)
            .ok_or(BP)?;
        {
            let tr = self.tr_mut(pt)?;
            tr.derivedbp = None;
            if edgeout_bl.is_none() {
                tr.flags |= TERMINAL;
                tr.bottom = None;
                tr.destnode = None;
                tr.edgelump = 0;
            } else {
                tr.bottom = edgeout_bl;
                tr.destnode = exitblock;
                tr.edgelump = edgelump_sum;
            }
        }
        self.insert_active(pt)?;
        Ok(Some(pt))
    }

    /// `pushBranches` (blockaction.cc:983).
    ///
    /// In an acyclic view each node is opened at most once; more openings
    /// than nodes mean a cycle that Ghidra would trace forever, which is
    /// [`CfgError::TraceCycle`] here.
    pub(crate) fn push_branches(
        &mut self,
        g: &mut Graph,
        budget: &mut Budget,
    ) -> Result<(), CfgError> {
        let max_opens = 2 * g.list.len() + 8;
        let mut opens = 0usize;
        let mut current = self.head;
        self.missedactivecount = 0;
        while self.activecount > 0 {
            budget.step()?;
            if current.is_none() {
                current = self.head;
            }
            let curtrace = current.ok_or(TR)?;
            if self.missedactivecount >= self.activecount {
                let bad = self.select_bad_edge(g)?;
                self.remove_trace(g, bad)?;
                current = self.head;
                self.missedactivecount = 0;
            } else if let Some(exit) = self.check_retirement(curtrace)? {
                let top = self.tr(curtrace)?.top;
                current = self.retire_branch(top, exit)?;
                self.missedactivecount = 0;
            } else if self.check_open(g, curtrace)? {
                opens += 1;
                if opens > max_opens {
                    return Err(CfgError::TraceCycle);
                }
                current = self.open_branch(g, curtrace)?;
                self.missedactivecount = 0;
            } else {
                self.missedactivecount += 1;
                current = self.tr(curtrace)?.next;
            }
        }
        // `clearVisitCount` (blockaction.cc:940).
        for &(_, bottom) in self.likelygoto.iter() {
            g.node_mut(bottom).visit = 0;
        }
        Ok(())
    }
}
