//! Choosing the bad edge when no trace can move.
//!
//! Ghidra: `BranchPoint::markPath` (blockaction.cc:509), `distance` (524),
//! `BadEdgeScore::compareFinal` (617), `TraceDAG::processExitConflict`
//! (694) and `selectBadEdge` (730).

use super::{BadEdgeScore, BpId, TR, TrId, TraceDag};
use crate::error::CfgError;
use crate::graph::Graph;

impl TraceDag<'_> {
    /// `BranchPoint::markPath` (blockaction.cc:509).
    pub(super) fn mark_path(&mut self, bp: BpId) -> Result<(), CfgError> {
        let mut cur = Some(bp);
        while let Some(c) = cur {
            let b = self.bp_mut(c)?;
            b.ismark = !b.ismark;
            cur = b.parent;
        }
        Ok(())
    }

    /// `BranchPoint::distance` (blockaction.cc:524).
    pub(super) fn distance(&self, this: BpId, op2: BpId) -> Result<i32, CfgError> {
        let depth = self.bp(this)?.depth;
        let op2depth = self.bp(op2)?.depth;
        let mut cur = Some(op2);
        while let Some(c) = cur {
            let b = self.bp(c)?;
            if b.ismark {
                return Ok((depth - b.depth) + (op2depth - b.depth));
            }
            cur = b.parent;
        }
        Ok(depth + op2depth + 1)
    }

    /// `processExitConflict` (blockaction.cc:694) over `scores[start..end]`.
    fn process_exit_conflict(
        &mut self,
        scores: &mut [BadEdgeScore],
        start: usize,
        end: usize,
    ) -> Result<(), CfgError> {
        for s in start..end {
            let startbp = self.tr(scores.get(s).ok_or(TR)?.trace)?.top;
            if s + 1 == end {
                continue;
            }
            self.mark_path(startbp)?;
            for k in s + 1..end {
                let kbp = self.tr(scores.get(k).ok_or(TR)?.trace)?.top;
                if startbp == kbp {
                    if let Some(a) = scores.get_mut(s) {
                        a.siblingedge += 1;
                    }
                    if let Some(b) = scores.get_mut(k) {
                        b.siblingedge += 1;
                    }
                }
                let dist = self.distance(startbp, kbp)?;
                for idx in [s, k] {
                    if let Some(sc) = scores.get_mut(idx)
                        && (sc.distance == -1 || sc.distance > dist)
                    {
                        sc.distance = dist;
                    }
                }
            }
            self.mark_path(startbp)?;
        }
        Ok(())
    }

    /// `BadEdgeScore::compareFinal` (blockaction.cc:617): whether `a` is
    /// less likely to be the bad edge than `b`.
    fn compare_final(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> Result<bool, CfgError> {
        if a.siblingedge != b.siblingedge {
            return Ok(b.siblingedge < a.siblingedge);
        }
        if a.terminal != b.terminal {
            return Ok(a.terminal < b.terminal);
        }
        if a.distance != b.distance {
            return Ok(a.distance < b.distance);
        }
        let ad = self.bp(self.tr(a.trace)?.top)?.depth;
        let bd = self.bp(self.tr(b.trace)?.top)?.depth;
        Ok(ad < bd)
    }

    /// `selectBadEdge` (blockaction.cc:730). An empty candidate list, which
    /// Ghidra dereferences, is [`CfgError::NoBadEdge`].
    pub(super) fn select_bad_edge(&mut self, g: &Graph) -> Result<TrId, CfgError> {
        let mut scores: Vec<BadEdgeScore> = Vec::new();
        let mut cur = self.head;
        while let Some(t) = cur {
            let tr = self.tr(t)?;
            cur = tr.next;
            if tr.is_terminal() {
                continue;
            }
            if self.bp(tr.top)?.top.is_none() && tr.bottom.is_none() {
                continue;
            }
            let dest = tr.destnode.ok_or(TR)?;
            scores.push(BadEdgeScore {
                exitproto: dest,
                trace: t,
                distance: -1,
                terminal: i32::from(g.size_out(dest) == 0),
                siblingedge: 0,
            });
        }
        // `list::sort` is stable: by exit index, branch-point index, pathout.
        let mut keyed = Vec::with_capacity(scores.len());
        for s in &scores {
            let tr = self.tr(s.trace)?;
            let bptop = self.bp(tr.top)?.top.map_or(-1, |n| g.node(n).index);
            keyed.push((g.node(s.exitproto).index, bptop, tr.pathout));
        }
        let mut order: Vec<usize> = (0..scores.len()).collect();
        order.sort_by_key(|&i| keyed.get(i).copied());
        let mut sorted: Vec<BadEdgeScore> = order
            .iter()
            .filter_map(|&i| scores.get(i).copied())
            .collect();

        let first = sorted.first().ok_or(CfgError::NoBadEdge)?;
        let mut curbl = first.exitproto;
        let mut startiter = 0;
        let mut samenodecount = 1;
        for idx in 1..sorted.len() {
            let ex = sorted.get(idx).ok_or(TR)?.exitproto;
            if ex == curbl {
                samenodecount += 1;
            } else {
                if samenodecount > 1 {
                    self.process_exit_conflict(&mut sorted, startiter, idx)?;
                }
                curbl = ex;
                startiter = idx;
                samenodecount = 1;
            }
        }
        if samenodecount > 1 {
            let end = sorted.len();
            self.process_exit_conflict(&mut sorted, startiter, end)?;
        }
        let mut maxi = 0;
        for idx in 1..sorted.len() {
            let (a, b) = (sorted.get(maxi).ok_or(TR)?, sorted.get(idx).ok_or(TR)?);
            if self.compare_final(a, b)? {
                maxi = idx;
            }
        }
        Ok(sorted.get(maxi).ok_or(TR)?.trace)
    }
}
