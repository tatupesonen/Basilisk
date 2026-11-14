//! The cases of a switch node.
//!
//! Ghidra: `BlockSwitch::CaseOrder` (block.hh:811), `addCase`
//! (block.cc:3618), `grabCaseBasic` (3647), the sort of
//! `finalizePrinting` (3679–3714) with the labels as input, and
//! `CaseOrder::compare` (block.hh:973).
//!
//! `grabCaseBasic` reads the *original* basic blocks (`subBlock(0)` of a
//! copy): their in-edge order, the out-slot of the switch block and its
//! default label. The structurer never flips a switch block, so the input
//! graph as given answers these exactly (`docs/agents/decomp-cfg.md`).

use crate::error::CfgError;
use crate::flags::{Kind, node_flags};
use crate::graph::{Graph, KindData, NodeId, to_i32};

/// One case of a switch (`BlockSwitch::CaseOrder`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseOrder {
    /// The structured case node.
    pub block: NodeId,
    /// The first input node executed in the case.
    pub basicblock: NodeId,
    /// The case label (set by [`finish`](crate::finish) from the labels
    /// given; 0 otherwise).
    pub label: u64,
    /// How deep in a fall-through chain the case is.
    pub depth: i32,
    /// The case this one falls through to (an index into the cases), or −1.
    pub chain: i32,
    /// The out-slot of the switch block leading to this case.
    pub outindex: i32,
    /// The goto type when the switch edge to the case is unstructured, else
    /// 0.
    pub gototype: u32,
    /// Whether the case flows to the switch's exit.
    pub isexit: bool,
    /// Whether this is the formal default case.
    pub isdefault: bool,
}

impl CaseOrder {
    /// `CaseOrder::compare` (block.hh:973): by label, then depth.
    pub(crate) fn key(&self) -> (u64, i32) {
        (self.label, self.depth)
    }
}

impl Graph {
    /// `BlockSwitch::addCase` (block.cc:3618).
    fn add_case(
        &self,
        orig: &Self,
        cases: &mut Vec<CaseOrder>,
        switchbl: NodeId,
        bl: NodeId,
        gt: u32,
    ) -> Result<(), CfgError> {
        let basicbl = self.front_leaf(bl).ok_or(CfgError::CaseDetached)?;
        orig.check(basicbl)?;
        let inindex = orig
            .in_index(basicbl, switchbl)
            .ok_or(CfgError::CaseDetached)?;
        let outindex = orig.in_edge(basicbl, inindex)?.rev as usize;
        let isexit = gt == 0 && self.size_out(bl) == 1;
        let isdefault = orig.is_default_branch(switchbl, outindex)?;
        cases.push(CaseOrder {
            block: bl,
            basicblock: basicbl,
            label: 0,
            depth: 0,
            chain: -1,
            outindex: to_i32(outindex)?,
            gototype: gt,
            isexit,
            isdefault,
        });
        Ok(())
    }

    /// `BlockSwitch::grabCaseBasic` (block.cc:3647): the cases of the switch
    /// whose components are `cs` (the switch node first), with fall-through
    /// chains and the goto cases of a multigoto root.
    pub(crate) fn grab_case_basic(
        &self,
        orig: &Self,
        switchbl: NodeId,
        cs: &[NodeId],
    ) -> Result<Vec<CaseOrder>, CfgError> {
        orig.check(switchbl)?;
        let mut casemap: Vec<i32> = vec![-1; orig.size_out(switchbl)];
        let mut cases = Vec::with_capacity(cs.len());
        for (i, &casebl) in cs.iter().enumerate().skip(1) {
            self.add_case(orig, &mut cases, switchbl, casebl, 0)?;
            let outindex = cases.last().map_or(-1, |c| c.outindex);
            if let Some(slot) = usize::try_from(outindex)
                .ok()
                .and_then(|o| casemap.get_mut(o))
            {
                *slot = to_i32(i - 1)?;
            }
        }
        for case in &mut cases {
            if self.node(case.block).kind != Kind::Goto {
                continue;
            }
            let KindData::Goto { target, .. } = self.node(case.block).data else {
                continue;
            };
            let Some(basicbl) = self.front_leaf(target) else {
                continue;
            };
            if orig.check(basicbl).is_err() {
                continue;
            }
            let Some(inindex) = orig.in_index(basicbl, switchbl) else {
                continue;
            };
            let rev = orig.in_edge(basicbl, inindex)?.rev as usize;
            case.chain = casemap.get(rev).copied().unwrap_or(-1);
        }
        if let Some(&root) = cs.first()
            && self.node(root).kind == Kind::MultiGoto
            && let KindData::MultiGoto { targets, .. } = &self.node(root).data
        {
            for &t in targets {
                self.add_case(orig, &mut cases, switchbl, t, node_flags::GOTO_GOTO)?;
            }
        }
        Ok(cases)
    }
}

/// The ordering half of `BlockSwitch::finalizePrinting` (block.cc:3685–3714):
/// depths along fall-through chains, labels from `first_label` (the first
/// label of a case's first input node, or `None` when the jump table has no
/// index for it), then a stable sort by label and depth.
pub(crate) fn order_cases(cases: &mut [CaseOrder], first_label: &dyn Fn(NodeId) -> Option<u64>) {
    let n = cases.len();
    let chain_of = |cases: &[CaseOrder], j: i32| -> Option<usize> {
        usize::try_from(j).ok().filter(|&j| j < cases.len())
    };
    for i in 0..n {
        let mut j = cases.get(i).and_then(|c| chain_of(cases, c.chain));
        let mut guard = n;
        while let Some(k) = j {
            if guard == 0 {
                break;
            }
            guard -= 1;
            let Some(c) = cases.get_mut(k) else { break };
            if c.depth != 0 {
                break;
            }
            c.depth = -1;
            let next = c.chain;
            j = chain_of(cases, next);
        }
    }
    for i in 0..n {
        let Some(cur) = cases.get(i).copied() else {
            continue;
        };
        match first_label(cur.basicblock) {
            Some(label) => {
                if cur.depth != 0 {
                    continue;
                }
                if let Some(c) = cases.get_mut(i) {
                    c.label = label;
                }
                let mut j = chain_of(cases, cur.chain);
                let mut depthcount = 1;
                let mut guard = n;
                while let Some(k) = j {
                    if guard == 0 {
                        break;
                    }
                    guard -= 1;
                    let Some(c) = cases.get_mut(k) else { break };
                    if c.depth > 0 {
                        break;
                    }
                    c.depth = depthcount;
                    depthcount += 1;
                    c.label = label;
                    let next = c.chain;
                    j = chain_of(cases, next);
                }
            }
            None => {
                if let Some(c) = cases.get_mut(i) {
                    c.label = 0;
                }
            }
        }
    }
    cases.sort_by_key(CaseOrder::key);
}
