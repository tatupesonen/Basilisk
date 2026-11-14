//! The factories for structured nodes.
//!
//! Ghidra: `BlockGraph::newBlockCopy` (block.cc:1686) and the identify
//! factories `newBlockGoto` … `newBlockSwitch` (1707–1937). Each builds
//! the node, collapses its components with `identifyInternal`, appends it
//! to the top-level list and applies its fix-ups.

use crate::error::CfgError;
use crate::flags::{CondOp, Kind, node_flags};
use crate::graph::{Graph, KindData, Node, NodeId};

impl Graph {
    /// Creates a structured node of `kind` from `nodes` and appends it to
    /// the list (`identifyInternal` then `addBlock`).
    fn identify_new(
        &mut self,
        kind: Kind,
        data: KindData,
        nodes: &[NodeId],
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let mut node = Node::new(kind);
        node.data = data;
        let ret = self.push(node)?;
        self.identify_internal(ret, nodes, scratch)?;
        self.add_block_root(ret);
        Ok(ret)
    }

    /// `newBlockGoto` (block.cc:1707): `bl`'s single out-edge becomes the
    /// goto and is removed.
    pub(crate) fn new_block_goto(
        &mut self,
        bl: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let target = self.out(bl, 0)?;
        let data = KindData::Goto {
            target,
            goto_type: node_flags::GOTO_GOTO,
        };
        let ret = self.identify_new(Kind::Goto, data, &[bl], scratch)?;
        self.force_output_num(ret, 1)?;
        let out = self.out(ret, 0)?;
        self.remove_edge(ret, out)?;
        Ok(ret)
    }

    /// `newBlockMultiGoto` (block.cc:1725): out-edge `outedge` of `bl`
    /// becomes a goto of a (possibly existing) multigoto node.
    pub(crate) fn new_block_multi_goto(
        &mut self,
        bl: NodeId,
        outedge: usize,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let targetbl = self.out(bl, outedge)?;
        let isdefault = self.is_default_branch(bl, outedge)?;
        if self.node(bl).kind == Kind::MultiGoto {
            if let KindData::MultiGoto { targets, default } = &mut self.node_mut(bl).data {
                targets.push(targetbl);
                if isdefault {
                    *default = true;
                }
            }
            self.remove_edge(bl, targetbl)?;
            return Ok(bl);
        }
        let orig_size_out = self.size_out(bl);
        let data = KindData::MultiGoto {
            targets: vec![targetbl],
            default: isdefault,
        };
        let ret = self.identify_new(Kind::MultiGoto, data, &[bl], scratch)?;
        if targetbl != bl {
            if self.size_out(ret) != orig_size_out {
                // A self edge was collapsed; keep it (it is not the goto).
                self.force_output_num(ret, self.size_out(ret) + 1)?;
            }
            self.remove_edge(ret, targetbl)?;
        }
        Ok(ret)
    }

    /// `newBlockList` (block.cc:1763).
    pub(crate) fn new_block_list(
        &mut self,
        nodes: &[NodeId],
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let last = *nodes.last().ok_or(CfgError::Internal("empty list"))?;
        let outforce = self.size_out(last);
        let out0 = if outforce == 2 {
            Some(self.out(last, 0)?)
        } else {
            None
        };
        let ret = self.identify_new(Kind::List, KindData::None, nodes, scratch)?;
        self.force_output_num(ret, outforce)?;
        if self.size_out(ret) == 2 {
            self.force_false_edge(ret, out0)?;
        }
        Ok(ret)
    }

    /// `newBlockCondition` (block.cc:1785).
    pub(crate) fn new_block_condition(
        &mut self,
        b1: NodeId,
        b2: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let out0 = self.out(b2, 0)?;
        let opc = if self.out(b1, 0)? == b2 {
            CondOp::IntOr
        } else {
            CondOp::IntAnd
        };
        let ret = self.identify_new(
            Kind::Condition,
            KindData::Condition(opc),
            &[b1, b2],
            scratch,
        )?;
        self.force_output_num(ret, 2)?;
        self.force_false_edge(ret, Some(out0))?;
        Ok(ret)
    }

    /// `newBlockIfGoto` (block.cc:1804).
    pub(crate) fn new_block_if_goto(
        &mut self,
        cond: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        if !self.is_goto_out(cond, 1)? {
            return Err(CfgError::IfGotoTrueBranch);
        }
        let out0 = self.out(cond, 0)?;
        let target = self.out(cond, 1)?;
        let data = KindData::Goto {
            target,
            goto_type: node_flags::GOTO_GOTO,
        };
        let ret = self.identify_new(Kind::IfGoto, data, &[cond], scratch)?;
        self.force_output_num(ret, 2)?;
        self.force_false_edge(ret, Some(out0))?;
        let t = self.out(ret, 1)?;
        self.remove_edge(ret, t)?;
        Ok(ret)
    }

    /// `newBlockIf` (block.cc:1826).
    pub(crate) fn new_block_if(
        &mut self,
        cond: NodeId,
        tc: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let ret = self.identify_new(Kind::If, KindData::None, &[cond, tc], scratch)?;
        self.force_output_num(ret, 1)?;
        Ok(ret)
    }

    /// `newBlockIfElse` (block.cc:1844).
    pub(crate) fn new_block_if_else(
        &mut self,
        cond: NodeId,
        tc: NodeId,
        fc: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let ret = self.identify_new(Kind::IfElse, KindData::None, &[cond, tc, fc], scratch)?;
        self.force_output_num(ret, 1)?;
        Ok(ret)
    }

    /// `newBlockIfNoExit` (block.cc:1858).
    pub(crate) fn new_block_if_no_exit(
        &mut self,
        cond: NodeId,
        tc: NodeId,
        fc: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        self.identify_new(Kind::IfNoExit, KindData::None, &[cond, tc, fc], scratch)
    }

    /// `newBlockWhileDo` (block.cc:1875).
    pub(crate) fn new_block_while_do(
        &mut self,
        cond: NodeId,
        cl: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let ret = self.identify_new(Kind::WhileDo, KindData::None, &[cond, cl], scratch)?;
        self.force_output_num(ret, 1)?;
        Ok(ret)
    }

    /// `newBlockDoWhile` (block.cc:1891).
    pub(crate) fn new_block_do_while(
        &mut self,
        condcl: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let ret = self.identify_new(Kind::DoWhile, KindData::None, &[condcl], scratch)?;
        self.force_output_num(ret, 1)?;
        Ok(ret)
    }

    /// `newBlockInfLoop` (block.cc:1906).
    pub(crate) fn new_block_inf_loop(
        &mut self,
        body: NodeId,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        self.identify_new(Kind::InfLoop, KindData::None, &[body], scratch)
    }

    /// `newBlockSwitch` (block.cc:1921): `cs` is the switch node followed by
    /// its cases; `orig` is the input graph the cases are looked up in.
    pub(crate) fn new_block_switch(
        &mut self,
        orig: &Self,
        cs: &[NodeId],
        has_exit: bool,
        scratch: &mut Vec<NodeId>,
    ) -> Result<NodeId, CfgError> {
        let rootbl = *cs.first().ok_or(CfgError::Internal("empty switch"))?;
        let leaf = self
            .exit_leaf(rootbl)
            .filter(|&l| self.node(l).kind == Kind::Copy)
            .ok_or(CfgError::SwitchLeaf)?;
        let cases = self.grab_case_basic(orig, leaf, cs)?;
        let ret = self.identify_new(Kind::Switch, KindData::Switch(cases), cs, scratch)?;
        if has_exit {
            self.force_output_num(ret, 1)?;
        }
        self.node_mut(ret).flags &= !node_flags::SWITCH_OUT;
        Ok(ret)
    }
}
