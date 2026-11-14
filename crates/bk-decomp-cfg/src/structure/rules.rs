//! The structuring rules except the switch rules.
//!
//! Ghidra: `CollapseStructure::ruleBlockCat` (blockaction.cc:1284),
//! `ruleBlockOr` (1321), `ruleBlockProperIf` (1378), `ruleBlockIfElse`
//! (1416), `ruleBlockGoto` (1450), `ruleBlockIfNoExit` (1481),
//! `ruleBlockWhileDo` (1526), `ruleBlockDoWhile` (1563), `ruleBlockInfLoop`
//! (1587). Each check is in Ghidra's order; each attempt is one work step.

use super::collapse::Collapse;
use crate::error::CfgError;
use crate::flags::node_flags;
use crate::graph::NodeId;

impl Collapse<'_> {
    fn is_switch(&self, n: NodeId) -> bool {
        self.g.node(n).is_switch_out()
    }

    /// `ruleBlockGoto` (blockaction.cc:1450).
    pub(super) fn rule_block_goto(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let sizeout = self.g.size_out(bl);
        for i in 0..sizeout {
            if !self.g.is_goto_out(bl, i)? {
                continue;
            }
            if self.is_switch(bl) {
                self.build(|g, s| g.new_block_multi_goto(bl, i, s))?;
                return Ok(true);
            }
            if sizeout == 2 {
                if !self.g.is_goto_out(bl, 1)? {
                    self.negate(bl)?;
                }
                self.build(|g, s| g.new_block_if_goto(bl, s))?;
                return Ok(true);
            }
            if sizeout == 1 {
                self.build(|g, s| g.new_block_goto(bl, s))?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `ruleBlockCat` (blockaction.cc:1284).
    pub(super) fn rule_block_cat(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 1 || self.is_switch(bl) {
            return Ok(false);
        }
        if g.size_in(bl) == 1 && g.size_out(g.in_(bl, 0)?) == 1 {
            return Ok(false);
        }
        let mut outblock = g.out(bl, 0)?;
        if outblock == bl
            || g.size_in(outblock) != 1
            || !g.is_decision_out(bl, 0)?
            || self.is_switch(outblock)
        {
            return Ok(false);
        }
        let mut nodes = std::mem::take(&mut self.nodes);
        nodes.clear();
        nodes.push(bl);
        nodes.push(outblock);
        while self.g.size_out(outblock) == 1 {
            self.budget.step()?;
            let outbl2 = self.g.out(outblock, 0)?;
            if outbl2 == bl
                || self.g.size_in(outbl2) != 1
                || !self.g.is_decision_out(outblock, 0)?
                || self.is_switch(outbl2)
            {
                break;
            }
            outblock = outbl2;
            nodes.push(outblock);
        }
        let r = self.build(|g, s| g.new_block_list(&nodes, s));
        self.nodes = nodes;
        r?;
        Ok(true)
    }

    /// `ruleBlockOr` (blockaction.cc:1321).
    pub(super) fn rule_block_or(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || g.is_goto_out(bl, 0)?
            || g.is_goto_out(bl, 1)?
            || self.is_switch(bl)
        {
            return Ok(false);
        }
        for i in 0..2usize {
            let g = &self.g;
            let orblock = g.out(bl, i)?;
            if orblock == bl
                || g.size_in(orblock) != 1
                || g.size_out(orblock) != 2
                || g.node(orblock).is_interior_goto_target()
                || self.is_switch(orblock)
                || g.is_back_edge_out(bl, i)?
                || g.is_complex(orblock, self.facts)
            {
                continue;
            }
            let clauseblock = g.out(bl, 1 - i)?;
            if clauseblock == bl || clauseblock == orblock {
                continue;
            }
            let Some(j) = (0..2usize).find(|&j| g.out(orblock, j).ok() == Some(clauseblock)) else {
                continue;
            };
            if g.out(orblock, 1 - j)? == bl {
                continue;
            }
            if i == 1 {
                self.negate(bl)?;
            }
            if j == 0 {
                self.negate(orblock)?;
            }
            self.build(|g, s| g.new_block_condition(bl, orblock, s))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `ruleBlockProperIf` (blockaction.cc:1378).
    pub(super) fn rule_block_proper_if(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || self.is_switch(bl)
            || g.out(bl, 0)? == bl
            || g.out(bl, 1)? == bl
            || g.is_goto_out(bl, 0)?
            || g.is_goto_out(bl, 1)?
        {
            return Ok(false);
        }
        for i in 0..2usize {
            let g = &self.g;
            let clauseblock = g.out(bl, i)?;
            if g.size_in(clauseblock) != 1
                || g.size_out(clauseblock) != 1
                || self.is_switch(clauseblock)
                || !g.is_decision_out(bl, i)?
                || g.is_goto_out(clauseblock, 0)?
            {
                continue;
            }
            if g.out(clauseblock, 0)? != g.out(bl, 1 - i)? {
                continue;
            }
            if i == 0 {
                self.negate(bl)?;
            }
            self.build(|g, s| g.new_block_if(bl, clauseblock, s))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `ruleBlockIfElse` (blockaction.cc:1416).
    pub(super) fn rule_block_if_else(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || self.is_switch(bl)
            || !g.is_decision_out(bl, 0)?
            || !g.is_decision_out(bl, 1)?
        {
            return Ok(false);
        }
        let tc = g.out(bl, 1)?;
        let fc = g.out(bl, 0)?;
        if g.size_in(tc) != 1 || g.size_in(fc) != 1 || g.size_out(tc) != 1 || g.size_out(fc) != 1 {
            return Ok(false);
        }
        let outblock = g.out(tc, 0)?;
        if outblock == bl || outblock != g.out(fc, 0)? {
            return Ok(false);
        }
        if self.is_switch(tc)
            || self.is_switch(fc)
            || g.is_goto_out(tc, 0)?
            || g.is_goto_out(fc, 0)?
        {
            return Ok(false);
        }
        self.build(|g, s| g.new_block_if_else(bl, tc, fc, s))?;
        Ok(true)
    }

    /// `ruleBlockIfNoExit` (blockaction.cc:1481).
    pub(super) fn rule_block_if_no_exit(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || self.is_switch(bl)
            || g.out(bl, 0)? == bl
            || g.out(bl, 1)? == bl
            || g.is_goto_out(bl, 0)?
            || g.is_goto_out(bl, 1)?
        {
            return Ok(false);
        }
        for i in 0..2usize {
            let g = &self.g;
            let clauseblock = g.out(bl, i)?;
            if g.size_in(clauseblock) != 1
                || g.size_out(clauseblock) != 0
                || self.is_switch(clauseblock)
                || !g.is_decision_out(bl, i)?
            {
                continue;
            }
            if i == 0 {
                let other = g.out(bl, 1)?;
                if g.size_in(other) == 1
                    && g.size_out(other) == 0
                    && !self.is_switch(other)
                    && g.is_decision_out(bl, 1)?
                {
                    self.negate(bl)?;
                    self.build(|g, s| g.new_block_if_no_exit(bl, clauseblock, other, s))?;
                    return Ok(true);
                }
                self.negate(bl)?;
            }
            self.build(|g, s| g.new_block_if(bl, clauseblock, s))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `ruleBlockWhileDo` (blockaction.cc:1526).
    pub(super) fn rule_block_while_do(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || self.is_switch(bl)
            || g.out(bl, 0)? == bl
            || g.out(bl, 1)? == bl
            || g.node(bl).is_interior_goto_target()
            || g.is_goto_out(bl, 0)?
            || g.is_goto_out(bl, 1)?
        {
            return Ok(false);
        }
        for i in 0..2usize {
            let g = &self.g;
            let clauseblock = g.out(bl, i)?;
            if g.size_in(clauseblock) != 1
                || g.size_out(clauseblock) != 1
                || self.is_switch(clauseblock)
                || g.out(clauseblock, 0)? != bl
            {
                continue;
            }
            let overflow = g.is_complex(bl, self.facts);
            if (i == 0) != overflow {
                self.negate(bl)?;
            }
            let newbl = self.build(|g, s| g.new_block_while_do(bl, clauseblock, s))?;
            if overflow {
                self.g.node_mut(newbl).flags |= node_flags::WHILEDO_OVERFLOW;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// `ruleBlockDoWhile` (blockaction.cc:1563).
    pub(super) fn rule_block_do_while(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 2
            || self.is_switch(bl)
            || g.is_goto_out(bl, 0)?
            || g.is_goto_out(bl, 1)?
        {
            return Ok(false);
        }
        for i in 0..2usize {
            if self.g.out(bl, i)? != bl {
                continue;
            }
            if i == 0 {
                self.negate(bl)?;
            }
            self.build(|g, s| g.new_block_do_while(bl, s))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `ruleBlockInfLoop` (blockaction.cc:1587); a switch is deliberately
    /// allowed.
    pub(super) fn rule_block_inf_loop(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        let g = &self.g;
        if g.size_out(bl) != 1 || g.is_goto_out(bl, 0)? || g.out(bl, 0)? != bl {
            return Ok(false);
        }
        self.build(|g, s| g.new_block_inf_loop(bl, s))?;
        Ok(true)
    }
}
