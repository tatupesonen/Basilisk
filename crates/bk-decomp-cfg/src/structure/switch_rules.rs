//! The switch rules.
//!
//! Ghidra: `CollapseStructure::checkSwitchSkips` (blockaction.cc:1615),
//! `ruleBlockSwitch` (1657) and `ruleCaseFallthru` (1737). The last two can
//! report "applied" having only marked gotos.

use super::GotoCause;
use super::collapse::Collapse;
use crate::error::CfgError;
use crate::flags::Kind;
use crate::graph::{KindData, NodeId};

impl Collapse<'_> {
    /// `checkSwitchSkips` (blockaction.cc:1615): `false` when skip edges to
    /// the exit were turned into gotos.
    fn check_switch_skips(
        &mut self,
        switchbl: NodeId,
        exitblock: Option<NodeId>,
    ) -> Result<bool, CfgError> {
        let Some(exitblock) = exitblock else {
            return Ok(true);
        };
        let sizeout = self.g.size_out(switchbl);
        let mut defaultnottoexit = false;
        let mut anyskiptoexit = false;
        for edgenum in 0..sizeout {
            let isdefault = self.g.is_default_branch(switchbl, edgenum)?;
            if self.g.out(switchbl, edgenum)? == exitblock {
                if !isdefault {
                    anyskiptoexit = true;
                }
            } else if isdefault {
                defaultnottoexit = true;
            }
        }
        if !anyskiptoexit {
            return Ok(true);
        }
        if !defaultnottoexit
            && self.g.node(switchbl).kind == Kind::MultiGoto
            && matches!(
                self.g.node(switchbl).data,
                KindData::MultiGoto { default: true, .. }
            )
        {
            defaultnottoexit = true;
        }
        if !defaultnottoexit {
            return Ok(true);
        }
        self.begin_batch();
        for edgenum in 0..sizeout {
            if self.g.out(switchbl, edgenum)? == exitblock
                && !self.g.is_default_branch(switchbl, edgenum)?
            {
                self.set_goto_branch(switchbl, edgenum, GotoCause::SwitchSkip)?;
            }
        }
        self.end_batch();
        Ok(false)
    }

    /// `ruleBlockSwitch` (blockaction.cc:1657).
    pub(super) fn rule_block_switch(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        if !self.g.node(bl).is_switch_out() {
            return Ok(false);
        }
        let sizeout = self.g.size_out(bl);
        let mut exitblock = None;
        for i in 0..sizeout {
            let curbl = self.g.out(bl, i)?;
            if curbl == bl || self.g.size_out(curbl) > 1 || self.g.size_in(curbl) > 1 {
                exitblock = Some(curbl);
                break;
            }
        }
        match exitblock {
            None => {
                for i in 0..sizeout {
                    let curbl = self.g.out(bl, i)?;
                    if self.g.is_goto_in(curbl, 0)? || self.g.node(curbl).is_switch_out() {
                        return Ok(false);
                    }
                    if self.g.size_out(curbl) == 1 {
                        if self.g.is_goto_out(curbl, 0)? {
                            return Ok(false);
                        }
                        let o = self.g.out(curbl, 0)?;
                        match exitblock {
                            Some(e) if e != o => return Ok(false),
                            Some(_) => {}
                            None => exitblock = Some(o),
                        }
                    }
                }
            }
            Some(exit) => {
                for i in 0..self.g.size_in(exit) {
                    if self.g.is_goto_in(exit, i)? {
                        return Ok(false);
                    }
                }
                for i in 0..self.g.size_out(exit) {
                    if self.g.is_goto_out(exit, i)? {
                        return Ok(false);
                    }
                }
                for i in 0..sizeout {
                    let curbl = self.g.out(bl, i)?;
                    if curbl == exit {
                        continue;
                    }
                    if self.g.size_in(curbl) > 1
                        || self.g.is_goto_in(curbl, 0)?
                        || self.g.size_out(curbl) > 1
                    {
                        return Ok(false);
                    }
                    if self.g.size_out(curbl) == 1
                        && (self.g.is_goto_out(curbl, 0)? || self.g.out(curbl, 0)? != exit)
                    {
                        return Ok(false);
                    }
                    if self.g.node(curbl).is_switch_out() {
                        return Ok(false);
                    }
                }
            }
        }
        if !self.check_switch_skips(bl, exitblock)? {
            return Ok(true);
        }
        let mut cases = std::mem::take(&mut self.nodes);
        cases.clear();
        cases.push(bl);
        for i in 0..sizeout {
            let curbl = self.g.out(bl, i)?;
            if Some(curbl) != exitblock {
                cases.push(curbl);
            }
        }
        let orig = self.orig;
        let r = self.build(|g, s| g.new_block_switch(orig, &cases, exitblock.is_some(), s));
        self.nodes = cases;
        r?;
        Ok(true)
    }

    /// `ruleCaseFallthru` (blockaction.cc:1737).
    pub(super) fn rule_case_fallthru(&mut self, bl: NodeId) -> Result<bool, CfgError> {
        self.budget.step()?;
        if !self.g.node(bl).is_switch_out() {
            return Ok(false);
        }
        let sizeout = self.g.size_out(bl);
        let mut nonfallthru = 0;
        let mut fallthru = std::mem::take(&mut self.nodes);
        fallthru.clear();
        let result = (|| {
            for i in 0..sizeout {
                let curbl = self.g.out(bl, i)?;
                if curbl == bl {
                    return Ok(false);
                }
                if self.g.size_in(curbl) > 2 || self.g.size_out(curbl) > 1 {
                    nonfallthru += 1;
                } else if self.g.size_out(curbl) == 1 {
                    let target = self.g.out(curbl, 0)?;
                    if self.g.size_in(target) == 2 && self.g.size_out(target) <= 1 {
                        let inslot = self.g.out_edge(curbl, 0)?.rev as usize;
                        if inslot <= 1 && self.g.in_(target, 1 - inslot)? == bl {
                            fallthru.push(curbl);
                        }
                    }
                }
                if nonfallthru > 1 {
                    return Ok(false);
                }
            }
            if fallthru.is_empty() {
                return Ok(false);
            }
            self.begin_batch();
            for &curbl in &fallthru {
                self.set_goto_branch(curbl, 0, GotoCause::CaseFallthru)?;
            }
            self.end_batch();
            Ok(true)
        })();
        self.nodes = fallthru;
        result
    }
}
