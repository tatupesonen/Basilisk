//! Per-kind queries over the hierarchy.
//!
//! Ghidra: the virtual `getFrontLeaf` (block.cc:344), `getExitLeaf`
//! (block.hh:236, 554, 585, 613, 729; block.cc:3015), `calcDepth`
//! (block.cc:372), `isComplex` (block.hh:259, 559, 659), `lastOp` as
//! `compareFinalOrder` uses it (block.hh:556, 586, 614, 710, 730;
//! block.cc:3022, 3078) and `nextFlowAfter` (block.cc:1349, 2961, 2993,
//! 3115, 3143, 3461, 3571, 3599, 3762), `BlockGoto::gotoPrints` (2943).
//! All iterative: the hierarchy's depth grows with the input's nesting.

use crate::facts::BlockFacts;
use crate::flags::Kind;
use crate::graph::{Graph, KindData, NodeId};

impl Graph {
    /// `getFrontLeaf`: descends through first components to a copy; `None`
    /// when a node without components is reached first.
    pub(crate) fn front_leaf(&self, id: NodeId) -> Option<NodeId> {
        let mut bl = id;
        let mut guard = self.nodes.len();
        while self.node(bl).kind != Kind::Copy {
            if guard == 0 {
                return None;
            }
            guard -= 1;
            bl = *self.node(bl).comps.first()?;
        }
        Some(bl)
    }

    /// `getExitLeaf`: the only leaf with structured edges out of `id`, or
    /// `None`.
    pub(crate) fn exit_leaf(&self, id: NodeId) -> Option<NodeId> {
        let mut bl = id;
        let mut guard = self.nodes.len();
        loop {
            if guard == 0 {
                return None;
            }
            guard -= 1;
            let node = self.node(bl);
            bl = match node.kind {
                Kind::Copy => return Some(bl),
                Kind::Goto | Kind::MultiGoto | Kind::IfGoto => *node.comps.first()?,
                Kind::List => *node.comps.last()?,
                _ => return None,
            };
        }
    }

    /// `calcDepth`: the number of parent steps from `leaf` up to `this`, or
    /// −1 if `this` is not above it.
    pub(crate) fn calc_depth(&self, this: NodeId, leaf: Option<NodeId>) -> i32 {
        let mut depth = 0;
        let mut cur = leaf;
        loop {
            match cur {
                Some(l) if l == this => return depth,
                Some(l) => {
                    cur = self.node(l).parent;
                    depth += 1;
                }
                None => return -1,
            }
        }
    }

    /// Whether `lastOp()` of `id` is a `RETURN`, as `compareFinalOrder`
    /// (block.cc:718) asks it; a null last op is not.
    pub(crate) fn ends_in_return(&self, id: NodeId, facts: &BlockFacts) -> bool {
        let mut bl = id;
        let mut guard = self.nodes.len();
        loop {
            if guard == 0 {
                return false;
            }
            guard -= 1;
            let node = self.node(bl);
            let next = match node.kind {
                Kind::Copy | Kind::Plain => return facts.get(bl.index()).ends_in_return,
                Kind::Goto | Kind::MultiGoto | Kind::IfGoto => node.comps.first(),
                Kind::List => node.comps.last(),
                Kind::Condition => node.comps.get(1),
                Kind::IfNoExit => node.comps.get(2),
                _ => None,
            };
            match next {
                Some(&n) => bl = n,
                None => return false,
            }
        }
    }

    /// `isComplex`: the fact for a copy, the first component's answer for a
    /// condition, `true` for everything else.
    pub(crate) fn is_complex(&self, id: NodeId, facts: &BlockFacts) -> bool {
        let mut bl = id;
        let mut guard = self.nodes.len();
        loop {
            if guard == 0 {
                return true;
            }
            guard -= 1;
            let node = self.node(bl);
            match node.kind {
                Kind::Copy | Kind::Plain => return facts.get(bl.index()).complex,
                Kind::Condition => match node.comps.first() {
                    Some(&c) => bl = c,
                    None => return true,
                },
                _ => return true,
            }
        }
    }

    /// `nextFlowAfter` of the node containing `bl` (its parent, or the
    /// top-level graph when it has none): the first leaf to execute after
    /// `bl` falls through, if unique.
    pub(crate) fn next_flow_after(&self, bl: NodeId) -> Option<NodeId> {
        let mut bl = bl;
        let mut guard = self.nodes.len() + 1;
        loop {
            if guard == 0 {
                return None;
            }
            guard -= 1;
            let Some(container) = self.node(bl).parent else {
                // The top-level graph: the next node in the list, if any;
                // the graph itself has no parent.
                let pos = self.list.iter().position(|&n| n == bl)?;
                let next = *self.list.get(pos + 1)?;
                return self.front_leaf(next);
            };
            let c = self.node(container);
            let first = c.comps.first().copied();
            match c.kind {
                Kind::Goto => {
                    let KindData::Goto { target, .. } = c.data else {
                        return None;
                    };
                    return self.front_leaf(target);
                }
                Kind::MultiGoto | Kind::Condition | Kind::DoWhile | Kind::Copy | Kind::Plain => {
                    return None;
                }
                Kind::If | Kind::IfElse | Kind::IfNoExit | Kind::IfGoto => {
                    if first == Some(bl) {
                        return None;
                    }
                    bl = container;
                }
                Kind::WhileDo => {
                    if first == Some(bl) {
                        return None;
                    }
                    return first.and_then(|f| self.front_leaf(f));
                }
                Kind::InfLoop => return first.and_then(|f| self.front_leaf(f)),
                Kind::Switch => {
                    if first == Some(bl) || self.node(bl).kind != Kind::Goto {
                        return None;
                    }
                    let KindData::Switch(cases) = &c.data else {
                        return None;
                    };
                    let i = cases.iter().position(|cs| cs.block == bl)?;
                    if let Some(next) = cases.get(i + 1) {
                        return self.front_leaf(next.block);
                    }
                    bl = container;
                }
                Kind::List => {
                    let pos = c.comps.iter().position(|&n| n == bl)?;
                    match c.comps.get(pos + 1) {
                        Some(&next) => return self.front_leaf(next),
                        None => bl = container,
                    }
                }
            }
        }
    }

    /// `BlockGoto::gotoPrints` (block.cc:2943): whether the goto's target is
    /// not simply what flows next. A goto node always has a container here
    /// (at worst the top-level graph).
    pub(crate) fn goto_prints(&self, goto_node: NodeId) -> bool {
        let KindData::Goto { target, .. } = self.node(goto_node).data else {
            return false;
        };
        self.front_leaf(target) != self.next_flow_after(goto_node)
    }
}
