//! Per-block facts: what Ghidra's structurer learns from a basic block
//! through virtual calls, given as input (ADR-028, ADR-042;
//! `docs/features/decomp-cfg.md` 4.1).

/// The four facts of one input node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fact {
    /// `BlockBasic::isComplex` (block.cc:2417); a bare graph's blocks are
    /// complex (`FlowBlock::isComplex`, block.hh:259).
    pub complex: bool,
    /// `f_switch_out`, set by the flow pass on a block ending in
    /// `BRANCHIND`; OR-ed into the node's flags when the structurer copies
    /// it.
    pub switch_out: bool,
    /// The block's last op is a `RETURN` (read only by `orderBlocks`).
    pub ends_in_return: bool,
    /// Negating the block changes data-flow (`BlockBasic::negateCondition`
    /// returns `true`, block.cc:2369; `FlowBlock`'s returns `false`).
    pub negation_changes_dataflow: bool,
}

impl Fact {
    /// The facts of a node of a bare graph (`structure blocks`): complex and
    /// nothing else.
    pub const NEUTRAL: Self = Self {
        complex: true,
        switch_out: false,
        ends_in_return: false,
        negation_changes_dataflow: false,
    };
}

/// The facts of every input node, indexed by node id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockFacts {
    facts: Vec<Fact>,
}

impl BlockFacts {
    /// Neutral facts ([`Fact::NEUTRAL`]) for `n` nodes.
    pub fn neutral(n: usize) -> Self {
        Self {
            facts: vec![Fact::NEUTRAL; n],
        }
    }

    /// Facts from a vector indexed by node id.
    pub fn from_vec(facts: Vec<Fact>) -> Self {
        Self { facts }
    }

    /// The number of nodes covered.
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether no node is covered.
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// The facts of node `id`; a node beyond the table has neutral facts.
    pub fn get(&self, id: usize) -> Fact {
        self.facts.get(id).copied().unwrap_or(Fact::NEUTRAL)
    }

    /// Replaces the facts of node `id`, growing the table with neutral
    /// facts as needed.
    pub fn set(&mut self, id: usize, fact: Fact) {
        if self.facts.len() <= id {
            self.facts.resize(id + 1, Fact::NEUTRAL);
        }
        if let Some(f) = self.facts.get_mut(id) {
            *f = fact;
        }
    }

    /// All facts, by node id.
    pub fn as_slice(&self) -> &[Fact] {
        &self.facts
    }
}
