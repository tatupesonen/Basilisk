//! Decision trees (`DecisionNode`, `DecisionProperties`,
//! `SubtableSymbol::buildDecisionTree`, inventory 10 c.6–c.9).

mod log;
mod log_data;
#[cfg(test)]
mod log_table_test;
mod node;
mod order;
#[cfg(test)]
mod proptests;
mod score;

pub(crate) use node::{Entry, build_tree};

use crate::ids::CtorId;
use crate::pattern::Disjoint;

/// One node of a decision tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionNode {
    /// How many patterns were placed at the node (`num`).
    pub number: i32,
    /// Whether the field tested is in the context.
    pub context: bool,
    /// First bit of the field.
    pub start_bit: i32,
    /// Bits in the field; 0 for a leaf.
    pub size: u8,
    /// A leaf's patterns in the order tried: constructor index in the
    /// table, pattern.
    pub pairs: Vec<(u32, Disjoint)>,
    /// An inner node's children (indices into [`DecisionTree::nodes`]).
    pub children: Vec<usize>,
}

/// A table's decision tree; node 0 is the root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionTree {
    /// The nodes.
    pub nodes: Vec<DecisionNode>,
}

/// An error building a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecisionError {
    /// Ghidra's "Child has as many Patterns as parent".
    ChildAsLargeAsParent,
}

/// `DecisionProperties`: identical and conflicting pattern pairs over all
/// tables; each constructor is reported at most once.
#[derive(Clone, Debug, Default)]
pub(crate) struct Properties {
    in_error: rustc_hash::FxHashSet<CtorId>,
    pub(crate) identical: Vec<(CtorId, CtorId)>,
    pub(crate) conflicts: Vec<(CtorId, CtorId)>,
}

impl Properties {
    fn note(&mut self, a: CtorId, b: CtorId) -> bool {
        if self.in_error.contains(&a) || self.in_error.contains(&b) {
            return false;
        }
        self.in_error.insert(a);
        self.in_error.insert(b);
        true
    }

    /// `identicalPattern`.
    pub(crate) fn identical(&mut self, a: CtorId, b: CtorId) {
        if self.note(a, b) {
            self.identical.push((a, b));
        }
    }

    /// `conflictingPattern`.
    pub(crate) fn conflicting(&mut self, a: CtorId, b: CtorId) {
        if self.note(a, b) {
            self.conflicts.push((a, b));
        }
    }
}
