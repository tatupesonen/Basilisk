//! Limits against hostile input (ADR-009; `docs/features/decomp-cfg.md` 5.3).
//!
//! Ghidra has none. A step is one rule attempt, one trace step or one
//! analysis visit.

use crate::error::{CfgError, LimitKind};

/// Bounds on one analysis or structuring call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "the names docs/features/decomp-cfg.md 5.3 gives"
)]
pub struct Limits {
    /// The most nodes an input graph may have.
    pub max_nodes: u64,
    /// The most edges an input graph may have.
    pub max_edges: u64,
    /// The most work steps one call may take; `None` takes the default for
    /// the graph's size ([`Limits::default_steps`]).
    pub max_steps: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_nodes: 1_000_000,
            max_edges: 4_000_000,
            max_steps: None,
        }
    }
}

impl Limits {
    /// The default step limit for a graph of `nodes` nodes and `edges`
    /// edges: `64 * (nodes + edges)^2 / 1000 + 10^6`, saturating.
    pub fn default_steps(nodes: u64, edges: u64) -> u64 {
        let size = nodes.saturating_add(edges);
        size.saturating_mul(size).saturating_mul(64) / 1000 + 1_000_000
    }

    /// Checks a graph's size and returns the step budget for it.
    pub(crate) fn budget(&self, nodes: usize, edges: usize) -> Result<Budget, CfgError> {
        let nodes = nodes as u64;
        let edges = edges as u64;
        if nodes > self.max_nodes {
            return Err(CfgError::LimitExceeded {
                what: LimitKind::Nodes,
                limit: self.max_nodes,
            });
        }
        if edges > self.max_edges {
            return Err(CfgError::LimitExceeded {
                what: LimitKind::Edges,
                limit: self.max_edges,
            });
        }
        let limit = self
            .max_steps
            .unwrap_or_else(|| Self::default_steps(nodes, edges));
        Ok(Budget { used: 0, limit })
    }
}

/// A running count of work steps against a limit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    used: u64,
    limit: u64,
}

impl Budget {
    /// Takes one step.
    #[inline]
    pub(crate) fn step(&mut self) -> Result<(), CfgError> {
        self.used += 1;
        if self.used > self.limit {
            return Err(CfgError::LimitExceeded {
                what: LimitKind::Steps,
                limit: self.limit,
            });
        }
        Ok(())
    }

    /// The steps taken so far.
    pub(crate) const fn used(&self) -> u64 {
        self.used
    }
}
