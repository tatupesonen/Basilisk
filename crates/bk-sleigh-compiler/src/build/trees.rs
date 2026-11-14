//! `buildDecisionTrees` (inventory 10 c.6): one tree per table with a
//! pattern, the root first, and the identical and indistinguishable
//! pattern errors.

use super::BuildState;
use crate::compiler::Compiler;
use crate::decision::{DecisionError, DecisionTree, Entry, Properties, build_tree};
use crate::ids::CtorId;

impl Compiler<'_> {
    /// Builds the decision trees, by table; `None` for tables without a
    /// pattern. Reports Ghidra's errors.
    pub(crate) fn build_decision_trees(&mut self, state: &BuildState) -> Vec<Option<DecisionTree>> {
        let mut props = Properties::default();
        let mut trees = Vec::with_capacity(self.tables.len());
        for (t, table) in self.tables.iter().enumerate() {
            if state.tables.get(t).is_none_or(|s| s.pattern.is_none()) {
                trees.push(None);
                continue;
            }
            let mut entries = Vec::new();
            for (index, &ctor) in table.ctors.iter().enumerate() {
                let Some(p) = state.ctor_patterns.get(ctor.slot()) else {
                    continue;
                };
                for d in p.pattern.disjuncts() {
                    entries.push(Entry {
                        pattern: d.simplified(),
                        index: index as u32,
                        ctor,
                    });
                }
            }
            match build_tree(entries, &mut props) {
                Ok(tree) => trees.push(Some(tree)),
                Err(DecisionError::ChildAsLargeAsParent) => {
                    self.diags
                        .error(None, "Child has as many Patterns as parent");
                    trees.push(None);
                }
            }
        }
        let report = |c: &mut Self, pairs: &[(CtorId, CtorId)], text: &str| {
            for &(a, b) in pairs {
                let at = |id: CtorId| c.ctors.get(id.slot()).map(|d| d.at);
                let (Some(la), Some(lb)) = (at(a), at(b)) else {
                    continue;
                };
                let (fa, fb) = (c.format_location(la), c.format_location(lb));
                c.diags.error_at(la, format!("{text}{fb}"));
                c.diags.error_at(lb, format!("{text}{fa}"));
            }
        };
        report(
            self,
            &props.identical,
            "Constructor has identical pattern to constructor at ",
        );
        if !self.options.lenient_conflicts {
            report(
                self,
                &props.conflicts,
                "Constructor pattern cannot be distinguished from constructor at ",
            );
        }
        trees
    }
}
