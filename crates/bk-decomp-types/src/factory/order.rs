//! The identity order of all types and the dependency order (Ghidra's walk
//! of `tree`, `orderRecurse`, `dependentOrder`).

use std::collections::HashSet;

use crate::compare::identity::compare_identity;
use crate::factory::TypeFactory;
use crate::ids::TypeId;

impl TypeFactory {
    /// Every live type in Ghidra's set order: `compareDependency`, then the
    /// 64-bit id (`DatatypeCompare`).
    pub fn sorted_ids(&self) -> Vec<TypeId> {
        let mut ids = self.ids();
        ids.sort_by(|&a, &b| compare_identity(self.entry(a), self.entry(b)));
        ids
    }

    /// Ghidra `dependentOrder`: every type after the types it depends on.
    pub fn dependent_order(&self) -> Vec<TypeId> {
        let mut out = Vec::new();
        let mut mark = HashSet::new();
        for id in self.sorted_ids() {
            self.order_recurse(id, &mut mark, &mut out);
        }
        out
    }

    /// Ghidra `orderRecurse`, with an explicit stack so that long chains of
    /// dependencies cannot overflow the call stack.
    fn order_recurse(&self, root: TypeId, mark: &mut HashSet<TypeId>, out: &mut Vec<TypeId>) {
        if !mark.insert(root) {
            return;
        }
        // (type, next dependency to visit); dependency 0 is the typedef.
        let mut stack: Vec<(TypeId, usize)> = vec![(root, 0)];
        while let Some(&mut (id, ref mut next)) = stack.last_mut() {
            let step = *next;
            *next += 1;
            let dep = if step == 0 {
                self.entry(id).typedef_imm
            } else if step <= self.num_depend(id) {
                self.depend(id, step - 1)
            } else {
                out.push(id);
                stack.pop();
                continue;
            };
            if let Some(dep) = dep
                && mark.insert(dep)
            {
                stack.push((dep, 0));
            }
        }
    }
}
