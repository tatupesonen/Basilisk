//! Operand collisions (`SleighCompile::checkLocalCollisions`,
//! `checkLocalExports`, `findCollision`; `Constructor::collectLocalExports`,
//! `collectLocalValues` of the symbols, inventory 10 c.5).

use std::collections::BTreeMap;

use bk_sla::ConstTpl;

use crate::compiler::Compiler;
use crate::ids::{CtorId, SymbolId, TableId};
use crate::symbols::SymbolKind;
use crate::template::{is_const_space, is_unique_space, real};

impl Compiler<'_> {
    /// `collectLocalValues` of a symbol. Tables already visited are not
    /// entered again, which only drops duplicates (and keeps a recursive
    /// table from looping, where Ghidra would not stop).
    fn local_values(&self, symbol: SymbolId, out: &mut Vec<u64>, visited: &mut Vec<TableId>) {
        match self.kind(symbol) {
            Some(SymbolKind::Varnode(vn)) if vn.space == crate::template::UNIQUE_SPACE => out.push(vn.offset),
            Some(SymbolKind::Subtable(table)) => {
                if visited.contains(table) {
                    return;
                }
                visited.push(*table);
                for ctor in self.table_ctors(*table) {
                    self.local_exports(ctor, out, visited);
                }
            }
            _ => {}
        }
    }

    /// `collectLocalExports` of a constructor.
    fn local_exports(&self, ctor: CtorId, out: &mut Vec<u64>, visited: &mut Vec<TableId>) {
        let Some(c) = self.ctors.get(ctor.slot()) else { return };
        let Some(hand) = c.main.as_ref().and_then(|t| t.result) else {
            return;
        };
        if is_const_space(&hand.space) {
            return;
        }
        if !matches!(hand.ptr_space, ConstTpl::Real(_)) {
            if is_unique_space(&hand.temp_space) {
                out.push(real(&hand.temp_offset));
            }
            return;
        }
        if is_unique_space(&hand.space) {
            out.push(real(&hand.ptr_offset));
            return;
        }
        if let ConstTpl::Handle { index, .. } = hand.space
            && let Some(op) = c.operands.get(index as usize)
            && let Some(sym) = self.operands.get(op.slot()).and_then(|o| o.def_symbol)
        {
            self.local_values(sym, out, visited);
        }
    }

    /// `checkLocalExports`: false if two operands may export the same
    /// temporary.
    fn check_local_exports(&mut self, ctor: CtorId) -> bool {
        let Some(c) = self.ctors.get(ctor.slot()) else { return true };
        let Some(main) = &c.main else { return true };
        if main.build_only() || c.operands.len() < 2 {
            return true;
        }
        let mut seen: BTreeMap<u64, usize> = BTreeMap::new();
        let operands = c.operands.clone();
        for (i, op) in operands.iter().enumerate() {
            let mut values = Vec::new();
            if let Some(sym) = self.operands.get(op.slot()).and_then(|o| o.def_symbol) {
                self.local_values(sym, &mut values, &mut Vec::new());
            }
            for value in values {
                let old = *seen.entry(value).or_insert(i);
                if old != i {
                    if self.options.warn_all_collisions {
                        let name = |op: Option<&crate::ids::OperandId>| {
                            op.and_then(|o| self.operands.get(o.slot()))
                                .and_then(|o| self.symbols.get(o.symbol))
                                .map_or("", |s| self.names.resolve(s.name))
                                .to_owned()
                        };
                        let message = format!(
                            "Possible operand collision between symbols '{}' and '{}'",
                            name(operands.get(old)),
                            name(Some(op))
                        );
                        let at = self.ctor_at(ctor);
                        self.diags.warning_at(at, message);
                    }
                    return false;
                }
            }
        }
        true
    }

    /// `checkLocalCollisions`: the root table, then the tables in order.
    pub(crate) fn check_local_collisions(&mut self) {
        let mut count = 0_usize;
        for t in 0..self.tables.len() {
            for ctor in self.table_ctors(TableId::new(t as u32)) {
                if !self.check_local_exports(ctor) {
                    count += 1;
                }
            }
        }
        if count > 0 {
            self.diags.warning(None, format!("{count} constructors with local collisions between operands"));
            if !self.options.warn_all_collisions {
                self.diags.warning(None, "Use -c switch to list each individually");
            }
        }
    }
}
