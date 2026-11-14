//! One constructor's pattern, operand offsets and operand order
//! (`Constructor::buildPattern`, inventory 10 c.3).

use super::reorder::{OperandFacts, order_operands, unravel};
use super::{BuildState, CtorResult, OperandLayout};
use crate::compiler::{Compiler, ContextChange};
use crate::equation::{
    EqError, EquationView, Offsets, generate, min_pattern, operand_order, resolve_offsets,
};
use crate::ids::CtorId;
use crate::pattern::{PExpr, TokenPattern};
use crate::symbols::SymbolKind;

impl Compiler<'_> {
    /// Builds a constructor's pattern. On success the constructor's result
    /// is stored in `state`; on failure the error's explanation is returned.
    pub(super) fn build_constructor_pattern(
        &self,
        ctor: CtorId,
        state: &mut BuildState,
        msg: &mut String,
        depth: u32,
    ) -> Result<(), EqError> {
        let Some(data) = self.ctors.get(ctor.slot()) else {
            return Ok(());
        };
        let view = EquationView {
            arena: &self.patterns,
            operands: &self.operands,
        };
        let n = data.operands.len();
        let mut ops: Vec<TokenPattern> = Vec::with_capacity(n);
        let mut facts = vec![OperandFacts::default(); n];
        let mut recursion = false;
        for (i, &op) in data.operands.iter().enumerate() {
            let Some(operand) = self.operands.get(op.slot()) else {
                ops.push(TokenPattern::constant(true));
                continue;
            };
            let pattern = if let Some(sym) = operand.def_symbol {
                match self.kind(sym) {
                    Some(SymbolKind::Subtable(t)) => {
                        let t = *t;
                        if state.tables.get(t.slot()).is_some_and(|s| s.being_built) {
                            if recursion {
                                return Err(EqError::new("Illegal recursion"));
                            }
                            recursion = true;
                            TokenPattern::constant(true)
                        } else {
                            self.build_table(t, state, msg, depth + 1)?
                        }
                    }
                    Some(kind) => match kind.pattern_value() {
                        Some(crate::pattern::PatValue::Token(_, tok)) => TokenPattern::token(tok),
                        _ => TokenPattern::constant(true),
                    },
                    None => TokenPattern::constant(true),
                }
            } else if let Some(expr) = operand.def_expr {
                min_pattern(&view, expr, &ops)
            } else {
                let name = self.symbol_text(operand.symbol);
                return Err(EqError::new(format!("{name}: operand is undefined")));
            };
            if let Some(f) = facts.get_mut(i) {
                *f = OperandFacts {
                    irrelevant: operand.offset_irrelevant,
                    variable: pattern.has_ellipsis(),
                    min_length: pattern.minimum_length(),
                };
            }
            ops.push(pattern);
        }
        let Some(equation) = data.equation else {
            return Err(EqError::new("Missing equation"));
        };
        let (mut pattern, shapes) = generate(&view, equation, &ops)?;
        // What the table's common pattern sees from here on, even if a
        // later step fails (Ghidra stores the pattern before checking it).
        if let Some(slot) = state.ctor_patterns.get_mut(ctor.slot()) {
            slot.clone_from(&pattern);
        }
        if pattern.pattern.always_false() {
            return Err(EqError::new("Impossible pattern"));
        }
        if recursion {
            pattern.right_ellipsis = true;
            if let Some(slot) = state.ctor_patterns.get_mut(ctor.slot()) {
                slot.right_ellipsis = true;
            }
        }
        let irrelevant: Vec<bool> = facts.iter().map(|f| f.irrelevant).collect();
        let mut resolved: Vec<Option<Offsets>> = vec![None; n];
        if !resolve_offsets(&view, equation, &shapes, &irrelevant, &mut resolved) {
            return Err(EqError::new("Unable to resolve operand offsets"));
        }
        // Ghidra leaves the offsets of operands the equation does not place
        // uninitialised; every operand that is not offset-irrelevant is
        // placed, so this default is never used by a valid specification.
        let mut offsets: Vec<Offsets> = resolved
            .into_iter()
            .map(|o| o.unwrap_or(Offsets { base: -1, offset: 0 }))
            .collect();
        unravel(&mut offsets, &facts);
        for change in &data.context {
            if let ContextChange::Op { expr, .. } = change {
                self.validate_context_expr(*expr, &data.operands, &offsets)?;
            }
        }
        let mut marked = vec![false; n];
        let mut pattern_order = Vec::with_capacity(n);
        operand_order(&view, equation, &mut marked, &mut pattern_order);
        let Some(order) = order_operands(&pattern_order, &offsets, &facts) else {
            return Err(EqError::new("Circular offset dependency between operands"));
        };
        let mut handmap = vec![0_u32; n];
        for (new, &old) in order.iter().enumerate() {
            if let Some(h) = handmap.get_mut(old) {
                *h = new as u32;
            }
        }
        let layout = (0..n)
            .map(|i| {
                let o = offsets.get(i).copied().unwrap_or_default();
                let base = usize::try_from(o.base)
                    .ok()
                    .and_then(|b| handmap.get(b))
                    .map_or(o.base, |&b| b as i32);
                OperandLayout {
                    base,
                    offset: o.offset,
                    min_length: facts.get(i).map_or(0, |f| f.min_length),
                }
            })
            .collect();
        let min_length = pattern.minimum_length();
        if let Some(slot) = state.ctors.get_mut(ctor.slot()) {
            *slot = Some(CtorResult {
                pattern,
                min_length,
                layout,
                handmap,
            });
        }
        Ok(())
    }

    /// `ContextOp::validate`: an operand in a context expression must have
    /// an offset relative to the constructor's start.
    fn validate_context_expr(
        &self,
        expr: crate::ids::PExprId,
        operands: &[crate::ids::OperandId],
        offsets: &[Offsets],
    ) -> Result<(), EqError> {
        let mut bad = None;
        self.patterns.for_each_value(expr, |leaf| {
            if bad.is_some() {
                return;
            }
            if let PExpr::Operand(op) = leaf
                && let Some(data) = self.operands.get(op.slot())
            {
                let index = data.index as usize;
                let relative = offsets.get(index).is_none_or(|o| o.base == -1);
                if !relative && operands.get(index) == Some(op) {
                    bad = Some(data.symbol);
                }
            }
        });
        match bad {
            Some(sym) => Err(EqError::new(format!(
                "{}: cannot be used in context expression",
                self.symbol_text(sym)
            ))),
            None => Ok(()),
        }
    }

    /// A symbol's name.
    pub(crate) fn symbol_text(&self, id: crate::ids::SymbolId) -> String {
        self.symbols
            .get(id)
            .map_or_else(String::new, |s| self.text(s.name).to_owned())
    }
}
