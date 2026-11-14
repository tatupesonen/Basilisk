//! Pattern sections and context blocks (`pequation`, `constraint`,
//! `contextlist` of `slghparse.y` 309-346; `SleighCompile::constrainOperand`,
//! `defineOperand`, `defineInvisibleOperand`, `selfDefine`, `contextMod`,
//! `contextSet`; `calc_maskword`).

use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{
    ConstraintOp as AstOp, ContextBlock, ContextStmt, Equation as AstEq, EquationId as AstEqId,
    EquationOp, PatExpr,
};

use super::{Compiler, ContextChange};
use crate::ids::{EquationId, OperandId, PExprId, SymbolId};
use crate::pattern::{ConstraintOp, Equation, PExpr};
use crate::symbols::SymbolKind;

/// The pattern or context block cannot be used; the constructor is
/// abandoned (Ghidra's parser recovers at the next `}`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Abandon;

impl From<super::pexpr::BadExpr> for Abandon {
    fn from(_: super::pexpr::BadExpr) -> Self {
        Self
    }
}

/// What `calc_maskword` computes for a context field: the word, the shift
/// and the mask; `None` if the field straddles two words.
pub(crate) fn mask_word(start: i32, end: i32) -> Option<(i32, i32, u32)> {
    let word = start.div_euclid(32);
    if word != end.div_euclid(32) {
        return None;
    }
    let s = start - word * 32;
    let e = end - word * 32;
    let shift = 32 - e - 1;
    let total = s.checked_add(shift)?;
    let mask = u32::MAX.checked_shr(total as u32).unwrap_or(0);
    let mask = mask.checked_shl(shift as u32).unwrap_or(0);
    Some((word, shift, mask))
}

impl Compiler<'_> {
    /// Builds the equation of a pattern section, creating operands and
    /// definitions as Ghidra's grammar actions do, left to right.
    pub(crate) fn equation(&mut self, id: AstEqId) -> Result<EquationId, Abandon> {
        let nodes = &self.parsed.spec.nodes;
        match &nodes[id] {
            AstEq::Binary { op, lhs, rhs, .. } => {
                let (op, lhs, rhs) = (*op, *lhs, *rhs);
                let l = self.equation(lhs)?;
                let r = self.equation(rhs)?;
                Ok(self.patterns.equation(match op {
                    EquationOp::And => Equation::And(l, r),
                    EquationOp::Or => Equation::Or(l, r),
                    EquationOp::Seq => Equation::Cat(l, r),
                }))
            }
            AstEq::EllipsisLeft { inner, .. } => {
                let e = self.equation(*inner)?;
                Ok(self.patterns.equation(Equation::LeftEllipsis(e)))
            }
            AstEq::EllipsisRight { inner, .. } => {
                let e = self.equation(*inner)?;
                Ok(self.patterns.equation(Equation::RightEllipsis(e)))
            }
            AstEq::Paren { inner, .. } => self.equation(*inner),
            AstEq::Constraint {
                name, op, value, ..
            } => {
                let (name, op, value) = (*name, *op, *value);
                let Some(sym) = self.lookup(name.name) else {
                    self.syntax_error(name.span);
                    return Err(Abandon);
                };
                let kind = self.kind(sym).cloned();
                match kind {
                    Some(SymbolKind::Operand(operand)) => {
                        if op != AstOp::Equal {
                            self.syntax_error(name.span);
                            return Err(Abandon);
                        }
                        let expr = self.pattern_expr(value, false)?;
                        self.constrain_operand(operand, expr, name)
                    }
                    Some(k) if k.is_family() => {
                        let expr = self.pattern_expr(value, false)?;
                        let field =
                            self.pexpr(k.pattern_value().map_or(PExpr::Constant(0), PExpr::Field));
                        let op = match op {
                            AstOp::Equal => ConstraintOp::Equal,
                            AstOp::NotEqual => ConstraintOp::NotEqual,
                            AstOp::Less => ConstraintOp::Less,
                            AstOp::LessEqual => ConstraintOp::LessEqual,
                            AstOp::Great => ConstraintOp::Greater,
                            AstOp::GreatEqual => ConstraintOp::GreaterEqual,
                        };
                        Ok(self.patterns.equation(Equation::Constraint {
                            op,
                            value: field,
                            expr,
                        }))
                    }
                    _ => {
                        self.syntax_error(name.span);
                        Err(Abandon)
                    }
                }
            }
            AstEq::Symbol(ident) => {
                let ident = *ident;
                let Some(sym) = self.lookup(ident.name) else {
                    self.syntax_error(ident.span);
                    return Err(Abandon);
                };
                let kind = self.kind(sym).cloned();
                match kind {
                    Some(SymbolKind::Operand(operand)) => {
                        let eq = self.patterns.equation(Equation::Operand(operand));
                        self.self_define(operand, ident.span);
                        Ok(eq)
                    }
                    Some(SymbolKind::Epsilon) => {
                        let zero = self.pexpr(PExpr::Constant(0));
                        Ok(self.patterns.equation(Equation::Unconstrained(zero)))
                    }
                    Some(k) if k.is_family() || matches!(k, SymbolKind::Subtable(_)) => {
                        Ok(self.invisible_operand(sym, ident.span))
                    }
                    _ => {
                        self.syntax_error(ident.span);
                        Err(Abandon)
                    }
                }
            }
            AstEq::Error(_) => Err(Abandon),
        }
    }

    /// `constrainOperand`.
    fn constrain_operand(
        &mut self,
        operand: OperandId,
        expr: PExprId,
        name: bk_sleigh_syntax::ast::Ident,
    ) -> Result<EquationId, Abandon> {
        let family = self
            .operands
            .get(operand.slot())
            .and_then(|o| o.def_symbol)
            .and_then(|s| self.kind(s))
            .and_then(SymbolKind::pattern_value);
        if let Some(value) = family {
            let field = self.pexpr(PExpr::Field(value));
            return Ok(self.patterns.equation(Equation::Constraint {
                op: ConstraintOp::Equal,
                value: field,
                expr,
            }));
        }
        let message = format!(
            "Constraining currently undefined operand {}",
            self.text(name.name)
        );
        self.diags.error(Some(name.span), message);
        Err(Abandon)
    }

    /// `OperandSymbol::defineOperand` with an expression or a symbol.
    fn define_operand(
        &mut self,
        operand: OperandId,
        expr: Option<PExprId>,
        symbol: Option<SymbolId>,
        at: Span,
    ) -> bool {
        let Some(data) = self.operands.get_mut(operand.slot()) else {
            return false;
        };
        if data.is_defined() {
            self.diags.error_at(at, "Redefining operand");
            return false;
        }
        data.def_expr = expr;
        data.def_symbol = symbol;
        true
    }

    /// Defines an operand by a global symbol: value and context symbols by
    /// their field, others as the defining symbol.
    fn define_by(&mut self, operand: OperandId, sym: SymbolId, at: Span) {
        match self.kind(sym).cloned() {
            Some(SymbolKind::Value(v) | SymbolKind::Context { field: v, .. }) => {
                let expr = self.pexpr(PExpr::Field(v));
                self.define_operand(operand, Some(expr), None, at);
            }
            _ => {
                self.define_operand(operand, None, Some(sym), at);
            }
        }
    }

    /// `selfDefine`: an operand named like a global symbol takes its
    /// meaning from it.
    fn self_define(&mut self, operand: OperandId, at: Span) {
        let Some(name) = self
            .operands
            .get(operand.slot())
            .and_then(|o| self.symbols.get(o.symbol))
            .map(|s| s.name)
        else {
            return;
        };
        let glob = self.symbols.lookup_skipping(name, 1).filter(|&g| {
            matches!(
                self.kind(g),
                Some(
                    SymbolKind::Value(_)
                        | SymbolKind::ValueMap(..)
                        | SymbolKind::Name(..)
                        | SymbolKind::VarnodeList(..)
                        | SymbolKind::Context { .. }
                        | SymbolKind::Varnode(_)
                        | SymbolKind::Operand(_)
                        | SymbolKind::Start
                        | SymbolKind::End
                        | SymbolKind::Next2
                        | SymbolKind::Epsilon
                        | SymbolKind::Subtable(_)
                )
            )
        });
        if let Some(g) = glob {
            self.define_by(operand, g, at);
        } else {
            let message = format!("No matching global symbol '{}'", self.text(name));
            self.diags.error_at(at, message);
        }
    }

    /// `defineInvisibleOperand`.
    fn invisible_operand(&mut self, sym: SymbolId, at: Span) -> EquationId {
        let name = self.symbols.get(sym).map(|s| s.name);
        let ctor = self.cur_ctor;
        let index = ctor
            .and_then(|c| self.ctors.get(c.slot()))
            .map_or(0, |c| c.operands.len() as u32);
        let Some(name) = name else {
            let zero = self.pexpr(PExpr::Constant(0));
            return self.patterns.equation(Equation::Unconstrained(zero));
        };
        let operand = self.new_operand(name, index, ctor, at);
        if let Some(c) = ctor.and_then(|c| self.ctors.get_mut(c.slot())) {
            c.operands.push(operand);
        }
        let eq = self.patterns.equation(Equation::Operand(operand));
        self.define_by(operand, sym, at);
        eq
    }

    /// A context block (`contextlist`). `Err` abandons the constructor.
    pub(crate) fn context_block(
        &mut self,
        block: &ContextBlock,
    ) -> Result<Vec<ContextChange>, Abandon> {
        let mut changes = Vec::new();
        for stmt in &block.stmts {
            match stmt {
                ContextStmt::Assign {
                    target,
                    value,
                    span,
                    ..
                } => {
                    let Some(sym) = self.lookup(target.name) else {
                        let message =
                            format!("Expecting context symbol, not {}", self.text(target.name));
                        self.diags.error(Some(target.span), message);
                        return Err(Abandon);
                    };
                    match self.kind(sym).cloned() {
                        Some(SymbolKind::Context { field, .. }) => {
                            let expr = self.pattern_expr(*value, true)?;
                            let mut uses_next = false;
                            self.patterns.for_each_value(expr, |v| {
                                uses_next |= matches!(v, PExpr::End | PExpr::Next2);
                            });
                            if uses_next {
                                let message = format!(
                                    "Cannot use 'inst_next' or 'inst_next2' to set context variable: {}",
                                    self.text(target.name)
                                );
                                self.diags.error(Some(*span), message);
                                return Err(Abandon);
                            }
                            let f = field.field();
                            let Some((word, shift, mask)) = mask_word(f.start_bit, f.end_bit)
                            else {
                                self.diags.error(
                                    Some(*span),
                                    "Context field not contained within one machine int",
                                );
                                self.fatal = true;
                                return Err(Abandon);
                            };
                            changes.push(ContextChange::Op {
                                word,
                                shift,
                                mask,
                                expr,
                            });
                        }
                        Some(SymbolKind::Operand(operand)) => {
                            let expr = self.pattern_expr(*value, true)?;
                            if self.define_operand(operand, Some(expr), None, *span)
                                && let Some(data) = self.operands.get_mut(operand.slot())
                            {
                                data.offset_irrelevant = true;
                            }
                        }
                        _ => {
                            self.syntax_error(target.span);
                            return Err(Abandon);
                        }
                    }
                }
                ContextStmt::Apply { name, args, span } => {
                    let commit = self.global_set(*name, *args, *span)?;
                    changes.push(commit);
                }
            }
        }
        Ok(changes)
    }

    /// `globalset(symbol, contextfield);` (`contextSet`).
    fn global_set(
        &mut self,
        name: bk_sleigh_syntax::ast::Ident,
        args: bk_sleigh_syntax::ast::PatExprList,
        span: Span,
    ) -> Result<ContextChange, Abandon> {
        let nodes = &self.parsed.spec.nodes;
        let list = nodes.pat_exprs(args);
        let (Some(a), Some(b), 2) = (list.first(), list.get(1), list.len()) else {
            self.syntax_error(span);
            return Err(Abandon);
        };
        let (PatExpr::Ident(addr), PatExpr::Ident(var)) = (&nodes[*a], &nodes[*b]) else {
            self.syntax_error(span);
            return Err(Abandon);
        };
        let (addr, var) = (*addr, *var);
        if self.text(name.name) != "globalset" {
            self.syntax_error(name.span);
            return Err(Abandon);
        }
        let symbol = match self.lookup(addr.name) {
            Some(s)
                if self
                    .kind(s)
                    .is_some_and(|k| k.is_family() || k.is_specific()) =>
            {
                s
            }
            _ => {
                self.syntax_error(addr.span);
                return Err(Abandon);
            }
        };
        let Some(&SymbolKind::Context { field, flow, .. }) = self.lookup_kind(var.name) else {
            self.syntax_error(var.span);
            return Err(Abandon);
        };
        let f = field.field();
        let Some((word, _, mask)) = mask_word(f.start_bit, f.end_bit) else {
            self.diags.error(
                Some(span),
                "Context field not contained within one machine int",
            );
            self.fatal = true;
            return Err(Abandon);
        };
        Ok(ContextChange::Commit {
            symbol,
            word,
            mask,
            flow,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::mask_word;

    #[test]
    fn mask_words_follow_calc_maskword() {
        assert_eq!(mask_word(0, 0), Some((0, 31, 0x8000_0000)));
        assert_eq!(mask_word(0, 31), Some((0, 0, 0xffff_ffff)));
        assert_eq!(mask_word(4, 7), Some((0, 24, 0x0f00_0000)));
        assert_eq!(mask_word(33, 34), Some((1, 29, 0x6000_0000)));
        assert_eq!(mask_word(30, 33), None);
    }
}
