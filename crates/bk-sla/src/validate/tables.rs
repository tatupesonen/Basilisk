//! Validation of subtables: constructors, templates, decision trees, and the
//! operand-expression dependency check (rules 2–4 of `features/sla.md` 4.3).

use std::fmt::{self, Display};

use bk_pcode::OpCode;

use super::{Validator, fail};
use crate::error::SlaError;
use crate::model::constructor::{Constructor, ContextChange, DisjointPattern, PrintPiece};
use crate::model::expr::Expr;
use crate::model::handles::{BlockId, ExprId, SymbolId};
use crate::model::symbol::{Subtable, SymbolKind};
use crate::model::template::{ConstTpl, HandleSelect, TemplateRef, VarnodeTpl};

/// The path of a constructor, rendered only for an error.
pub(crate) struct CtorPath<'s, 'c> {
    sla: &'s crate::Sla,
    table: SymbolId,
    ct: u32,
    ctor: &'c Constructor,
}

impl Display for CtorPath<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = self.sla.source_file(self.ctor.source).unwrap_or("?");
        write!(
            f,
            "table \"{}\" constructor {} ({file}:{})",
            self.sla.symbol_name(self.table),
            self.ct,
            self.ctor.line
        )
    }
}

impl<'s> Validator<'s> {
    pub(super) fn tables(&mut self) -> Result<(), SlaError> {
        let sla = self.sla;
        for (index, symbol) in sla.a.symbols.iter().enumerate() {
            let SymbolKind::Subtable(table) = symbol.kind else {
                continue;
            };
            let id = SymbolId::new(index as u32);
            let path = self.symbol_path(id);
            if table.constructors.range().end > sla.a.constructors.len() {
                return fail(path, "dangling constructor range");
            }
            for ct in 0..table.num_constructors() {
                let Some(ctor) = table.constructor(ct).and_then(|c| sla.constructor(c)) else {
                    return fail(path, "dangling constructor");
                };
                let ctor_path = self.constructor_path(id, ct, ctor);
                self.constructor(&ctor_path, id, ct, ctor)?;
            }
            self.decision_tree(&path, &table)?;
        }
        for (index, symbol) in sla.a.symbols.iter().enumerate() {
            if matches!(symbol.kind, SymbolKind::Operand(_))
                && self.owners.get(index).copied() != Some(1)
            {
                return fail(
                    self.symbol_path(SymbolId::new(index as u32)),
                    "an operand symbol is not owned by exactly one constructor",
                );
            }
        }
        Ok(())
    }

    pub(crate) fn constructor_path<'c>(
        &self,
        table: SymbolId,
        ct: u32,
        ctor: &'c Constructor,
    ) -> CtorPath<'s, 'c> {
        CtorPath {
            sla: self.sla,
            table,
            ct,
            ctor,
        }
    }

    fn constructor(
        &mut self,
        path: &dyn Display,
        table: SymbolId,
        ct: u32,
        ctor: &Constructor,
    ) -> Result<(), SlaError> {
        let sla = self.sla;
        if ctor.parent != table {
            return fail(
                path,
                format!("parent {} is not the enclosing subtable", ctor.parent),
            );
        }
        let operands = sla.operands(ctor);
        if operands.len() != ctor.operands.len() as usize {
            return fail(path, "dangling operand list");
        }
        if operands.len() > self.limits.operands as usize {
            return Err(SlaError::Limit {
                location: crate::error::Location {
                    path: path.to_string(),
                    offset: None,
                },
                what: "operands of one constructor",
                limit: u64::from(self.limits.operands),
                found: operands.len() as u64,
            });
        }
        let num_operands = operands.len() as u32;
        for (position, &operand_id) in operands.iter().enumerate() {
            let Some(SymbolKind::Operand(operand)) = sla.symbol(operand_id).map(|s| s.kind) else {
                return fail(path, format!("oper {operand_id} is not an operand symbol"));
            };
            if let Some(count) = self.owners.get_mut(operand_id.slot()) {
                *count = count.saturating_add(1);
            }
            if operand.index != position as i32 {
                return fail(
                    path,
                    format!(
                        "operand {operand_id} has index {} at position {position}",
                        operand.index
                    ),
                );
            }
            let names_itself = matches!(
                sla.expr(operand.local_expr),
                Some(&Expr::Operand { index, table: t, ct: c })
                    if index == operand.index && t == table && c == ct
            );
            if !names_itself {
                return fail(
                    path,
                    format!("operand {operand_id}'s first expression does not name it"),
                );
            }
        }
        let pieces = sla.print_pieces(ctor);
        if pieces.len() != ctor.print.len() as usize {
            return fail(path, "dangling print pieces");
        }
        for piece in pieces {
            if let PrintPiece::Operand(index) = *piece
                && (index < 0 || index as u32 >= num_operands)
            {
                return fail(path, format!("opprint {index} is out of range"));
            }
        }
        if ctor.first < -1 || ctor.first > pieces.len() as i32 {
            return fail(path, format!("first {} is out of range", ctor.first));
        }
        self.byte_quantity(path, "length", ctor.length)?;
        for change in sla.context_changes(ctor) {
            match *change {
                ContextChange::Op {
                    word, shift, expr, ..
                } => {
                    self.context_word(path, word)?;
                    if !(0..=31).contains(&shift) {
                        return fail(path, format!("context_op shift {shift} is out of range"));
                    }
                    self.expr_ok(path, expr)?;
                }
                ContextChange::Commit { symbol, word, .. } => {
                    self.context_word(path, word)?;
                    if !sla
                        .symbol(symbol)
                        .is_some_and(|s| s.kind.has_fixed_handle())
                    {
                        return fail(path, format!("commit symbol {symbol} has no fixed handle"));
                    }
                }
            }
        }
        if ctor.templates.range().end > sla.a.templates.len() {
            return fail(path, "dangling templates");
        }
        let mut previous: Option<Option<u32>> = None;
        for id in sla.template_ids(ctor) {
            let Some(template) = sla.template(id) else {
                return fail(path, "dangling template");
            };
            let section = template.header().section;
            let in_order = previous.is_none_or(|before| match (before, section) {
                (None, Some(_)) => true,
                (Some(a), Some(b)) => a < b,
                _ => false,
            });
            if !in_order {
                return fail(path, "duplicate or unordered templates");
            }
            if let Some(number) = section
                && number >= sla.header.num_sections
            {
                return fail(path, format!("section {number} is not below numsections"));
            }
            previous = Some(section);
            self.template(path, &template, num_operands)?;
        }
        Ok(())
    }

    fn context_word(&self, path: &dyn Display, word: i32) -> Result<(), SlaError> {
        if word < 0 || word as u32 >= self.context_words {
            return fail(
                path,
                format!(
                    "context word {word} is outside the {} words the context fields address",
                    self.context_words
                ),
            );
        }
        Ok(())
    }

    /// Checks one template against the constructor's operand count.
    pub(crate) fn template(
        &self,
        path: &dyn Display,
        template: &TemplateRef<'_>,
        num_operands: u32,
    ) -> Result<(), SlaError> {
        check_template(
            self.limits,
            &|index| self.space_known(index),
            path,
            template,
            num_operands,
        )
    }

    fn decision_tree(&self, path: &dyn Display, table: &Subtable) -> Result<(), SlaError> {
        let sla = self.sla;
        let mut stack = vec![(table.decision, 1u32)];
        let mut visited = 0usize;
        while let Some((id, depth)) = stack.pop() {
            visited += 1;
            if visited > sla.a.decisions.len() {
                return fail(path, "the decision tree shares nodes");
            }
            if depth > self.limits.decision_depth {
                return Err(SlaError::Limit {
                    location: crate::error::Location {
                        path: path.to_string(),
                        offset: None,
                    },
                    what: "decision-tree depth",
                    limit: u64::from(self.limits.decision_depth),
                    found: u64::from(depth),
                });
            }
            let Some(node) = sla.decision(id) else {
                return fail(path, format!("dangling decision node {id}"));
            };
            if node.size > 8 {
                return fail(
                    path,
                    format!("decision node size {} is not in 0..=8", node.size),
                );
            }
            if node.is_leaf() {
                let pairs = sla.pairs(node);
                if pairs.len() != node.pairs.len() as usize {
                    return fail(path, "dangling pairs");
                }
                for pair in pairs {
                    if pair.constructor >= table.num_constructors() {
                        return fail(
                            path,
                            format!("pair id {} is not below numct", pair.constructor),
                        );
                    }
                    match pair.pattern {
                        DisjointPattern::Instruction(block) | DisjointPattern::Context(block) => {
                            self.block(path, block)?;
                        }
                        DisjointPattern::Combine {
                            context,
                            instruction,
                        } => {
                            self.block(path, context)?;
                            self.block(path, instruction)?;
                        }
                    }
                }
            } else {
                if !node.pairs.is_empty() {
                    return fail(path, "a decision node with children has pairs");
                }
                if node.first_child as usize + node.num_children() as usize > sla.a.decisions.len()
                {
                    return fail(path, "dangling decision children");
                }
                stack.extend(sla.children(node).map(|child| (child, depth + 1)));
            }
        }
        Ok(())
    }

    fn block(&self, path: &dyn Display, id: BlockId) -> Result<(), SlaError> {
        let Some(block) = self.sla.block(id) else {
            return fail(path, format!("dangling pattern block {id}"));
        };
        if self.sla.block_words(block).len() != block.words.len() as usize {
            return fail(path, "dangling mask words");
        }
        if block.nonzero < -1 {
            return fail(path, format!("pattern block nonzero {}", block.nonzero));
        }
        self.byte_quantity(path, "pattern offset", block.offset)
    }

    /// Rule 4: no operand's defining expression depends on itself through
    /// `operand_exp` references.
    pub(super) fn operand_cycles(&self) -> Result<(), SlaError> {
        let sla = self.sla;
        let count = sla.a.symbols.len();
        // 0 = unvisited, 1 = on the stack, 2 = done.
        let mut state = vec![0u8; count];
        let mut refs: Vec<SymbolId> = Vec::new();
        for start in 0..count {
            if state.get(start) != Some(&0)
                || self.defining_expr(SymbolId::new(start as u32)).is_none()
            {
                continue;
            }
            // Iterative depth-first search: (symbol, its references, next).
            let mut stack: Vec<(SymbolId, Vec<SymbolId>, usize)> = Vec::new();
            let first = SymbolId::new(start as u32);
            self.references(first, &mut refs);
            stack.push((first, refs.clone(), 0));
            if let Some(s) = state.get_mut(start) {
                *s = 1;
            }
            while let Some((symbol, targets, next)) = stack.last_mut() {
                if let Some(&target) = targets.get(*next) {
                    *next += 1;
                    match state.get(target.slot()) {
                        Some(1) => {
                            return fail(
                                self.symbol_path(target),
                                "the operand's defining expression depends on itself",
                            );
                        }
                        Some(0) => {
                            self.references(target, &mut refs);
                            if let Some(s) = state.get_mut(target.slot()) {
                                *s = 1;
                            }
                            stack.push((target, refs.clone(), 0));
                        }
                        _ => {}
                    }
                } else {
                    if let Some(s) = state.get_mut(symbol.slot()) {
                        *s = 2;
                    }
                    stack.pop();
                }
            }
        }
        Ok(())
    }

    fn defining_expr(&self, id: SymbolId) -> Option<ExprId> {
        match self.sla.symbol(id)?.kind {
            SymbolKind::Operand(operand) => operand.defining_expr,
            _ => None,
        }
    }

    /// The operand symbols an operand's defining expression refers to.
    fn references(&self, id: SymbolId, out: &mut Vec<SymbolId>) {
        out.clear();
        let Some(root) = self.defining_expr(id) else {
            return;
        };
        let mut work = vec![root];
        while let Some(expr) = work.pop() {
            match self.sla.expr(expr) {
                Some(&Expr::Binary { left, right, .. }) => work.extend([left, right]),
                Some(&Expr::Unary { operand, .. }) => work.push(operand),
                Some(&Expr::Operand { index, table, ct }) => {
                    let target = self
                        .sla
                        .subtable(table)
                        .and_then(|t| t.constructor(ct))
                        .and_then(|c| self.sla.constructor(c))
                        .and_then(|c| self.sla.operands(c).get(index as usize).copied());
                    if let Some(target) = target {
                        out.push(target);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Checks one template: ranges, labels, spaces, handle indices below
/// `num_operands`, directive shapes.
pub(crate) fn check_template(
    limits: &crate::Limits,
    space_known: &dyn Fn(u32) -> bool,
    path: &dyn Display,
    template: &TemplateRef<'_>,
    num_operands: u32,
) -> Result<(), SlaError> {
    let header = template.header();
    super::byte_quantity(limits, path, "delay", header.delay)?;
    if header.labels < 0 {
        return fail(path, "negative label count");
    }
    if template.ops().len() != header.ops.len() as usize {
        return fail(path, "dangling ops");
    }
    let labels = header.labels as u64;
    let check = |c: &ConstTpl| -> Result<(), SlaError> {
        match *c {
            ConstTpl::Handle {
                index,
                select,
                plus,
            } => {
                if index >= num_operands {
                    return fail(path, format!("const_handle {index} is out of range"));
                }
                if select != HandleSelect::OffsetPlus && plus != 0 {
                    return fail(path, "const_handle plus without selector 3");
                }
            }
            ConstTpl::Space(space) if !space_known(space) => {
                return fail(path, format!("unknown space index {space}"));
            }
            ConstTpl::Relative(label) if label >= labels => {
                return fail(path, format!("label {label} is not below {labels}"));
            }
            _ => {}
        }
        Ok(())
    };
    let check_varnode = |v: &VarnodeTpl| -> Result<(), SlaError> {
        check(&v.space)?;
        check(&v.offset)?;
        check(&v.size)
    };
    if let Some(result) = template.result() {
        for part in &result.parts() {
            check(part)?;
        }
    }
    for (number, op) in template.ops().iter().enumerate() {
        let inputs = template.inputs(op);
        if inputs.len() != op.num_inputs() as usize {
            return fail(path, "dangling op varnodes");
        }
        if inputs.len() > limits.op_inputs as usize {
            return Err(SlaError::Limit {
                location: crate::error::Location {
                    path: format!("{path} op {number}"),
                    offset: None,
                },
                what: "inputs of one op template",
                limit: u64::from(limits.op_inputs),
                found: inputs.len() as u64,
            });
        }
        if let Some(output) = template.output(op) {
            check_varnode(output)?;
        }
        for input in inputs {
            check_varnode(input)?;
        }
        let constant = |slot: usize| match inputs.get(slot).map(|v| v.offset) {
            Some(ConstTpl::Real(value)) => Some(value),
            _ => None,
        };
        let directive_ok = match op.opcode {
            OpCode::MultiEqual => {
                inputs.len() == 1 && constant(0).is_some_and(|v| v < u64::from(num_operands))
            }
            OpCode::Indirect => inputs.len() == 1 && constant(0).is_some(),
            OpCode::PtrAdd => inputs.len() == 1 && constant(0).is_some_and(|v| v < labels),
            OpCode::PtrSub => inputs.len() == 2 && constant(1).is_some(),
            _ => true,
        };
        if !directive_ok {
            return fail(
                format!("{path} op {number}"),
                format!("directive {} has malformed inputs", op.opcode.name()),
            );
        }
    }
    Ok(())
}
