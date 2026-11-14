//! Writing symbol bodies, constructors, decision trees and expressions.

use bk_marshal::{EncodeError, Encoder};

use super::space_ref;
use super::template::encode_template;
use crate::ids::{
    ATTRIB_BASE, ATTRIB_BIGENDIAN, ATTRIB_CODE, ATTRIB_CONTEXT, ATTRIB_CT, ATTRIB_ENDBIT,
    ATTRIB_ENDBYTE, ATTRIB_FIRST, ATTRIB_FLOW, ATTRIB_HIGH, ATTRIB_I, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_LENGTH, ATTRIB_LINE, ATTRIB_LOW, ATTRIB_MASK, ATTRIB_MINLEN, ATTRIB_NAME,
    ATTRIB_NONZERO, ATTRIB_NUMBER, ATTRIB_NUMCT, ATTRIB_OFF, ATTRIB_PARENT, ATTRIB_PIECE,
    ATTRIB_SHIFT, ATTRIB_SIGNBIT, ATTRIB_SIZE, ATTRIB_SOURCE, ATTRIB_SPACE, ATTRIB_STARTBIT,
    ATTRIB_STARTBYTE, ATTRIB_SUBSYM, ATTRIB_TABLE, ATTRIB_VAL, ATTRIB_VARNODE, ELEM_AND_EXP,
    ELEM_COMBINE_PAT, ELEM_COMMIT, ELEM_CONSTRUCTOR, ELEM_CONTEXT_OP, ELEM_CONTEXT_PAT,
    ELEM_CONTEXT_SYM, ELEM_CONTEXTFIELD, ELEM_DECISION, ELEM_DIV_EXP, ELEM_END_EXP, ELEM_END_SYM,
    ELEM_EPSILON_SYM, ELEM_INSTRUCT_PAT, ELEM_INTB, ELEM_LSHIFT_EXP, ELEM_MASK_WORD,
    ELEM_MINUS_EXP, ELEM_MULT_EXP, ELEM_NAME_SYM, ELEM_NAMETAB, ELEM_NEXT2_EXP, ELEM_NEXT2_SYM,
    ELEM_NOT_EXP, ELEM_NULL, ELEM_OPER, ELEM_OPERAND_EXP, ELEM_OPERAND_SYM, ELEM_OPPRINT,
    ELEM_OR_EXP, ELEM_PAIR, ELEM_PAT_BLOCK, ELEM_PLUS_EXP, ELEM_PRINT, ELEM_RSHIFT_EXP,
    ELEM_START_EXP, ELEM_START_SYM, ELEM_SUB_EXP, ELEM_SUBTABLE_SYM, ELEM_TOKENFIELD, ELEM_USEROP,
    ELEM_VALUE_SYM, ELEM_VALUEMAP_SYM, ELEM_VALUETAB, ELEM_VAR, ELEM_VARLIST_SYM, ELEM_VARNODE_SYM,
    ELEM_XOR_EXP,
};
use crate::model::Sla;
use crate::model::constructor::{
    Constructor, ContextChange, DecisionNode, DisjointPattern, PrintPiece,
};
use crate::model::expr::{BinaryOp, Expr, UnaryOp};
use crate::model::handles::{BlockId, ExprId, SymbolId};
use crate::model::symbol::SymbolKind;

impl Sla {
    pub(super) fn encode_body<E: Encoder>(
        &self,
        enc: &mut E,
        id: SymbolId,
    ) -> Result<(), EncodeError> {
        let Some(symbol) = self.symbol(id) else {
            return Ok(());
        };
        let id_value = u64::from(id.index());
        let simple = |enc: &mut E, element| {
            enc.open_element(element);
            enc.write_unsigned(ATTRIB_ID, id_value);
            enc.close_element(element);
        };
        match symbol.kind {
            SymbolKind::UserOp { index } => {
                enc.open_element(ELEM_USEROP);
                enc.write_unsigned(ATTRIB_ID, id_value);
                enc.write_signed(ATTRIB_INDEX, i64::from(index));
                enc.close_element(ELEM_USEROP);
            }
            SymbolKind::Value { expr } => {
                enc.open_element(ELEM_VALUE_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                self.encode_expr(enc, expr);
                enc.close_element(ELEM_VALUE_SYM);
            }
            SymbolKind::ValueMap { expr, table } => {
                enc.open_element(ELEM_VALUEMAP_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                self.encode_expr(enc, expr);
                for &value in self.value_table(table) {
                    enc.open_element(ELEM_VALUETAB);
                    enc.write_signed(ATTRIB_VAL, value);
                    enc.close_element(ELEM_VALUETAB);
                }
                enc.close_element(ELEM_VALUEMAP_SYM);
            }
            SymbolKind::Name { expr, table } => {
                enc.open_element(ELEM_NAME_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                self.encode_expr(enc, expr);
                for &name in self.name_table(table) {
                    enc.open_element(ELEM_NAMETAB);
                    if let Some(name) = name {
                        enc.write_string(ATTRIB_NAME, self.text(name))?;
                    }
                    enc.close_element(ELEM_NAMETAB);
                }
                enc.close_element(ELEM_NAME_SYM);
            }
            SymbolKind::Varnode {
                space,
                offset,
                size,
            } => {
                enc.open_element(ELEM_VARNODE_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                enc.write_space(ATTRIB_SPACE, &space_ref(self, space));
                enc.write_unsigned(ATTRIB_OFF, offset);
                enc.write_signed(ATTRIB_SIZE, i64::from(size));
                enc.close_element(ELEM_VARNODE_SYM);
            }
            SymbolKind::Context {
                varnode,
                low,
                high,
                flow,
                expr,
            } => {
                enc.open_element(ELEM_CONTEXT_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                enc.write_unsigned(ATTRIB_VARNODE, u64::from(varnode.index()));
                enc.write_signed(ATTRIB_LOW, i64::from(low));
                enc.write_signed(ATTRIB_HIGH, i64::from(high));
                enc.write_bool(ATTRIB_FLOW, flow);
                self.encode_expr(enc, expr);
                enc.close_element(ELEM_CONTEXT_SYM);
            }
            SymbolKind::VarnodeList { expr, table } => {
                enc.open_element(ELEM_VARLIST_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                self.encode_expr(enc, expr);
                for &entry in self.varnode_table(table) {
                    if let Some(var) = entry {
                        enc.open_element(ELEM_VAR);
                        enc.write_unsigned(ATTRIB_ID, u64::from(var.index()));
                        enc.close_element(ELEM_VAR);
                    } else {
                        enc.open_element(ELEM_NULL);
                        enc.close_element(ELEM_NULL);
                    }
                }
                enc.close_element(ELEM_VARLIST_SYM);
            }
            SymbolKind::Operand(operand) => {
                enc.open_element(ELEM_OPERAND_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                if let Some(sub) = operand.defining_symbol {
                    enc.write_unsigned(ATTRIB_SUBSYM, u64::from(sub.index()));
                }
                enc.write_signed(ATTRIB_OFF, i64::from(operand.offset));
                enc.write_signed(ATTRIB_BASE, i64::from(operand.base));
                enc.write_signed(ATTRIB_MINLEN, i64::from(operand.min_length));
                if operand.code {
                    enc.write_bool(ATTRIB_CODE, true);
                }
                enc.write_signed(ATTRIB_INDEX, i64::from(operand.index));
                self.encode_expr(enc, operand.local_expr);
                if let Some(expr) = operand.defining_expr {
                    self.encode_expr(enc, expr);
                }
                enc.close_element(ELEM_OPERAND_SYM);
            }
            SymbolKind::Start => simple(enc, ELEM_START_SYM),
            SymbolKind::End => simple(enc, ELEM_END_SYM),
            SymbolKind::Next2 => simple(enc, ELEM_NEXT2_SYM),
            SymbolKind::Epsilon => simple(enc, ELEM_EPSILON_SYM),
            SymbolKind::Subtable(table) => {
                enc.open_element(ELEM_SUBTABLE_SYM);
                enc.write_unsigned(ATTRIB_ID, id_value);
                enc.write_signed(ATTRIB_NUMCT, i64::from(table.num_constructors()));
                for ctor in self
                    .constructors()
                    .get(table.constructors.range())
                    .unwrap_or_default()
                {
                    self.encode_constructor(enc, ctor)?;
                }
                if let Some(root) = self.decision(table.decision) {
                    self.encode_decision(enc, root);
                }
                enc.close_element(ELEM_SUBTABLE_SYM);
            }
        }
        Ok(())
    }

    fn encode_constructor<E: Encoder>(
        &self,
        enc: &mut E,
        ctor: &Constructor,
    ) -> Result<(), EncodeError> {
        enc.open_element(ELEM_CONSTRUCTOR);
        enc.write_unsigned(ATTRIB_PARENT, u64::from(ctor.parent.index()));
        enc.write_signed(ATTRIB_FIRST, i64::from(ctor.first));
        enc.write_signed(ATTRIB_LENGTH, i64::from(ctor.length));
        enc.write_signed(ATTRIB_SOURCE, i64::from(ctor.source));
        enc.write_signed(ATTRIB_LINE, i64::from(ctor.line));
        for operand in self.operands(ctor) {
            enc.open_element(ELEM_OPER);
            enc.write_unsigned(ATTRIB_ID, u64::from(operand.index()));
            enc.close_element(ELEM_OPER);
        }
        for piece in self.print_pieces(ctor) {
            match *piece {
                PrintPiece::Text(text) => {
                    enc.open_element(ELEM_PRINT);
                    enc.write_string(ATTRIB_PIECE, self.text(text))?;
                    enc.close_element(ELEM_PRINT);
                }
                PrintPiece::Operand(index) => {
                    enc.open_element(ELEM_OPPRINT);
                    enc.write_signed(ATTRIB_ID, i64::from(index));
                    enc.close_element(ELEM_OPPRINT);
                }
            }
        }
        for change in self.context_changes(ctor) {
            match *change {
                ContextChange::Op {
                    word,
                    shift,
                    mask,
                    expr,
                } => {
                    enc.open_element(ELEM_CONTEXT_OP);
                    enc.write_signed(ATTRIB_I, i64::from(word));
                    enc.write_signed(ATTRIB_SHIFT, i64::from(shift));
                    enc.write_unsigned(ATTRIB_MASK, u64::from(mask));
                    self.encode_expr(enc, expr);
                    enc.close_element(ELEM_CONTEXT_OP);
                }
                ContextChange::Commit {
                    symbol,
                    word,
                    mask,
                    flow,
                } => {
                    enc.open_element(ELEM_COMMIT);
                    enc.write_unsigned(ATTRIB_ID, u64::from(symbol.index()));
                    enc.write_signed(ATTRIB_NUMBER, i64::from(word));
                    enc.write_unsigned(ATTRIB_MASK, u64::from(mask));
                    enc.write_bool(ATTRIB_FLOW, flow);
                    enc.close_element(ELEM_COMMIT);
                }
            }
        }
        for id in self.template_ids(ctor) {
            if let Some(template) = self.template(id) {
                encode_template(enc, self, &template);
            }
        }
        enc.close_element(ELEM_CONSTRUCTOR);
        Ok(())
    }

    fn encode_decision<E: Encoder>(&self, enc: &mut E, node: &DecisionNode) {
        enc.open_element(ELEM_DECISION);
        enc.write_signed(ATTRIB_NUMBER, i64::from(node.number));
        enc.write_bool(ATTRIB_CONTEXT, node.context);
        enc.write_signed(ATTRIB_STARTBIT, i64::from(node.start_bit));
        enc.write_signed(ATTRIB_SIZE, i64::from(node.size));
        for pair in self.pairs(node) {
            enc.open_element(ELEM_PAIR);
            enc.write_signed(ATTRIB_ID, i64::from(pair.constructor));
            match pair.pattern {
                DisjointPattern::Instruction(block) => {
                    self.encode_wrapped(enc, ELEM_INSTRUCT_PAT, block);
                }
                DisjointPattern::Context(block) => {
                    self.encode_wrapped(enc, ELEM_CONTEXT_PAT, block);
                }
                DisjointPattern::Combine {
                    context,
                    instruction,
                } => {
                    enc.open_element(ELEM_COMBINE_PAT);
                    self.encode_wrapped(enc, ELEM_CONTEXT_PAT, context);
                    self.encode_wrapped(enc, ELEM_INSTRUCT_PAT, instruction);
                    enc.close_element(ELEM_COMBINE_PAT);
                }
            }
            enc.close_element(ELEM_PAIR);
        }
        for child in self.children(node) {
            if let Some(child) = self.decision(child) {
                self.encode_decision(enc, child);
            }
        }
        enc.close_element(ELEM_DECISION);
    }

    fn encode_wrapped<E: Encoder>(&self, enc: &mut E, element: bk_marshal::ElementId, id: BlockId) {
        enc.open_element(element);
        if let Some(block) = self.block(id) {
            enc.open_element(ELEM_PAT_BLOCK);
            enc.write_signed(ATTRIB_OFF, i64::from(block.offset));
            enc.write_signed(ATTRIB_NONZERO, i64::from(block.nonzero));
            for word in self.block_words(block) {
                enc.open_element(ELEM_MASK_WORD);
                enc.write_unsigned(ATTRIB_MASK, u64::from(word.mask));
                enc.write_unsigned(ATTRIB_VAL, u64::from(word.value));
                enc.close_element(ELEM_MASK_WORD);
            }
            enc.close_element(ELEM_PAT_BLOCK);
        }
        enc.close_element(element);
    }

    pub(crate) fn encode_expr<E: Encoder>(&self, enc: &mut E, id: ExprId) {
        let Some(expr) = self.expr(id) else {
            return;
        };
        match *expr {
            Expr::TokenField(field) | Expr::ContextField(field) => {
                let token = matches!(expr, Expr::TokenField(_));
                let field = self.field(field).copied().unwrap_or_default();
                let element = if token {
                    ELEM_TOKENFIELD
                } else {
                    ELEM_CONTEXTFIELD
                };
                enc.open_element(element);
                if token {
                    enc.write_bool(ATTRIB_BIGENDIAN, field.big_endian);
                }
                enc.write_bool(ATTRIB_SIGNBIT, field.sign_bit);
                enc.write_signed(ATTRIB_STARTBIT, i64::from(field.start_bit));
                enc.write_signed(ATTRIB_ENDBIT, i64::from(field.end_bit));
                enc.write_signed(ATTRIB_STARTBYTE, i64::from(field.start_byte));
                enc.write_signed(ATTRIB_ENDBYTE, i64::from(field.end_byte));
                enc.write_signed(ATTRIB_SHIFT, i64::from(field.shift));
                enc.close_element(element);
            }
            Expr::Constant(value) => {
                enc.open_element(ELEM_INTB);
                enc.write_signed(ATTRIB_VAL, value);
                enc.close_element(ELEM_INTB);
            }
            Expr::Operand { index, table, ct } => {
                enc.open_element(ELEM_OPERAND_EXP);
                enc.write_signed(ATTRIB_INDEX, i64::from(index));
                enc.write_unsigned(ATTRIB_TABLE, u64::from(table.index()));
                enc.write_unsigned(ATTRIB_CT, u64::from(ct));
                enc.close_element(ELEM_OPERAND_EXP);
            }
            Expr::Start | Expr::End | Expr::Next2 => {
                let element = match expr {
                    Expr::Start => ELEM_START_EXP,
                    Expr::End => ELEM_END_EXP,
                    _ => ELEM_NEXT2_EXP,
                };
                enc.open_element(element);
                enc.close_element(element);
            }
            Expr::Binary { op, left, right } => {
                let element = binary_element(op);
                enc.open_element(element);
                self.encode_expr(enc, left);
                self.encode_expr(enc, right);
                enc.close_element(element);
            }
            Expr::Unary { op, operand } => {
                let element = match op {
                    UnaryOp::Minus => ELEM_MINUS_EXP,
                    UnaryOp::Not => ELEM_NOT_EXP,
                };
                enc.open_element(element);
                self.encode_expr(enc, operand);
                enc.close_element(element);
            }
        }
    }
}

const fn binary_element(op: BinaryOp) -> bk_marshal::ElementId {
    match op {
        BinaryOp::Plus => ELEM_PLUS_EXP,
        BinaryOp::Sub => ELEM_SUB_EXP,
        BinaryOp::Mult => ELEM_MULT_EXP,
        BinaryOp::LeftShift => ELEM_LSHIFT_EXP,
        BinaryOp::RightShift => ELEM_RSHIFT_EXP,
        BinaryOp::And => ELEM_AND_EXP,
        BinaryOp::Or => ELEM_OR_EXP,
        BinaryOp::Xor => ELEM_XOR_EXP,
        BinaryOp::Div => ELEM_DIV_EXP,
    }
}
