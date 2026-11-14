//! Reading bits and bytes of the instruction and the local context, and
//! evaluating pattern expressions (Ghidra `ParserContext::get*Bytes`,
//! `get*Bits`, `PatternExpression::getValue`; inventory section 5).

use bk_core::Address;
use bk_sla::{BinaryOp, ConstructorId, Expr, ExprId, Field, Sla, UnaryOp};

use super::bytes::WINDOW;
use super::tree::{NONE, Parse};
use crate::error::{DecodeError, Limit};
use crate::language::Language;
use crate::language::tables::{OpDef, sign_extend, zero_extend};

/// How deeply expression evaluation may recurse (operand expressions refer
/// to other operands; `bk-sla` rejects cycles, this bounds the rest).
pub(crate) const MAX_EXPR_DEPTH: u32 = 64;

/// Where an expression is evaluated: at a node of the tree, or at the
/// stand-in node Ghidra builds to evaluate another operand "out of band"
/// (`ParserWalker::setOutOfBandState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    Node(u32),
    Temp { ct: u32, offset: u32 },
}

/// Everything expression evaluation reads. It is built afresh for each
/// evaluation (the parse changes between them), so it holds references
/// only: copying the parse's vector headers into it on every call cost a
/// store-to-load forwarding stall on x86-64 right after the node vector grew.
pub(crate) struct Env<'a> {
    pub(crate) lang: &'a Language,
    pub(crate) sla: &'a Sla,
    /// The instruction being decoded: its bytes, local context, nodes,
    /// address, `inst_next2` and overhang flag.
    pub(crate) parse: &'a Parse,
    /// The next address; `None` while the instruction is being resolved.
    pub(crate) naddr: Option<Address>,
}

impl Env<'_> {
    pub(crate) fn model(&self, what: &'static str) -> DecodeError {
        DecodeError::Model {
            address: self.parse.addr,
            what,
        }
    }

    fn too_long(&self) -> DecodeError {
        DecodeError::TooLong {
            address: self.parse.addr,
        }
    }

    pub(crate) fn offset_of(&self, point: Point) -> u32 {
        match point {
            Point::Node(n) => self
                .parse
                .nodes
                .get(n as usize)
                .map_or(0, |node| node.offset),
            Point::Temp { offset, .. } => offset,
        }
    }

    /// `size` (1..=4) instruction bytes at `start` from `node_offset`, big
    /// endian (Ghidra `getInstructionBytes`).
    #[inline]
    pub(crate) fn instruction_bytes(
        &self,
        start: i32,
        size: u32,
        node_offset: u32,
    ) -> Result<u32, DecodeError> {
        let pos = node_offset.wrapping_add(start as u32);
        if pos as usize >= WINDOW {
            return Err(self.too_long());
        }
        if pos as usize + size as usize > WINDOW {
            self.parse.overhang.set(true);
        }
        Ok(self.parse.window.read(pos, size))
    }

    /// A 4-byte pattern word at `start` from `node_offset`; bytes past the
    /// window only count as used when the mask covers them.
    #[inline]
    pub(crate) fn pattern_word(
        &self,
        start: i32,
        node_offset: u32,
        mask: u32,
    ) -> Result<u32, DecodeError> {
        let pos = node_offset.wrapping_add(start as u32);
        if pos as usize >= WINDOW {
            return Err(self.too_long());
        }
        let inside = WINDOW as u32 - pos;
        if inside < 4 && mask & (u32::MAX >> (8 * inside)) != 0 {
            self.parse.overhang.set(true);
        }
        Ok(self.parse.window.read(pos, 4))
    }

    /// `size` bits at `start_bit` from `node_offset`, most significant first
    /// (Ghidra `getInstructionBits`).
    #[inline]
    pub(crate) fn instruction_bits(
        &self,
        start_bit: i32,
        size: u32,
        node_offset: u32,
    ) -> Result<u32, DecodeError> {
        let pos = node_offset.wrapping_add((start_bit / 8) as u32);
        if pos as usize >= WINDOW {
            return Err(self.too_long());
        }
        let bit = (start_bit % 8) as u32;
        let byte_size = (bit + size).saturating_sub(1) / 8 + 1;
        if pos as usize + byte_size as usize > WINDOW {
            self.parse.overhang.set(true);
        }
        let raw = self.parse.window.read(pos, byte_size.min(4));
        let raw = raw.wrapping_shl(8 * (4 - byte_size.min(4)) + bit);
        Ok(raw.wrapping_shr(32u32.wrapping_sub(size)))
    }

    /// `size` (1..=4) context bytes at `start`, reading across at most two
    /// words; words past the end read as zero (Ghidra `getContextBytes`).
    #[inline]
    pub(crate) fn context_bytes(&self, start: i32, size: u32) -> u32 {
        let word_index = start.div_euclid(4);
        let byte_offset = start.rem_euclid(4) as u32;
        let word = |i: i32| {
            usize::try_from(i)
                .ok()
                .and_then(|i| self.parse.context.get(i))
                .copied()
        };
        let mut res = word(word_index).unwrap_or(0);
        res = res.wrapping_shl(byte_offset * 8);
        res = res.wrapping_shr((4u32.wrapping_sub(size)) * 8);
        let remaining = size as i32 - 4 + byte_offset as i32;
        if remaining > 0
            && let Some(next) = word(word_index + 1)
        {
            res |= next.wrapping_shr((4 - remaining as u32) * 8);
        }
        res
    }

    /// `size` context bits at `start_bit` (Ghidra `getContextBits`).
    #[inline]
    pub(crate) fn context_bits(&self, start_bit: i32, size: u32) -> u32 {
        let word_index = start_bit.div_euclid(32);
        let bit_offset = start_bit.rem_euclid(32) as u32;
        let word = |i: i32| {
            usize::try_from(i)
                .ok()
                .and_then(|i| self.parse.context.get(i))
                .copied()
        };
        let mut res = word(word_index).unwrap_or(0);
        res = res.wrapping_shl(bit_offset);
        res = res.wrapping_shr(32u32.wrapping_sub(size));
        let remaining = size as i32 - 32 + bit_offset as i32;
        if remaining > 0
            && let Some(next) = word(word_index + 1)
        {
            res |= next.wrapping_shr(32 - remaining as u32);
        }
        res
    }

    fn token_field(&self, field: &Field, node_offset: u32) -> Result<i64, DecodeError> {
        let size = field
            .end_byte
            .wrapping_sub(field.start_byte)
            .wrapping_add(1);
        let mut start = field.start_byte;
        let mut left = size;
        let mut res: i64 = 0;
        while left >= 4 {
            let tmp = self.instruction_bytes(start, 4, node_offset)?;
            res = res.wrapping_shl(32) | i64::from(tmp);
            start = start.wrapping_add(4);
            left -= 4;
        }
        if left > 0 {
            let tmp = self.instruction_bytes(start, left as u32, node_offset)?;
            res = res.wrapping_shl(8 * left as u32) | i64::from(tmp);
        }
        if !field.big_endian {
            res = byte_swap(res, size);
        }
        Ok(extend(res.wrapping_shr(field.shift as u32), field))
    }

    fn context_field(&self, field: &Field) -> i64 {
        let mut start = field.start_byte;
        let mut size = field.end_byte.wrapping_sub(start).wrapping_add(1);
        let mut res: i64 = 0;
        while size >= 4 {
            res = res.wrapping_shl(32) | i64::from(self.context_bytes(start, 4));
            start = start.wrapping_add(4);
            size = field.end_byte.wrapping_sub(start).wrapping_add(1);
        }
        if size > 0 {
            res = res.wrapping_shl(8 * size as u32)
                | i64::from(self.context_bytes(start, size as u32));
        }
        extend(res.wrapping_shr(field.shift as u32), field)
    }

    /// The value of an expression at `point`.
    pub(crate) fn eval(&self, id: ExprId, point: Point, depth: u32) -> Result<i64, DecodeError> {
        if depth > MAX_EXPR_DEPTH {
            return Err(DecodeError::Limit {
                address: self.parse.addr,
                limit: Limit::ExpressionDepth,
            });
        }
        let expr = self.sla.expr(id).ok_or_else(|| self.model("expression"))?;
        Ok(match *expr {
            Expr::TokenField(field) => {
                let field = self.sla.field(field).ok_or_else(|| self.model("field"))?;
                self.token_field(field, self.offset_of(point))?
            }
            Expr::ContextField(field) => {
                let field = self.sla.field(field).ok_or_else(|| self.model("field"))?;
                self.context_field(field)
            }
            Expr::Constant(value) => value,
            Expr::Operand { index, table, ct } => {
                let ctor = self
                    .sla
                    .subtable(table)
                    .and_then(|t| t.constructor(ct))
                    .ok_or_else(|| self.model("operand_exp constructor"))?;
                self.operand_value(ctor, index, point, depth)?
            }
            Expr::Start => self.unit_offset(self.parse.addr),
            Expr::End => self.unit_offset(self.naddr.unwrap_or(self.parse.addr)),
            Expr::Next2 => {
                let next2 = self.parse.next2.ok_or(DecodeError::Next2Unavailable {
                    address: self.parse.addr,
                })?;
                self.unit_offset(next2)
            }
            Expr::Binary { op, left, right } => {
                let a = self.eval(left, point, depth + 1)?;
                let b = self.eval(right, point, depth + 1)?;
                binary(op, a, b).ok_or(DecodeError::DivisionByZero {
                    address: self.parse.addr,
                })?
            }
            Expr::Unary { op, operand } => {
                let a = self.eval(operand, point, depth + 1)?;
                match op {
                    UnaryOp::Minus => a.wrapping_neg(),
                    UnaryOp::Not => !a,
                }
            }
        })
    }

    /// An address's offset in addressable units (Ghidra
    /// `StartInstructionValue::getValue`).
    fn unit_offset(&self, addr: Address) -> i64 {
        let word = addr
            .space()
            .and_then(|space| self.lang.spaces().space(space))
            .map_or(1, |space| u64::from(space.word_size().max(1)));
        (addr.offset() / word).cast_signed()
    }

    /// The value of operand `index` of constructor `ctor`, evaluated where
    /// that constructor sits above `point` (Ghidra `OperandValue::getValue`).
    fn operand_value(
        &self,
        ctor: ConstructorId,
        index: i32,
        point: Point,
        depth: u32,
    ) -> Result<i64, DecodeError> {
        let info = self
            .lang
            .tables
            .ctor(ctor)
            .ok_or_else(|| self.model("constructor"))?;
        let op = self
            .lang
            .tables
            .op(info, index.max(0) as u32)
            .filter(|_| index >= 0)
            .ok_or_else(|| self.model("operand"))?;
        let expr = match op.def {
            OpDef::Expr(expr) | OpDef::Value(expr) | OpDef::Table { expr, .. } => expr,
            OpDef::Start => return Ok(self.unit_offset(self.parse.addr)),
            OpDef::End => return Ok(self.unit_offset(self.naddr.unwrap_or(self.parse.addr))),
            OpDef::Next2 => {
                let next2 = self.parse.next2.ok_or(DecodeError::Next2Unavailable {
                    address: self.parse.addr,
                })?;
                return Ok(self.unit_offset(next2));
            }
            OpDef::Varnode { .. } | OpDef::Zero => return Ok(0),
            OpDef::Subtable(_) => return Err(self.model("Cannot use subtable in expression")),
        };
        let target = self.out_of_band(ctor.index(), index, op.base, op.offset, point);
        self.eval(expr, target, depth + 1)
    }

    /// The stand-in node for evaluating operand `index` of constructor `ct`
    /// from `point`. Where Ghidra leaves its walker uninitialised (the
    /// constructor is not above `point`), the operand is evaluated at `point`.
    fn out_of_band(&self, ct: u32, index: i32, base: i32, rel: i32, point: Point) -> Point {
        match point {
            Point::Node(start) => {
                let mut at = start;
                loop {
                    let Some(node) = self.parse.nodes.get(at as usize) else {
                        return point;
                    };
                    if node.ctor == ct {
                        let offset = if base < 0 {
                            node.offset.wrapping_add(rel as u32)
                        } else {
                            node.child(index as u32)
                                .and_then(|c| self.parse.nodes.get(c as usize))
                                .map_or(0, |child| child.offset)
                        };
                        return Point::Temp { ct, offset };
                    }
                    if node.parent == NONE {
                        return point;
                    }
                    at = node.parent;
                }
            }
            Point::Temp { ct: here, offset } => {
                if here == ct && base < 0 {
                    Point::Temp {
                        ct,
                        offset: offset.wrapping_add(rel as u32),
                    }
                } else {
                    point
                }
            }
        }
    }
}

/// The binary operators on 64-bit signed values (ADR-024): wrapping
/// arithmetic, shift counts modulo 64 with an arithmetic right shift, and
/// `None` for division by zero.
pub(crate) fn binary(op: BinaryOp, a: i64, b: i64) -> Option<i64> {
    Some(match op {
        BinaryOp::Plus => a.wrapping_add(b),
        BinaryOp::Sub => a.wrapping_sub(b),
        BinaryOp::Mult => a.wrapping_mul(b),
        BinaryOp::LeftShift => a.wrapping_shl(b as u32),
        BinaryOp::RightShift => a.wrapping_shr(b as u32),
        BinaryOp::And => a & b,
        BinaryOp::Or => a | b,
        BinaryOp::Xor => a ^ b,
        BinaryOp::Div => {
            if b == 0 {
                return None;
            }
            a.wrapping_div(b)
        }
    })
}

/// Ghidra `byte_swap(intb&, size)`: reverses the low `size` bytes.
fn byte_swap(value: i64, size: i32) -> i64 {
    let mut value = value;
    let mut res: i64 = 0;
    let mut left = size;
    while left > 0 {
        res = res.wrapping_shl(8) | (value & 0xff);
        value = value.wrapping_shr(8);
        left -= 1;
    }
    res
}

fn extend(value: i64, field: &Field) -> i64 {
    let bit = field.end_bit.wrapping_sub(field.start_bit);
    if field.sign_bit {
        sign_extend(value, bit)
    } else {
        zero_extend(value, bit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_have_defined_results() {
        assert_eq!(binary(BinaryOp::LeftShift, 1, 0), Some(1));
        assert_eq!(binary(BinaryOp::LeftShift, 1, 63), Some(i64::MIN));
        assert_eq!(binary(BinaryOp::LeftShift, 1, 64), Some(1));
        assert_eq!(binary(BinaryOp::LeftShift, 1, -1), Some(i64::MIN));
        assert_eq!(binary(BinaryOp::RightShift, -8, 1), Some(-4));
        assert_eq!(binary(BinaryOp::RightShift, -8, 64), Some(-8));
        assert_eq!(binary(BinaryOp::RightShift, i64::MIN, 63), Some(-1));
        assert_eq!(binary(BinaryOp::Div, 7, 0), None);
        assert_eq!(binary(BinaryOp::Div, i64::MIN, -1), Some(i64::MIN));
        assert_eq!(binary(BinaryOp::Div, -7, 2), Some(-3));
        assert_eq!(binary(BinaryOp::Plus, i64::MAX, 1), Some(i64::MIN));
        assert_eq!(binary(BinaryOp::Sub, i64::MIN, 1), Some(i64::MAX));
        assert_eq!(binary(BinaryOp::Mult, i64::MIN, -1), Some(i64::MIN));
        assert_eq!(binary(BinaryOp::Xor, 6, 3), Some(5));
        assert_eq!(binary(BinaryOp::And, 6, 3), Some(2));
        assert_eq!(binary(BinaryOp::Or, 6, 3), Some(7));
    }

    #[test]
    fn byte_swap_reverses_low_bytes() {
        assert_eq!(byte_swap(0x1122_3344, 4), 0x4433_2211);
        assert_eq!(byte_swap(0x1122, 2), 0x2211);
        assert_eq!(byte_swap(0x1122, 0), 0);
        assert_eq!(byte_swap(0x0102_0304_0506_0708, 8), 0x0807_0605_0403_0201);
    }
}
