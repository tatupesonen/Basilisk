//! Pattern expressions (inventory section 1.3).

use super::handles::{ExprId, FieldId, SymbolId};

/// One node of a pattern expression. Children are earlier nodes of the same
/// arena, so a tree has no cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expr {
    /// `tokenfield`: bits of the instruction bytes.
    TokenField(FieldId),
    /// `contextfield`: bits of the context words.
    ContextField(FieldId),
    /// `intb`: a constant.
    Constant(i64),
    /// `operand_exp`: the value of operand `index` of constructor `ct` of
    /// subtable `table`.
    Operand {
        /// The operand index.
        index: i32,
        /// The subtable.
        table: SymbolId,
        /// The constructor's index in the subtable.
        ct: u32,
    },
    /// `start_exp`: the instruction's address.
    Start,
    /// `end_exp`: the next instruction's address.
    End,
    /// `next2_exp`: the address of the instruction after the next.
    Next2,
    /// A binary operator.
    Binary {
        /// The operator.
        op: BinaryOp,
        /// Left operand.
        left: ExprId,
        /// Right operand.
        right: ExprId,
    },
    /// A unary operator.
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: ExprId,
    },
}

impl Expr {
    /// Whether the node is a value (Ghidra's `PatternValue`), not an
    /// operator.
    pub const fn is_value(&self) -> bool {
        !matches!(self, Self::Binary { .. } | Self::Unary { .. })
    }
}

/// The binary operators of pattern expressions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// `plus_exp`.
    Plus,
    /// `sub_exp`.
    Sub,
    /// `mult_exp`.
    Mult,
    /// `lshift_exp`.
    LeftShift,
    /// `rshift_exp`.
    RightShift,
    /// `and_exp`.
    And,
    /// `or_exp`.
    Or,
    /// `xor_exp`.
    Xor,
    /// `div_exp`.
    Div,
}

impl BinaryOp {
    /// Every operator.
    pub const ALL: [Self; 9] = [
        Self::Plus,
        Self::Sub,
        Self::Mult,
        Self::LeftShift,
        Self::RightShift,
        Self::And,
        Self::Or,
        Self::Xor,
        Self::Div,
    ];
}

/// The unary operators of pattern expressions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// `minus_exp`: negation.
    Minus,
    /// `not_exp`: bitwise complement.
    Not,
}

/// A token field or context field (`tokenfield`, `contextfield`).
///
/// For a context field the bit numbers are most-significant-bit first over
/// the whole context array and `big_endian` is unused (false).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Field {
    /// Byte order of the token (token fields only).
    pub big_endian: bool,
    /// Whether the value is sign-extended.
    pub sign_bit: bool,
    /// First bit.
    pub start_bit: i32,
    /// Last bit.
    pub end_bit: i32,
    /// First byte read.
    pub start_byte: i32,
    /// Last byte read.
    pub end_byte: i32,
    /// Right shift applied to the bytes read.
    pub shift: i32,
}
