//! Pattern equations at compile time: their patterns
//! (`genPattern`), the offsets of the operands they place
//! (`resolveOperandLeft`) and the order operands appear in
//! (`operandOrder`) (inventory 10 a.5–a.8).

mod generate;
mod order;
mod resolve;

pub(crate) use generate::{Shape, generate, min_pattern};
pub(crate) use order::operand_order;
pub(crate) use resolve::{Offsets, resolve_offsets};

use crate::ids::OperandId;
use crate::pattern::{CombineError, PatternArena};
use crate::symbols::OperandData;

/// Deepest equation or expression tree handled; deeper ones are an error
/// rather than a risk to the stack (specifications are untrusted input).
pub(crate) const MAX_DEPTH: u32 = 512;

/// Most assignments a constraint may enumerate (Ghidra enumerates every
/// value of the fields involved; a constraint over wide fields would never
/// finish). The shipped specifications stay far below.
pub(crate) const MAX_ENUMERATION: u128 = 1 << 20;

/// An error building a constructor's pattern: Ghidra's `SleighError`
/// explanation, or a token mismatch whose names are filled in later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EqError {
    /// Text as Ghidra gives it.
    Text(String),
    /// A failed combination of two patterns.
    Combine(CombineError),
}

impl EqError {
    pub(crate) fn new(text: impl Into<String>) -> Self {
        Self::Text(text.into())
    }

    pub(crate) fn combine(error: CombineError) -> Self {
        Self::Combine(error)
    }
}

/// What the equation passes read: the expression and equation arenas and
/// the operands (for their index in the constructor).
pub(crate) struct EquationView<'a> {
    pub(crate) arena: &'a PatternArena,
    pub(crate) operands: &'a [OperandData],
}

impl EquationView<'_> {
    /// The operand's index in its constructor (parse order).
    pub(crate) fn operand_index(&self, op: OperandId) -> Option<usize> {
        self.operands.get(op.slot()).map(|o| o.index as usize)
    }
}
