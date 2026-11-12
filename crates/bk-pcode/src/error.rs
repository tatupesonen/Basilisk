//! The error an operation evaluation can produce.

use core::fmt;

use crate::opcode::OpCode;

/// Which evaluation interface was asked for an operation it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arity {
    /// One input.
    Unary,
    /// Two inputs.
    Binary,
    /// Three inputs.
    Ternary,
}

impl fmt::Display for Arity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unary => "Unary",
            Self::Binary => "Binary",
            Self::Ternary => "Ternary",
        })
    }
}

/// Why an operation could not be evaluated, or an input not recovered.
///
/// Ghidra throws `EvaluationError` or `LowlevelError` in these places; the
/// messages here are Ghidra's where it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum EvalError {
    /// `INT_DIV` or `INT_SDIV` with a zero divisor.
    #[error("Divide by 0")]
    DivideByZero,
    /// `INT_REM` or `INT_SREM` with a zero divisor.
    #[error("Remainder by 0")]
    RemainderByZero,
    /// The operation has no arithmetic of this arity: it is a special
    /// operation (`LOAD`, `BRANCH`, `MULTIEQUAL`, …), or it was evaluated
    /// through the wrong interface.
    #[error("{arity} emulation unimplemented for {op}")]
    Unimplemented {
        /// The operation.
        op: OpCode,
        /// The interface that was used.
        arity: Arity,
    },
    /// A floating-point operation on a size the format table has no format
    /// for. (The C++ reports this as an unimplemented emulation.)
    #[error("no floating-point format of {size} bytes for {op}")]
    NoFloatFormat {
        /// The operation.
        op: OpCode,
        /// The operand size in bytes that has no format.
        size: u32,
    },
    /// An operand size the evaluation path cannot represent.
    #[error("operand size of {size} bytes exceeds the {limit} bytes this evaluation supports")]
    UnsupportedSize {
        /// The offending size in bytes.
        size: u32,
        /// The largest supported size in bytes.
        limit: u32,
    },
    /// The operation loses information, so its input cannot be recovered
    /// from its output.
    #[error("Cannot recover input parameter without loss of information")]
    CannotRecover,
    /// No input produces the given output.
    #[error("Output is not in range of {0} operation")]
    OutOfRange(RecoverOp),
}

/// The operation named in [`EvalError::OutOfRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoverOp {
    /// `INT_ZEXT`.
    ZExt,
    /// `INT_SEXT`.
    SExt,
    /// `INT_LEFT`.
    LeftShift,
    /// `INT_RIGHT` or `INT_SRIGHT`.
    RightShift,
}

impl fmt::Display for RecoverOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZExt => "zext",
            Self::SExt => "sext",
            Self::LeftShift => "left shift",
            Self::RightShift => "right shift",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_ghidras() {
        assert_eq!(EvalError::DivideByZero.to_string(), "Divide by 0");
        assert_eq!(EvalError::RemainderByZero.to_string(), "Remainder by 0");
        assert_eq!(
            EvalError::Unimplemented {
                op: OpCode::Load,
                arity: Arity::Unary
            }
            .to_string(),
            "Unary emulation unimplemented for LOAD"
        );
        assert_eq!(
            EvalError::Unimplemented {
                op: OpCode::MultiEqual,
                arity: Arity::Binary
            }
            .to_string(),
            "Binary emulation unimplemented for BUILD"
        );
        assert_eq!(
            EvalError::Unimplemented {
                op: OpCode::IntAdd,
                arity: Arity::Ternary
            }
            .to_string(),
            "Ternary emulation unimplemented for INT_ADD"
        );
        assert_eq!(
            EvalError::CannotRecover.to_string(),
            "Cannot recover input parameter without loss of information"
        );
        assert_eq!(
            EvalError::OutOfRange(RecoverOp::ZExt).to_string(),
            "Output is not in range of zext operation"
        );
        assert_eq!(
            EvalError::OutOfRange(RecoverOp::SExt).to_string(),
            "Output is not in range of sext operation"
        );
        assert_eq!(
            EvalError::OutOfRange(RecoverOp::LeftShift).to_string(),
            "Output is not in range of left shift operation"
        );
        assert_eq!(
            EvalError::OutOfRange(RecoverOp::RightShift).to_string(),
            "Output is not in range of right shift operation"
        );
    }
}
