//! The failures of the decoder's inner functions, before they become a
//! [`DecodeError`].
//!
//! Every inner function of decoding and handle resolution can fail, and a
//! `Result<_, DecodeError>` is returned through memory: the error carries
//! the address and its text. A [`Fault`] is two bytes, so a `Result<i64,
//! Fault>` or `Result<ConstructorId, Fault>` comes back in registers, and the
//! address (the instruction's, the same for every failure of one parse) is
//! added once, where decoding hands its result to the caller
//! ([`Fault::at`]). The errors are the same.

use bk_core::Address;

use crate::error::{DecodeError, Limit, TableKind};
use crate::language::Language;

/// A decode failure without its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// [`DecodeError::Model`].
    Model(What),
    /// [`DecodeError::TooLong`].
    TooLong,
    /// [`DecodeError::NoConstructor`].
    NoConstructor,
    /// [`DecodeError::NoTableEntry`].
    NoTableEntry(TableKind),
    /// [`DecodeError::DivisionByZero`].
    DivisionByZero,
    /// [`DecodeError::Limit`].
    Limit(Limit),
    /// [`DecodeError::Next2Unavailable`].
    Next2Unavailable,
    /// [`DecodeError::NotASpace`].
    NotASpace,
}

/// What a malformed model lacked ([`DecodeError::Model`]'s `what`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum What {
    Node,
    NodeConstructor,
    Constructor,
    Operand,
    OperandNode,
    OperandBase,
    PatternBlock,
    Field,
    Subtable,
    Expression,
    OperandExpConstructor,
    SubtableInExpression,
    DecisionNode,
    DecisionChild,
    DecisionPairConstructor,
    DecisionTreeTooDeep,
    ConstHandleOperand,
}

impl What {
    /// The text [`DecodeError::Model`] prints.
    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::NodeConstructor => "node constructor",
            Self::Constructor => "constructor",
            Self::Operand => "operand",
            Self::OperandNode => "operand node",
            Self::OperandBase => "operand base",
            Self::PatternBlock => "pattern block",
            Self::Field => "field",
            Self::Subtable => "subtable",
            Self::Expression => "expression",
            Self::OperandExpConstructor => "operand_exp constructor",
            Self::SubtableInExpression => "Cannot use subtable in expression",
            Self::DecisionNode => "decision node",
            Self::DecisionChild => "decision child",
            Self::DecisionPairConstructor => "decision pair constructor",
            Self::DecisionTreeTooDeep => "decision tree too deep",
            Self::ConstHandleOperand => "const_handle operand",
        }
    }
}

impl Fault {
    /// The error for the instruction at `address`.
    #[cold]
    pub(crate) fn at(self, lang: &Language, address: Address) -> DecodeError {
        match self {
            Self::Model(what) => DecodeError::Model {
                address,
                what: what.text(),
            },
            Self::TooLong => DecodeError::TooLong { address },
            Self::NoConstructor => DecodeError::NoConstructor {
                address,
                at: lang.raw_text(address),
            },
            Self::NoTableEntry(table) => DecodeError::NoTableEntry {
                address,
                at: lang.raw_text(address),
                table,
            },
            Self::DivisionByZero => DecodeError::DivisionByZero { address },
            Self::Limit(limit) => DecodeError::Limit { address, limit },
            Self::Next2Unavailable => DecodeError::Next2Unavailable { address },
            Self::NotASpace => DecodeError::NotASpace { address },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_come_back_in_registers() {
        assert!(size_of::<Fault>() <= 2, "{}", size_of::<Fault>());
        assert!(size_of::<Result<i64, Fault>>() <= 16);
    }
}
