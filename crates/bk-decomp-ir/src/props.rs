//! The per-opcode property table: the `PcodeOp` flag bits each `TypeOp`
//! constructor passes as `opflags`, its `addlflags`, and the name
//! `print raw` uses (typeop.cc, `TypeOp::registerInstructions` and the
//! `TypeOp*` constructors). Checked against the reference console's own
//! table by this crate's tests.

use bk_pcode::OpCode;

use crate::flags::oflags::{
    BINARY, BOOLOUTPUT, BRANCH, CALL, CODEREF, COMMUTATIVE, HAS_CALLSPEC, MARKER, NOCOLLAPSE,
    RETURN_COPY, RETURNS, SPECIAL, TERNARY, UNARY,
};

/// `TypeOp::inherits_sign` and the other `addlflags` (typeop.hh:41–49).
pub mod addl {
    /// `inherits_sign`.
    pub const INHERITS_SIGN: u32 = 1;
    /// `inherits_sign_zero`.
    pub const INHERITS_SIGN_ZERO: u32 = 2;
    /// `shift_op`.
    pub const SHIFT_OP: u32 = 4;
    /// `arithmetic_op`.
    pub const ARITHMETIC_OP: u32 = 8;
    /// `logical_op`.
    pub const LOGICAL_OP: u32 = 0x10;
    /// `floatingpoint_op`.
    pub const FLOATINGPOINT_OP: u32 = 0x20;
    /// `boolean_reorder`.
    pub const BOOLEAN_REORDER: u32 = 0x40;
}

use addl::{
    ARITHMETIC_OP as AR, BOOLEAN_REORDER as BR, FLOATINGPOINT_OP as FP, INHERITS_SIGN as IS,
    INHERITS_SIGN_ZERO as IZ, LOGICAL_OP as LO, SHIFT_OP as SH,
};

/// How `TypeOp::printRaw` lays out an op (the class the constructor
/// derives from, or its own override).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RawForm {
    /// `out = in0 <sym> in1` (`TypeOpBinary`), the symbol given.
    Binary(&'static str),
    /// `out = <sym> in0` (`TypeOpUnary`).
    Unary(&'static str),
    /// `out = NAME(in0,in1,…)` (`TypeOpFunc`); some names take sizes.
    Func,
    /// `TypeOpCopy`.
    Copy,
    /// `TypeOpLoad`.
    Load,
    /// `TypeOpStore`.
    Store,
    /// `TypeOpBranch`.
    Branch,
    /// `TypeOpCbranch`.
    Cbranch,
    /// `TypeOpBranchind`.
    Branchind,
    /// `TypeOpCall`.
    Call,
    /// `TypeOpCallind`.
    Callind,
    /// `TypeOpCallother`.
    Callother,
    /// `TypeOpReturn`.
    Return,
    /// `TypeOpMulti`.
    Multi,
    /// `TypeOpIndirect`.
    Indirect,
    /// `TypeOpCast`.
    Cast,
    /// `TypeOpPtradd`.
    Ptradd,
    /// `TypeOpPtrsub`.
    Ptrsub,
    /// `TypeOpSegment`.
    Segment,
    /// `TypeOpCpoolref`.
    Cpoolref,
    /// `TypeOpNew`.
    New,
}

/// The properties of one opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpProps {
    /// `TypeOp::getFlags()`.
    pub flags: u32,
    /// `TypeOp::addlflags`.
    pub addl: u32,
    /// `TypeOp::getName()` (C operators; [`OpProps::name_java`] for Java).
    pub name: &'static str,
    /// How `printRaw` lays the op out.
    pub form: RawForm,
}

impl OpProps {
    /// The name with Java operators selected (`selectJavaOperators`:
    /// `INT_RIGHT` becomes `>>>`).
    pub fn name_java(&self, java: bool) -> &'static str {
        if java && self.name == ">>" && self.form == RawForm::Binary(">>") {
            ">>>"
        } else {
            self.name
        }
    }
}

const fn p(flags: u32, addl: u32, name: &'static str, form: RawForm) -> OpProps {
    OpProps {
        flags,
        addl,
        name,
        form,
    }
}

const fn bin(flags: u32, addl: u32, name: &'static str) -> OpProps {
    p(flags, addl, name, RawForm::Binary(name))
}

const fn bin_as(flags: u32, addl: u32, name: &'static str, sym: &'static str) -> OpProps {
    p(flags, addl, name, RawForm::Binary(sym))
}

const fn un(flags: u32, addl: u32, name: &'static str, sym: &'static str) -> OpProps {
    p(flags, addl, name, RawForm::Unary(sym))
}

const fn func(flags: u32, addl: u32, name: &'static str) -> OpProps {
    p(flags, addl, name, RawForm::Func)
}

/// The properties of `opcode`.
pub const fn props(opcode: OpCode) -> OpProps {
    use OpCode as O;
    use RawForm as F;
    let sp = SPECIAL | NOCOLLAPSE;
    match opcode {
        O::Copy => p(UNARY | NOCOLLAPSE, 0, "copy", F::Copy),
        O::Load => p(sp, 0, "load", F::Load),
        O::Store => p(sp, 0, "store", F::Store),
        O::Branch => p(sp | BRANCH | CODEREF, 0, "goto", F::Branch),
        O::CBranch => p(sp | BRANCH | CODEREF, 0, "goto", F::Cbranch),
        O::BranchInd => p(sp | BRANCH, 0, "switch", F::Branchind),
        O::Call => p(sp | CALL | HAS_CALLSPEC | CODEREF, 0, "call", F::Call),
        O::CallInd => p(sp | CALL | HAS_CALLSPEC, 0, "callind", F::Callind),
        O::CallOther => p(sp | CALL, 0, "syscall", F::Callother),
        O::Return => p(sp | RETURNS | RETURN_COPY, 0, "return", F::Return),
        O::IntEqual => bin(BINARY | BOOLOUTPUT | COMMUTATIVE, IS, "=="),
        O::IntNotEqual => bin(BINARY | BOOLOUTPUT | COMMUTATIVE, IS, "!="),
        O::IntSLess => bin_as(BINARY | BOOLOUTPUT, IS | BR, "<", "s<"),
        O::IntSLessEqual => bin_as(BINARY | BOOLOUTPUT, IS | BR, "<=", "s<="),
        O::IntLess => bin(BINARY | BOOLOUTPUT, IS | BR, "<"),
        O::IntLessEqual => bin(BINARY | BOOLOUTPUT, IS | BR, "<="),
        O::IntZExt => func(UNARY, 0, "ZEXT"),
        O::IntSExt => func(UNARY, 0, "SEXT"),
        O::IntAdd => bin(BINARY | COMMUTATIVE, AR | IS, "+"),
        O::IntSub => bin(BINARY, AR | IS, "-"),
        O::IntCarry => func(BINARY | COMMUTATIVE | BOOLOUTPUT, AR, "CARRY"),
        O::IntSCarry => func(BINARY | COMMUTATIVE | BOOLOUTPUT, AR, "SCARRY"),
        O::IntSBorrow => func(BINARY | BOOLOUTPUT, AR, "SBORROW"),
        O::Int2Comp => un(UNARY, AR | IS, "-", "-"),
        O::IntNegate => un(UNARY, LO | IS, "~", "~"),
        O::IntXor => bin(BINARY | COMMUTATIVE, LO | IS, "^"),
        O::IntAnd => bin(BINARY | COMMUTATIVE, LO | IS, "&"),
        O::IntOr => bin(BINARY | COMMUTATIVE, LO | IS, "|"),
        O::IntLeft => bin(BINARY, IS | IZ | SH, "<<"),
        O::IntRight => bin(BINARY, IS | IZ | SH, ">>"),
        O::IntSRight => bin_as(BINARY, IS | IZ | SH, ">>", "s>>"),
        O::IntMult => bin(BINARY | COMMUTATIVE, AR | IS, "*"),
        O::IntDiv => bin(BINARY, AR | IS, "/"),
        O::IntSDiv => bin_as(BINARY, AR | IS, "/", "s/"),
        O::IntRem => bin(BINARY, AR | IS | IZ, "%"),
        O::IntSRem => bin_as(BINARY, AR | IS | IZ, "%", "s%"),
        O::BoolNegate => un(UNARY | BOOLOUTPUT, LO, "!", "!"),
        O::BoolXor => bin(BINARY | COMMUTATIVE | BOOLOUTPUT, LO, "^^"),
        O::BoolAnd => bin(BINARY | COMMUTATIVE | BOOLOUTPUT, LO, "&&"),
        O::BoolOr => bin(BINARY | COMMUTATIVE | BOOLOUTPUT, LO, "||"),
        O::FloatEqual => bin_as(BINARY | BOOLOUTPUT | COMMUTATIVE, FP, "==", "f=="),
        O::FloatNotEqual => bin_as(BINARY | BOOLOUTPUT | COMMUTATIVE, FP, "!=", "f!="),
        O::FloatLess => bin_as(BINARY | BOOLOUTPUT, FP | BR, "<", "f<"),
        O::FloatLessEqual => bin_as(BINARY | BOOLOUTPUT, FP | BR, "<=", "f<="),
        O::FloatNan => func(UNARY | BOOLOUTPUT, FP, "NAN"),
        O::FloatAdd => bin_as(BINARY | COMMUTATIVE, FP, "+", "f+"),
        O::FloatDiv => bin_as(BINARY, FP, "/", "f/"),
        O::FloatMult => bin_as(BINARY | COMMUTATIVE, FP, "*", "f*"),
        O::FloatSub => bin_as(BINARY, FP, "-", "f-"),
        O::FloatNeg => un(UNARY, FP, "-", "f-"),
        O::FloatAbs => func(UNARY, FP, "ABS"),
        O::FloatSqrt => func(UNARY, FP, "SQRT"),
        O::FloatInt2Float => func(UNARY, FP, "INT2FLOAT"),
        O::FloatFloat2Float => func(UNARY, FP, "FLOAT2FLOAT"),
        O::FloatTrunc => func(UNARY, FP, "TRUNC"),
        O::FloatCeil => func(UNARY, FP, "CEIL"),
        O::FloatFloor => func(UNARY, FP, "FLOOR"),
        O::FloatRound => func(UNARY, FP, "ROUND"),
        O::MultiEqual => p(SPECIAL | MARKER | NOCOLLAPSE, 0, "?", F::Multi),
        O::Indirect => p(SPECIAL | MARKER | NOCOLLAPSE, 0, "[]", F::Indirect),
        O::Piece => func(BINARY, 0, "CONCAT"),
        O::SubPiece => func(BINARY, 0, "SUB"),
        O::Cast => p(UNARY | SPECIAL | NOCOLLAPSE, 0, "(cast)", F::Cast),
        O::PtrAdd => p(TERNARY | NOCOLLAPSE, AR, "+", F::Ptradd),
        O::PtrSub => p(BINARY | NOCOLLAPSE, AR, "->", F::Ptrsub),
        O::SegmentOp => p(sp, 0, "segmentop", F::Segment),
        O::CPoolRef => p(sp, 0, "cpoolref", F::Cpoolref),
        O::New => p(sp | CALL, 0, "new", F::New),
        O::Insert => func(TERNARY, 0, "INSERT"),
        O::ZPull => func(TERNARY, 0, "ZPULL"),
        O::PopCount => func(UNARY, 0, "POPCOUNT"),
        O::LzCount => func(UNARY, 0, "LZCOUNT"),
        O::SPull => func(TERNARY, 0, "SPULL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_has_an_evaluation_class() {
        let mut special = 0;
        for op in OpCode::ALL {
            let f = props(op).flags;
            assert_ne!(f & (UNARY | BINARY | TERNARY | SPECIAL), 0, "{op:?}");
            if f & SPECIAL != 0 {
                special += 1;
            }
        }
        assert_eq!(OpCode::ALL.len(), 73);
        assert_eq!(special, 15, "grep -c 'PcodeOp::special' typeop.cc");
        assert_eq!(props(OpCode::IntRight).name_java(true), ">>>");
        assert_eq!(props(OpCode::IntSRight).name_java(true), ">>");
    }
}
