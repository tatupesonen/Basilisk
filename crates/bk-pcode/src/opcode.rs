//! P-code operation codes.
//!
//! Ghidra sources: `opcodes.hh`/`opcodes.cc` (the `OpCode` enumeration, the
//! name table, `get_opname`, `get_opcode`), `PcodeOp.java` (the Java
//! constants and listing mnemonics), `typeop.cc` and `pcodeCPort/opcodes/OpCode.java`
//! (the complementary comparison of each boolean operation) and
//! `opbehavior.cc` (`isunary`, `isspecial`).
//!
//! The numeric values are fixed: they appear in compiled SLEIGH (`.sla`) files
//! and in encoded p-code. Value 0 is not an operation (`BLANK` in the C++ name
//! table, `UNIMPLEMENTED` in Java), slot 45 is unused (`UNUSED1`), and 75 is
//! the end marker (`CPUI_MAX`, `PCODE_MAX`). That leaves 73 operations.

use core::fmt;

/// Error for a number or name that is not a p-code operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpCodeError {
    /// The numeric value is 0, the unused slot 45, or at least [`OpCode::MAX`].
    #[error("{0} is not a p-code operation code")]
    UnknownValue(u8),
    /// The name is not in the table that was searched.
    #[error("{0:?} is not a p-code operation name")]
    UnknownName(String),
}

macro_rules! opcodes {
    ($( $(#[$doc:meta])* $variant:ident = $value:literal, $name:literal, $mnemonic:literal; )*) => {
        /// The op-code defining a specific p-code operation.
        ///
        /// Discriminants are Ghidra's `CPUI_*` values.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum OpCode {
            $( $(#[$doc])* $variant = $value, )*
        }

        impl OpCode {
            /// Every operation, in increasing numeric order.
            pub const ALL: [OpCode; OpCode::COUNT] = [ $( OpCode::$variant, )* ];

            /// The operation with the given numeric value, if there is one.
            pub const fn from_u8(value: u8) -> Option<OpCode> {
                match value {
                    $( $value => Some(OpCode::$variant), )*
                    _ => None,
                }
            }

            /// The name Ghidra's C++ `get_opname` returns.
            ///
            /// Four operations carry the name of the SLEIGH template directive
            /// that shares their slot: `MULTIEQUAL` is `BUILD`, `INDIRECT` is
            /// `DELAY_SLOT`, `PTRADD` is `LABEL` and `PTRSUB` is `CROSSBUILD`.
            pub const fn name(self) -> &'static str {
                match self {
                    $( OpCode::$variant => $name, )*
                }
            }

            /// The mnemonic Ghidra's Java `PcodeOp.getMnemonic` returns, which
            /// is what p-code listings print.
            pub const fn mnemonic(self) -> &'static str {
                match self {
                    $( OpCode::$variant => $mnemonic, )*
                }
            }
        }
    };
}

opcodes! {
    /// Copy one operand to another.
    Copy = 1, "COPY", "COPY";
    /// Load from a pointer into a specified address space.
    Load = 2, "LOAD", "LOAD";
    /// Store at a pointer into a specified address space.
    Store = 3, "STORE", "STORE";
    /// Always branch.
    Branch = 4, "BRANCH", "BRANCH";
    /// Conditional branch.
    CBranch = 5, "CBRANCH", "CBRANCH";
    /// Indirect branch (jump table).
    BranchInd = 6, "BRANCHIND", "BRANCHIND";
    /// Call to an absolute address.
    Call = 7, "CALL", "CALL";
    /// Call through an indirect address.
    CallInd = 8, "CALLIND", "CALLIND";
    /// User-defined operation.
    CallOther = 9, "CALLOTHER", "CALLOTHER";
    /// Return from subroutine.
    Return = 10, "RETURN", "RETURN";
    /// Integer comparison, equality (`==`).
    IntEqual = 11, "INT_EQUAL", "INT_EQUAL";
    /// Integer comparison, inequality (`!=`).
    IntNotEqual = 12, "INT_NOTEQUAL", "INT_NOTEQUAL";
    /// Integer comparison, signed less-than (`<`).
    IntSLess = 13, "INT_SLESS", "INT_SLESS";
    /// Integer comparison, signed less-than-or-equal (`<=`).
    IntSLessEqual = 14, "INT_SLESSEQUAL", "INT_SLESSEQUAL";
    /// Integer comparison, unsigned less-than (`<`).
    IntLess = 15, "INT_LESS", "INT_LESS";
    /// Integer comparison, unsigned less-than-or-equal (`<=`).
    IntLessEqual = 16, "INT_LESSEQUAL", "INT_LESSEQUAL";
    /// Zero extension.
    IntZExt = 17, "INT_ZEXT", "INT_ZEXT";
    /// Sign extension.
    IntSExt = 18, "INT_SEXT", "INT_SEXT";
    /// Addition, signed or unsigned (`+`).
    IntAdd = 19, "INT_ADD", "INT_ADD";
    /// Subtraction, signed or unsigned (`-`).
    IntSub = 20, "INT_SUB", "INT_SUB";
    /// Test for unsigned carry.
    IntCarry = 21, "INT_CARRY", "INT_CARRY";
    /// Test for signed carry.
    IntSCarry = 22, "INT_SCARRY", "INT_SCARRY";
    /// Test for signed borrow.
    IntSBorrow = 23, "INT_SBORROW", "INT_SBORROW";
    /// Twos complement.
    Int2Comp = 24, "INT_2COMP", "INT_2COMP";
    /// Bitwise negation (`~`).
    IntNegate = 25, "INT_NEGATE", "INT_NEGATE";
    /// Bitwise exclusive-or (`^`).
    IntXor = 26, "INT_XOR", "INT_XOR";
    /// Bitwise and (`&`).
    IntAnd = 27, "INT_AND", "INT_AND";
    /// Bitwise or (`|`).
    IntOr = 28, "INT_OR", "INT_OR";
    /// Left shift (`<<`).
    IntLeft = 29, "INT_LEFT", "INT_LEFT";
    /// Right shift, logical (`>>`).
    IntRight = 30, "INT_RIGHT", "INT_RIGHT";
    /// Right shift, arithmetic (`>>`).
    IntSRight = 31, "INT_SRIGHT", "INT_SRIGHT";
    /// Integer multiplication, signed and unsigned (`*`).
    IntMult = 32, "INT_MULT", "INT_MULT";
    /// Integer division, unsigned (`/`).
    IntDiv = 33, "INT_DIV", "INT_DIV";
    /// Integer division, signed (`/`).
    IntSDiv = 34, "INT_SDIV", "INT_SDIV";
    /// Remainder, unsigned (`%`).
    IntRem = 35, "INT_REM", "INT_REM";
    /// Remainder, signed (`%`).
    IntSRem = 36, "INT_SREM", "INT_SREM";
    /// Boolean negate (`!`).
    BoolNegate = 37, "BOOL_NEGATE", "BOOL_NEGATE";
    /// Boolean exclusive-or (`^^`).
    BoolXor = 38, "BOOL_XOR", "BOOL_XOR";
    /// Boolean and (`&&`).
    BoolAnd = 39, "BOOL_AND", "BOOL_AND";
    /// Boolean or (`||`).
    BoolOr = 40, "BOOL_OR", "BOOL_OR";
    /// Floating-point comparison, equality (`==`).
    FloatEqual = 41, "FLOAT_EQUAL", "FLOAT_EQUAL";
    /// Floating-point comparison, inequality (`!=`).
    FloatNotEqual = 42, "FLOAT_NOTEQUAL", "FLOAT_NOTEQUAL";
    /// Floating-point comparison, less-than (`<`).
    FloatLess = 43, "FLOAT_LESS", "FLOAT_LESS";
    /// Floating-point comparison, less-than-or-equal (`<=`).
    FloatLessEqual = 44, "FLOAT_LESSEQUAL", "FLOAT_LESSEQUAL";
    /// Not-a-number test.
    FloatNan = 46, "FLOAT_NAN", "FLOAT_NAN";
    /// Floating-point addition (`+`).
    FloatAdd = 47, "FLOAT_ADD", "FLOAT_ADD";
    /// Floating-point division (`/`).
    FloatDiv = 48, "FLOAT_DIV", "FLOAT_DIV";
    /// Floating-point multiplication (`*`).
    FloatMult = 49, "FLOAT_MULT", "FLOAT_MULT";
    /// Floating-point subtraction (`-`).
    FloatSub = 50, "FLOAT_SUB", "FLOAT_SUB";
    /// Floating-point negation (`-`).
    FloatNeg = 51, "FLOAT_NEG", "FLOAT_NEG";
    /// Floating-point absolute value.
    FloatAbs = 52, "FLOAT_ABS", "FLOAT_ABS";
    /// Floating-point square root.
    FloatSqrt = 53, "FLOAT_SQRT", "FLOAT_SQRT";
    /// Convert an integer to floating point.
    FloatInt2Float = 54, "INT2FLOAT", "INT2FLOAT";
    /// Convert between floating-point sizes.
    FloatFloat2Float = 55, "FLOAT2FLOAT", "FLOAT2FLOAT";
    /// Convert floating point to integer, rounding towards zero.
    FloatTrunc = 56, "TRUNC", "TRUNC";
    /// Round towards positive infinity.
    FloatCeil = 57, "CEIL", "CEIL";
    /// Round towards negative infinity.
    FloatFloor = 58, "FLOOR", "FLOOR";
    /// Round towards nearest.
    FloatRound = 59, "ROUND", "ROUND";
    /// Phi-node operator.
    MultiEqual = 60, "BUILD", "MULTIEQUAL";
    /// Copy with an indirect effect.
    Indirect = 61, "DELAY_SLOT", "INDIRECT";
    /// Concatenate.
    Piece = 62, "PIECE", "PIECE";
    /// Truncate.
    SubPiece = 63, "SUBPIECE", "SUBPIECE";
    /// Cast from one data-type to another.
    Cast = 64, "CAST", "CAST";
    /// Index into an array (`[]`).
    PtrAdd = 65, "LABEL", "PTRADD";
    /// Drill down to a sub-field (`->`).
    PtrSub = 66, "CROSSBUILD", "PTRSUB";
    /// Look up a segmented address.
    SegmentOp = 67, "SEGMENTOP", "SEGMENTOP";
    /// Recover a value from the constant pool.
    CPoolRef = 68, "CPOOLREF", "CPOOLREF";
    /// Allocate a new object.
    New = 69, "NEW", "NEW";
    /// Insert a bit-range.
    Insert = 70, "INSERT", "INSERT";
    /// Extract an unsigned bit-range.
    ZPull = 71, "ZPULL", "ZPULL";
    /// Count the 1-bits.
    PopCount = 72, "POPCOUNT", "POPCOUNT";
    /// Count the leading 0-bits.
    LzCount = 73, "LZCOUNT", "LZCOUNT";
    /// Extract a signed bit-range.
    SPull = 74, "SPULL", "SPULL";
}

impl OpCode {
    /// The number of p-code operations.
    pub const COUNT: usize = 73;

    /// One past the largest numeric value (`CPUI_MAX`, `PCODE_MAX`).
    pub const MAX: u8 = 75;

    /// The numeric value Ghidra assigns to the operation.
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Looks an operation up by its C++ name ([`OpCode::name`]), as Ghidra's
    /// `get_opcode` does.
    ///
    /// Unknown names give `None` where the C++ returns the value 0. The C++
    /// also maps `"UNUSED1"` to the unused slot 45; that is not an operation
    /// and gives `None` here.
    pub fn from_name(name: &str) -> Option<OpCode> {
        OpCode::ALL.iter().copied().find(|op| op.name() == name)
    }

    /// Looks an operation up by its Java mnemonic ([`OpCode::mnemonic`]), as
    /// Ghidra's `PcodeOp.getOpcode` does.
    ///
    /// Like the Java table this also accepts the four template directives
    /// `BUILD`, `DELAY_SLOT`, `LABEL` and `CROSSBUILD`. Unknown mnemonics give
    /// `None` where the Java throws `UnknownInstructionException`; so do the
    /// Java table's two entries that are not operations (`UNIMPLEMENTED` = 0
    /// and `INVALID_OP` = 45).
    pub fn from_mnemonic(mnemonic: &str) -> Option<OpCode> {
        OpCode::ALL
            .iter()
            .copied()
            .find(|op| op.mnemonic() == mnemonic || op.name() == mnemonic)
    }

    /// The complementary comparison: the operation that produces the opposite
    /// boolean on the same inputs, and whether the inputs must be swapped to
    /// get it (Ghidra's `TypeOp::getBooleanFlip` and `isBooleanFlipReorder`).
    ///
    /// `None` for operations that have no complement (Ghidra's `CPUI_MAX`).
    pub const fn boolean_flip(self) -> Option<BooleanFlip> {
        let (opcode, reorder) = match self {
            OpCode::IntEqual => (OpCode::IntNotEqual, false),
            OpCode::IntNotEqual => (OpCode::IntEqual, false),
            OpCode::IntSLess => (OpCode::IntSLessEqual, true),
            OpCode::IntSLessEqual => (OpCode::IntSLess, true),
            OpCode::IntLess => (OpCode::IntLessEqual, true),
            OpCode::IntLessEqual => (OpCode::IntLess, true),
            OpCode::BoolNegate => (OpCode::Copy, false),
            OpCode::FloatEqual => (OpCode::FloatNotEqual, false),
            OpCode::FloatNotEqual => (OpCode::FloatEqual, false),
            OpCode::FloatLess => (OpCode::FloatLessEqual, true),
            OpCode::FloatLessEqual => (OpCode::FloatLess, true),
            _ => return None,
        };
        Some(BooleanFlip { opcode, reorder })
    }

    /// Whether the operation is evaluated through the unary interface
    /// (`OpBehavior::isUnary`).
    pub const fn is_unary(self) -> bool {
        matches!(
            self,
            OpCode::Copy
                | OpCode::IntZExt
                | OpCode::IntSExt
                | OpCode::Int2Comp
                | OpCode::IntNegate
                | OpCode::BoolNegate
                | OpCode::FloatNan
                | OpCode::FloatNeg
                | OpCode::FloatAbs
                | OpCode::FloatSqrt
                | OpCode::FloatInt2Float
                | OpCode::FloatFloat2Float
                | OpCode::FloatTrunc
                | OpCode::FloatCeil
                | OpCode::FloatFloor
                | OpCode::FloatRound
                | OpCode::PopCount
                | OpCode::LzCount
        )
    }

    /// Whether the operation is neither a normal unary nor a normal binary
    /// operation and needs special handling to emulate
    /// (`OpBehavior::isSpecial`).
    pub const fn is_special(self) -> bool {
        matches!(
            self,
            OpCode::Load
                | OpCode::Store
                | OpCode::Branch
                | OpCode::CBranch
                | OpCode::BranchInd
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::CallOther
                | OpCode::Return
                | OpCode::MultiEqual
                | OpCode::Indirect
                | OpCode::Cast
                | OpCode::SegmentOp
                | OpCode::CPoolRef
                | OpCode::New
        )
    }
}

/// The complement of a boolean-valued operation; see [`OpCode::boolean_flip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BooleanFlip {
    /// The complementary operation.
    pub opcode: OpCode,
    /// Whether the two inputs must be swapped for the complement to hold.
    pub reorder: bool,
}

impl fmt::Display for OpCode {
    /// Writes the C++ name ([`OpCode::name`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<OpCode> for u8 {
    fn from(op: OpCode) -> u8 {
        op.value()
    }
}

impl TryFrom<u8> for OpCode {
    type Error = OpCodeError;

    fn try_from(value: u8) -> Result<OpCode, OpCodeError> {
        OpCode::from_u8(value).ok_or(OpCodeError::UnknownValue(value))
    }
}

impl core::str::FromStr for OpCode {
    type Err = OpCodeError;

    /// Parses a C++ name ([`OpCode::from_name`]).
    fn from_str(name: &str) -> Result<OpCode, OpCodeError> {
        OpCode::from_name(name).ok_or_else(|| OpCodeError::UnknownName(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `opcode_name` from `opcodes.cc`, indexed by numeric value.
    const CPP_NAMES: [&str; 75] = [
        "BLANK",
        "COPY",
        "LOAD",
        "STORE",
        "BRANCH",
        "CBRANCH",
        "BRANCHIND",
        "CALL",
        "CALLIND",
        "CALLOTHER",
        "RETURN",
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "INT_SLESS",
        "INT_SLESSEQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_ZEXT",
        "INT_SEXT",
        "INT_ADD",
        "INT_SUB",
        "INT_CARRY",
        "INT_SCARRY",
        "INT_SBORROW",
        "INT_2COMP",
        "INT_NEGATE",
        "INT_XOR",
        "INT_AND",
        "INT_OR",
        "INT_LEFT",
        "INT_RIGHT",
        "INT_SRIGHT",
        "INT_MULT",
        "INT_DIV",
        "INT_SDIV",
        "INT_REM",
        "INT_SREM",
        "BOOL_NEGATE",
        "BOOL_XOR",
        "BOOL_AND",
        "BOOL_OR",
        "FLOAT_EQUAL",
        "FLOAT_NOTEQUAL",
        "FLOAT_LESS",
        "FLOAT_LESSEQUAL",
        "UNUSED1",
        "FLOAT_NAN",
        "FLOAT_ADD",
        "FLOAT_DIV",
        "FLOAT_MULT",
        "FLOAT_SUB",
        "FLOAT_NEG",
        "FLOAT_ABS",
        "FLOAT_SQRT",
        "INT2FLOAT",
        "FLOAT2FLOAT",
        "TRUNC",
        "CEIL",
        "FLOOR",
        "ROUND",
        "BUILD",
        "DELAY_SLOT",
        "PIECE",
        "SUBPIECE",
        "CAST",
        "LABEL",
        "CROSSBUILD",
        "SEGMENTOP",
        "CPOOLREF",
        "NEW",
        "INSERT",
        "ZPULL",
        "POPCOUNT",
        "LZCOUNT",
        "SPULL",
    ];

    /// `PcodeOp.getMnemonic` for the values where it differs from the C++ name.
    const JAVA_DIFFERENCES: [(u8, &str); 4] = [
        (60, "MULTIEQUAL"),
        (61, "INDIRECT"),
        (65, "PTRADD"),
        (66, "PTRSUB"),
    ];

    #[test]
    fn values_and_names_match_opcodes_cc() {
        let mut seen = 0;
        for (value, name) in CPP_NAMES.iter().enumerate() {
            let value = u8::try_from(value).unwrap();
            match OpCode::from_u8(value) {
                Some(op) => {
                    seen += 1;
                    assert_eq!(op.value(), value);
                    assert_eq!(op.name(), *name);
                    assert_eq!(op.to_string(), *name);
                    assert_eq!(OpCode::from_name(name), Some(op));
                    assert_eq!(name.parse::<OpCode>(), Ok(op));
                    assert_eq!(OpCode::try_from(value), Ok(op));
                    assert_eq!(u8::from(op), value);
                }
                None => assert!(value == 0 || value == 45, "value {value} missing"),
            }
        }
        assert_eq!(seen, OpCode::COUNT);
        assert_eq!(OpCode::ALL.len(), OpCode::COUNT);
        assert_eq!(CPP_NAMES.len(), usize::from(OpCode::MAX));
    }

    #[test]
    fn all_is_sorted_by_value() {
        assert!(
            OpCode::ALL
                .windows(2)
                .all(|pair| pair[0].value() < pair[1].value())
        );
        assert_eq!(OpCode::ALL[0], OpCode::Copy);
        assert_eq!(OpCode::ALL[OpCode::COUNT - 1], OpCode::SPull);
    }

    #[test]
    fn values_outside_the_table_are_rejected() {
        assert_eq!(OpCode::try_from(0), Err(OpCodeError::UnknownValue(0)));
        assert_eq!(OpCode::try_from(45), Err(OpCodeError::UnknownValue(45)));
        for value in OpCode::MAX..=u8::MAX {
            assert_eq!(OpCode::from_u8(value), None);
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        // The C++ returns 0 for these, and 45 for "UNUSED1".
        for name in [
            "",
            "BLANK",
            "UNUSED1",
            "copy",
            "INT_ADD ",
            "MULTIEQUAL",
            "PTRADD",
            "NOPE",
        ] {
            assert_eq!(OpCode::from_name(name), None, "{name}");
            assert_eq!(
                name.parse::<OpCode>(),
                Err(OpCodeError::UnknownName(name.to_owned()))
            );
        }
    }

    #[test]
    fn mnemonics_match_pcodeop_java() {
        for op in OpCode::ALL {
            let expected = JAVA_DIFFERENCES
                .iter()
                .find(|(value, _)| *value == op.value())
                .map_or(op.name(), |(_, mnemonic)| mnemonic);
            assert_eq!(op.mnemonic(), expected);
            assert_eq!(OpCode::from_mnemonic(op.mnemonic()), Some(op));
            // The Java table also holds the template directive names.
            assert_eq!(OpCode::from_mnemonic(op.name()), Some(op));
        }
        for mnemonic in [
            "UNIMPLEMENTED",
            "INVALID_OP",
            "UNUSED1",
            "BLANK",
            "",
            "int_add",
        ] {
            assert_eq!(OpCode::from_mnemonic(mnemonic), None, "{mnemonic}");
        }
    }

    #[test]
    fn boolean_flips_match_typeop_cc() {
        use OpCode::{
            BoolNegate, Copy, FloatEqual, FloatLess, FloatLessEqual, FloatNotEqual, IntEqual,
            IntLess, IntLessEqual, IntNotEqual, IntSLess, IntSLessEqual,
        };
        let table = [
            (IntEqual, IntNotEqual, false),
            (IntNotEqual, IntEqual, false),
            (IntSLess, IntSLessEqual, true),
            (IntSLessEqual, IntSLess, true),
            (IntLess, IntLessEqual, true),
            (IntLessEqual, IntLess, true),
            (BoolNegate, Copy, false),
            (FloatEqual, FloatNotEqual, false),
            (FloatNotEqual, FloatEqual, false),
            (FloatLess, FloatLessEqual, true),
            (FloatLessEqual, FloatLess, true),
        ];
        for op in OpCode::ALL {
            let expected = table
                .iter()
                .find(|(from, _, _)| *from == op)
                .map(|&(_, opcode, reorder)| BooleanFlip { opcode, reorder });
            assert_eq!(op.boolean_flip(), expected, "{op}");
        }
        // A comparison's flip flips back, except BOOL_NEGATE whose flip is COPY.
        for (from, to, _) in table {
            if from != BoolNegate {
                assert_eq!(to.boolean_flip().map(|flip| flip.opcode), Some(from));
            }
        }
    }

    #[test]
    fn classification_matches_register_instructions() {
        let unary = [
            1, 17, 18, 24, 25, 37, 46, 51, 52, 53, 54, 55, 56, 57, 58, 59, 72, 73,
        ];
        let special = [2, 3, 4, 5, 6, 7, 8, 9, 10, 60, 61, 64, 67, 68, 69];
        for op in OpCode::ALL {
            assert_eq!(op.is_unary(), unary.contains(&op.value()), "{op}");
            assert_eq!(op.is_special(), special.contains(&op.value()), "{op}");
            assert!(!(op.is_unary() && op.is_special()));
        }
    }
}
