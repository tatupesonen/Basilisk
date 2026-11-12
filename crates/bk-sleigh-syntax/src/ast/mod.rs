//! The syntax tree.
//!
//! The tree is symbol-free, like the one Ghidra's `SleighParser.g` builds:
//! identifiers stay identifiers, and whether one names a register, a field,
//! a table or a macro is for the compiler to decide. Every node carries a
//! [`Span`]. Names, string contents and print pieces are [`Symbol`]s of the
//! parse's [`Interner`](crate::Interner).
//!
//! The recursive parts (semantic expressions, pattern expressions, pattern
//! equations) live in arenas inside [`Nodes`] and refer to each other by
//! typed `u32` ids, so the tree is plain data that is cheap to build, walk
//! and drop. Everything else is ordinary structs, enums and `Vec`s.

mod definitions;
pub mod dump;
mod nodes;
mod pattern;
pub mod print;
mod semantic;

pub use definitions::{
    AlignmentDef, AttachNames, AttachValues, AttachVariables, BitrangeDef, BitrangeEntry,
    ContextDef, Definition, EndianDef, FieldDef, FieldDisplay, IdentOrWild, IntOrWild, NameOrWild,
    PcodeOpDef, SpaceDef, SpaceMod, TokenDef, VarnodeDef,
};
pub use nodes::{EquationId, ExprId, ExprList, Nodes, PatExprId, PatExprList};
pub use pattern::{
    ConstraintOp, ContextBlock, ContextStmt, Equation, EquationOp, PatBinaryOp, PatExpr, PatUnaryOp,
};
pub use semantic::{
    BinaryOp, ExportValue, Expr, JumpDest, LValue, SemanticBody, SizedStar, Statement, UnaryOp,
};

use crate::intern::Symbol;
use num_bigint::BigUint;

use crate::lex::literal::{IntValue, Radix};
use crate::span::Span;

/// An identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ident {
    /// The name.
    pub name: Symbol,
    /// Where it is written.
    pub span: Span,
}

/// A quoted string.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StrLit {
    /// The text between the quotes, exactly as written: Ghidra does not
    /// interpret the escape sequences its lexer accepts, and neither does
    /// the parser.
    pub value: Symbol,
    /// The literal including its quotes.
    pub span: Span,
}

/// An integer literal.
///
/// The value is exact at any width. Values that fit in 64 bits (every
/// literal in Ghidra's shipped specifications) are stored inline with the
/// radix packed beside them, so a literal is 24 bytes; wider values are
/// boxed. Literals are the bulk of the larger expression and statement
/// nodes, so their size is what keeps [`Expr`] and [`Statement`] small.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IntLit {
    repr: IntRepr,
    /// Where it is written.
    pub span: Span,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum IntRepr {
    Small { radix: Radix, value: u64 },
    Wide { radix: Radix, value: Box<BigUint> },
}

impl IntLit {
    /// A literal with `value` written in `radix` at `span`.
    pub fn new(value: IntValue, radix: Radix, span: Span) -> Self {
        let repr = match value.into_parts() {
            Ok(value) => IntRepr::Small { radix, value },
            Err(value) => IntRepr::Wide { radix, value },
        };
        Self { repr, span }
    }

    /// The exact value. Clones the boxed digits of a wide value.
    pub fn value(&self) -> IntValue {
        match &self.repr {
            IntRepr::Small { value, .. } => IntValue::from_parts(Ok(*value)),
            IntRepr::Wide { value, .. } => IntValue::from_parts(Err(value)),
        }
    }

    /// The value, if it fits in 64 bits.
    pub const fn to_u64(&self) -> Option<u64> {
        match &self.repr {
            IntRepr::Small { value, .. } => Some(*value),
            IntRepr::Wide { .. } => None,
        }
    }

    /// The radix the literal was written in (`0n` literals are decimal).
    pub const fn radix(&self) -> Radix {
        match &self.repr {
            IntRepr::Small { radix, .. } | IntRepr::Wide { radix, .. } => *radix,
        }
    }

    /// The value written in its radix with its prefix: `0x1f`, `0b101`, `31`.
    pub fn to_source(&self) -> String {
        let prefix = match self.radix() {
            Radix::Hex => "0x",
            Radix::Binary => "0b",
            Radix::Decimal => "",
        };
        let digits = match &self.repr {
            IntRepr::Small { value, radix } => IntValue::from_u64(*value).to_string_radix(*radix),
            IntRepr::Wide { value, radix } => value.to_str_radix(radix.base()),
        };
        format!("{prefix}{digits}")
    }
}

/// Byte order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Endian {
    /// `big`.
    Big,
    /// `little`.
    Little,
}

/// A whole specification.
#[derive(Clone, Debug, Default)]
pub struct Spec {
    /// The `define endian` statement. Ghidra requires it to be the first
    /// statement; the parser reports an error if it is missing or late.
    pub endian: Option<EndianDef>,
    /// Everything else, in source order.
    pub items: Vec<Item>,
    /// Storage for the expression and pattern nodes the items refer to.
    pub nodes: Nodes,
}

/// A top-level statement, or a statement inside a `with` block.
#[derive(Clone, Debug)]
pub enum Item {
    /// A `define ...;` or `attach ...;` statement.
    Definition(Definition),
    /// A `macro`.
    Macro(MacroDef),
    /// A `with` block.
    With(WithBlock),
    /// A constructor.
    Constructor(Constructor),
}

impl Item {
    /// The extent of the item.
    pub fn span(&self) -> Span {
        match self {
            Self::Definition(d) => d.span(),
            Self::Macro(m) => m.span,
            Self::With(w) => w.span,
            Self::Constructor(c) => c.span,
        }
    }
}

/// `macro name(a, b) { ... }`.
#[derive(Clone, Debug)]
pub struct MacroDef {
    /// The macro's name.
    pub name: Ident,
    /// Its parameters.
    pub params: Vec<Ident>,
    /// Its body.
    pub body: SemanticBody,
    /// The whole definition.
    pub span: Span,
}

/// `with table : pattern [context] { ... }`.
///
/// The table, pattern and context changes are prefixed to every constructor
/// inside the block; blocks nest.
#[derive(Clone, Debug)]
pub struct WithBlock {
    /// The table the enclosed constructors belong to by default.
    pub table: Option<Ident>,
    /// A pattern and-ed onto each enclosed constructor's pattern.
    pub pattern: Option<EquationId>,
    /// Context changes prefixed to each enclosed constructor's.
    pub context: Option<ContextBlock>,
    /// The enclosed definitions, macros, blocks and constructors.
    pub items: Vec<Item>,
    /// The whole block.
    pub span: Span,
}

/// A constructor: `table:display is pattern [context] { semantics }`.
#[derive(Clone, Debug)]
pub struct Constructor {
    /// The table name before the `:`; `None` for the root `instruction`
    /// table (or the table of an enclosing `with` block).
    pub table: Option<Ident>,
    /// Where the `:` that starts the display section is.
    pub colon: Span,
    /// The print pieces between `:` and `is`, whitespace included.
    pub display: Vec<DisplayPiece>,
    /// The bit pattern.
    pub pattern: EquationId,
    /// The `[ ... ]` context block, if present.
    pub context: Option<ContextBlock>,
    /// The semantic section or `unimpl`.
    pub body: ConstructorBody,
    /// The whole constructor.
    pub span: Span,
}

/// One piece of a display section.
///
/// Adjacent pieces are concatenated in the printed instruction. An
/// identifier may turn out to be an operand, or (first in the root table)
/// the mnemonic; every other piece prints literally.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DisplayPiece {
    /// An identifier.
    Ident(Ident),
    /// A run of spaces, tabs and line breaks. It prints as one space, and
    /// Ghidra ignores it when it is the very first piece.
    Whitespace(Span),
    /// `^`: separates two pieces without printing anything.
    Concat(Span),
    /// Punctuation or a number, printed as written.
    Literal {
        /// The text.
        text: Symbol,
        /// Where it is written.
        span: Span,
    },
    /// A quoted string; its content prints as written.
    Quoted(StrLit),
}

impl DisplayPiece {
    /// The extent of the piece.
    pub fn span(&self) -> Span {
        match self {
            Self::Ident(i) => i.span,
            Self::Whitespace(s) | Self::Concat(s) => *s,
            Self::Literal { span, .. } => *span,
            Self::Quoted(s) => s.span,
        }
    }
}

/// What a constructor does.
#[derive(Clone, Debug)]
pub enum ConstructorBody {
    /// `unimpl`: the instruction is recognised but has no semantics.
    Unimpl(Span),
    /// `{ ... }`.
    Semantic(SemanticBody),
}

impl ConstructorBody {
    /// The extent of the body.
    pub fn span(&self) -> Span {
        match self {
            Self::Unimpl(span) => *span,
            Self::Semantic(body) => body.span,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    /// ADR-012: hot node types stay small. A change that grows one of these
    /// should be deliberate (and update `docs/PERF.md`).
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn hot_node_sizes() {
        assert_eq!(size_of::<IntLit>(), 24);
        assert_eq!(size_of::<Ident>(), 12);
        assert_eq!(size_of::<Expr>(), 72);
        assert_eq!(size_of::<Statement>(), 88);
        assert_eq!(size_of::<PatExpr>(), 32);
        assert_eq!(size_of::<Equation>(), 36);
        assert_eq!(size_of::<DisplayPiece>(), 16);
        assert_eq!(size_of::<ContextStmt>(), 36);
    }

    #[test]
    fn int_lit_keeps_value_and_radix_at_any_width() {
        let small = IntLit::new(IntValue::from_u64(0x1f), Radix::Hex, Span::new(0, 4));
        assert_eq!(small.to_u64(), Some(31));
        assert_eq!(small.radix(), Radix::Hex);
        assert_eq!(small.to_source(), "0x1f");
        assert_eq!(small.value(), IntValue::from_u64(31));

        let digits = "123456789abcdef0fedcba9876543210";
        let wide_value = IntValue::parse(digits, Radix::Hex).unwrap();
        let wide = IntLit::new(wide_value.clone(), Radix::Hex, Span::new(0, 34));
        assert_eq!(wide.to_u64(), None);
        assert_eq!(wide.value(), wide_value);
        assert_eq!(wide.to_source(), format!("0x{digits}"));
        assert_eq!(
            IntLit::new(IntValue::from_u64(5), Radix::Binary, Span::default()).to_source(),
            "0b101"
        );
    }
}
