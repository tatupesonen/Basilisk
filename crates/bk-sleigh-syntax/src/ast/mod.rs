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
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IntLit {
    /// The value.
    pub value: IntValue,
    /// The radix it was written in.
    pub radix: Radix,
    /// Where it is written.
    pub span: Span,
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
            Item::Definition(d) => d.span(),
            Item::Macro(m) => m.span,
            Item::With(w) => w.span,
            Item::Constructor(c) => c.span,
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
            DisplayPiece::Ident(i) => i.span,
            DisplayPiece::Whitespace(s) | DisplayPiece::Concat(s) => *s,
            DisplayPiece::Literal { span, .. } => *span,
            DisplayPiece::Quoted(s) => s.span,
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
            ConstructorBody::Unimpl(span) => *span,
            ConstructorBody::Semantic(body) => body.span,
        }
    }
}
