//! Semantic sections: the p-code statement language.

use super::{ExprId, ExprList, Ident, IntLit};
use crate::span::Span;

/// A `{ ... }` semantic section, or a standalone p-code snippet.
#[derive(Clone, Debug, Default)]
pub struct SemanticBody {
    /// The statements in order. Named sections are introduced by
    /// [`Statement::Section`] markers; see [`Self::sections`].
    pub statements: Vec<Statement>,
    /// The whole body, braces included.
    pub span: Span,
}

impl SemanticBody {
    /// Splits the body at its `<<name>>` markers: first the unnamed main
    /// section (possibly empty), then each named section with its name.
    pub fn sections(&self) -> impl Iterator<Item = (Option<Ident>, &[Statement])> {
        let mut rest: &[Statement] = &self.statements;
        let mut name = None;
        let mut done = false;
        std::iter::from_fn(move || {
            if done {
                return None;
            }
            let split = rest
                .iter()
                .position(|s| matches!(s, Statement::Section { .. }));
            let current = name;
            if let Some(at) = split {
                let (head, tail) = rest.split_at(at);
                if let Some((Statement::Section { name: next, .. }, after)) = tail.split_first() {
                    name = Some(*next);
                    rest = after;
                }
                Some((current, head))
            } else {
                done = true;
                Some((current, rest))
            }
        })
    }
}

/// The `*` of a dereference with its optional space and size:
/// `*`, `*:4`, `*[ram]`, `*[ram]:4`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SizedStar {
    /// The address space in brackets, if given.
    pub space: Option<Ident>,
    /// The size in bytes after the colon, if given.
    pub size: Option<IntLit>,
    /// From the `*` to the end of the size.
    pub span: Span,
}

/// Where a `goto`, `call` or conditional branch goes.
#[derive(Clone, Debug)]
pub enum JumpDest {
    /// A name: an operand, `inst_next`, a label-like symbol.
    Symbol(Ident),
    /// `[expression]`: an address computed at run time.
    Dynamic(ExprId),
    /// A constant address in the current code space.
    Absolute(IntLit),
    /// `offset[space]`: a constant address in a named space.
    Relative {
        /// The address.
        offset: IntLit,
        /// The space.
        space: Ident,
    },
    /// `<label>`: a label inside this section.
    Label(Ident),
}

/// The target of an assignment.
#[derive(Clone, Debug)]
pub enum LValue {
    /// `name`.
    Ident(Ident),
    /// `name:size`: declares a temporary of that size.
    Sized {
        /// The temporary's name.
        name: Ident,
        /// Its size in bytes.
        size: IntLit,
    },
    /// `name[low, width]`: a bit range of a varnode.
    BitRange {
        /// The varnode.
        name: Ident,
        /// The least significant bit.
        low: IntLit,
        /// The number of bits.
        width: IntLit,
    },
    /// `*[space]:size address`: a store.
    Deref {
        /// The star with its space and size.
        star: SizedStar,
        /// The address stored to.
        address: ExprId,
    },
}

/// What a constructor exports.
#[derive(Clone, Debug)]
pub enum ExportValue {
    /// `export varnode;` (a name, a sized constant, an address-of).
    Varnode(ExprId),
    /// `export *[space]:size name;`: a dynamic (memory) operand.
    Deref {
        /// The star with its space and size.
        star: SizedStar,
        /// The name holding the address.
        name: Ident,
    },
}

/// One statement of a semantic section.
#[derive(Clone, Debug)]
pub enum Statement {
    /// `target = value;` or `local target = value;`.
    Assign {
        /// The statement starts with `local`.
        local: bool,
        /// The assignment target.
        target: LValue,
        /// Where the `=` is written.
        op_span: Span,
        /// The value assigned.
        value: ExprId,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `local name;` or `local name:size;`.
    Declare {
        /// The temporary's name.
        name: Ident,
        /// Its size in bytes, if given.
        size: Option<IntLit>,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `name(args);`: a user-defined operation or macro invocation whose
    /// result is not used, or a built-in such as `delayslot(1)`.
    Apply {
        /// The operation or macro.
        name: Ident,
        /// The arguments.
        args: ExprList,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `build operand;`.
    Build {
        /// The operand whose semantics are placed here.
        operand: Ident,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `crossbuild address, section;`.
    CrossBuild {
        /// The address of the instruction whose section is built.
        address: ExprId,
        /// The named section.
        section: Ident,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `goto dest;`.
    Goto {
        /// The destination.
        dest: JumpDest,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `if (condition) goto dest;`.
    If {
        /// The condition.
        condition: ExprId,
        /// The destination when the condition holds.
        dest: JumpDest,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `call dest;`.
    Call {
        /// The destination.
        dest: JumpDest,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `return [target];`.
    Return {
        /// The address returned to.
        target: ExprId,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `export value;`.
    Export {
        /// The exported value.
        value: ExportValue,
        /// The whole statement without its `;`.
        span: Span,
    },
    /// `<name>`: a branch target.
    Label {
        /// The label's name.
        name: Ident,
        /// The label with its angle brackets.
        span: Span,
    },
    /// `<<name>>`: starts a named section.
    Section {
        /// The section's name.
        name: Ident,
        /// The marker with its angle brackets.
        span: Span,
    },
    /// A placeholder where a syntax error was reported.
    Error(Span),
}

impl Statement {
    /// The extent of the statement.
    pub fn span(&self) -> Span {
        match self {
            Statement::Assign { span, .. }
            | Statement::Declare { span, .. }
            | Statement::Apply { span, .. }
            | Statement::Build { span, .. }
            | Statement::CrossBuild { span, .. }
            | Statement::Goto { span, .. }
            | Statement::If { span, .. }
            | Statement::Call { span, .. }
            | Statement::Return { span, .. }
            | Statement::Export { span, .. }
            | Statement::Label { span, .. }
            | Statement::Section { span, .. }
            | Statement::Error(span) => *span,
        }
    }
}

/// A unary operator of semantic expressions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UnaryOp {
    /// `!`: boolean negation.
    Not,
    /// `~`: bitwise complement.
    Invert,
    /// `-`: two's complement.
    Negate,
    /// `f-`: floating-point negation.
    FNegate,
}

/// A binary operator of semantic expressions.
///
/// Precedence, loosest first (`slghparse.y`, `SemanticParser.g`):
/// `||`; `&&` `^^`; `|`; `^`; `&`; equality; comparison; shifts; additive;
/// multiplicative. All are left-associative.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BinaryOp {
    /// `||`
    BoolOr,
    /// `&&`
    BoolAnd,
    /// `^^`
    BoolXor,
    /// `|`
    Or,
    /// `^`
    Xor,
    /// `&`
    And,
    /// `==`
    Equal,
    /// `!=`
    NotEqual,
    /// `f==`
    FEqual,
    /// `f!=`
    FNotEqual,
    /// `<`
    Less,
    /// `>=`
    GreatEqual,
    /// `<=`
    LessEqual,
    /// `>`
    Great,
    /// `s<`
    SLess,
    /// `s>=`
    SGreatEqual,
    /// `s<=`
    SLessEqual,
    /// `s>`
    SGreat,
    /// `f<`
    FLess,
    /// `f>=`
    FGreatEqual,
    /// `f<=`
    FLessEqual,
    /// `f>`
    FGreat,
    /// `<<`
    Left,
    /// `>>`
    Right,
    /// `s>>`
    SRight,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `f+`
    FAdd,
    /// `f-`
    FSub,
    /// `*`
    Mult,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// `s/`
    SDiv,
    /// `s%`
    SRem,
    /// `f*`
    FMult,
    /// `f/`
    FDiv,
}

impl BinaryOp {
    /// The operator as written in source.
    pub const fn as_str(self) -> &'static str {
        match self {
            BinaryOp::BoolOr => "||",
            BinaryOp::BoolAnd => "&&",
            BinaryOp::BoolXor => "^^",
            BinaryOp::Or => "|",
            BinaryOp::Xor => "^",
            BinaryOp::And => "&",
            BinaryOp::Equal => "==",
            BinaryOp::NotEqual => "!=",
            BinaryOp::FEqual => "f==",
            BinaryOp::FNotEqual => "f!=",
            BinaryOp::Less => "<",
            BinaryOp::GreatEqual => ">=",
            BinaryOp::LessEqual => "<=",
            BinaryOp::Great => ">",
            BinaryOp::SLess => "s<",
            BinaryOp::SGreatEqual => "s>=",
            BinaryOp::SLessEqual => "s<=",
            BinaryOp::SGreat => "s>",
            BinaryOp::FLess => "f<",
            BinaryOp::FGreatEqual => "f>=",
            BinaryOp::FLessEqual => "f<=",
            BinaryOp::FGreat => "f>",
            BinaryOp::Left => "<<",
            BinaryOp::Right => ">>",
            BinaryOp::SRight => "s>>",
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::FAdd => "f+",
            BinaryOp::FSub => "f-",
            BinaryOp::Mult => "*",
            BinaryOp::Div => "/",
            BinaryOp::Rem => "%",
            BinaryOp::SDiv => "s/",
            BinaryOp::SRem => "s%",
            BinaryOp::FMult => "f*",
            BinaryOp::FDiv => "f/",
        }
    }

    /// Binding strength: a higher number binds tighter. Operators with the
    /// same number associate to the left.
    pub const fn precedence(self) -> u8 {
        match self {
            BinaryOp::BoolOr => 1,
            BinaryOp::BoolAnd | BinaryOp::BoolXor => 2,
            BinaryOp::Or => 3,
            BinaryOp::Xor => 4,
            BinaryOp::And => 5,
            BinaryOp::Equal | BinaryOp::NotEqual | BinaryOp::FEqual | BinaryOp::FNotEqual => 6,
            BinaryOp::Less
            | BinaryOp::GreatEqual
            | BinaryOp::LessEqual
            | BinaryOp::Great
            | BinaryOp::SLess
            | BinaryOp::SGreatEqual
            | BinaryOp::SLessEqual
            | BinaryOp::SGreat
            | BinaryOp::FLess
            | BinaryOp::FGreatEqual
            | BinaryOp::FLessEqual
            | BinaryOp::FGreat => 7,
            BinaryOp::Left | BinaryOp::Right | BinaryOp::SRight => 8,
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::FAdd | BinaryOp::FSub => 9,
            BinaryOp::Mult
            | BinaryOp::Div
            | BinaryOp::Rem
            | BinaryOp::SDiv
            | BinaryOp::SRem
            | BinaryOp::FMult
            | BinaryOp::FDiv => 10,
        }
    }
}

/// A semantic expression.
#[derive(Clone, Debug)]
pub enum Expr {
    /// An integer constant.
    Int(IntLit),
    /// A name.
    Ident(Ident),
    /// `value:size`: a constant of an explicit size in bytes.
    SizedInt {
        /// The constant.
        value: IntLit,
        /// Its size in bytes.
        size: IntLit,
    },
    /// `name:size`: the low `size` bytes of a varnode.
    Truncate {
        /// The varnode.
        name: Ident,
        /// The number of bytes kept.
        size: IntLit,
    },
    /// `name[low, width]`: a bit range of a varnode.
    BitRange {
        /// The varnode.
        name: Ident,
        /// The least significant bit.
        low: IntLit,
        /// The number of bits.
        width: IntLit,
        /// The whole expression.
        span: Span,
    },
    /// `&operand` or `&:size operand`: the address of a varnode.
    AddressOf {
        /// The size of the resulting address in bytes, if given.
        size: Option<IntLit>,
        /// The varnode whose address is taken.
        operand: ExprId,
        /// The whole expression.
        span: Span,
    },
    /// `( inner )`.
    Paren {
        /// The parenthesised expression.
        inner: ExprId,
        /// The whole expression, parentheses included.
        span: Span,
    },
    /// `name(args)`: a built-in operator (`zext`, `carry`, ...), a
    /// user-defined operation, a macro, or `varnode(n)` (drop the low `n`
    /// bytes). The compiler tells them apart by what `name` is.
    Apply {
        /// The function name.
        name: Ident,
        /// The arguments.
        args: ExprList,
        /// The whole call.
        span: Span,
    },
    /// `op operand`.
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: ExprId,
        /// The whole expression.
        span: Span,
    },
    /// `*[space]:size operand`: a load.
    Deref {
        /// The star with its space and size.
        star: SizedStar,
        /// The address loaded from.
        operand: ExprId,
        /// The whole expression.
        span: Span,
    },
    /// `lhs op rhs`.
    Binary {
        /// The operator.
        op: BinaryOp,
        /// Left operand.
        lhs: ExprId,
        /// Right operand.
        rhs: ExprId,
        /// Where the operator is written.
        op_span: Span,
        /// The whole expression.
        span: Span,
    },
    /// A placeholder where a syntax error was reported.
    Error(Span),
}

impl Expr {
    /// The extent of the expression.
    pub fn span(&self) -> Span {
        match self {
            Expr::Int(lit) => lit.span,
            Expr::Ident(ident) => ident.span,
            Expr::SizedInt { value, size } => value.span.to(size.span),
            Expr::Truncate { name, size } => name.span.to(size.span),
            Expr::BitRange { span, .. }
            | Expr::AddressOf { span, .. }
            | Expr::Paren { span, .. }
            | Expr::Apply { span, .. }
            | Expr::Unary { span, .. }
            | Expr::Deref { span, .. }
            | Expr::Binary { span, .. }
            | Expr::Error(span) => *span,
        }
    }
}
