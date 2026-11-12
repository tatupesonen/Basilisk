//! `define` and `attach` statements.

use super::{Endian, Ident, IntLit, StrLit};
use crate::span::Span;

/// `define endian = big;`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndianDef {
    /// The byte order.
    pub endian: Endian,
    /// The whole statement.
    pub span: Span,
}

/// A `define ...;` or `attach ...;` statement.
#[derive(Clone, Debug)]
pub enum Definition {
    /// `define alignment = 2;`
    Alignment(AlignmentDef),
    /// `define token name (16) ...;`
    Token(TokenDef),
    /// `define context reg ...;`
    Context(ContextDef),
    /// `define space ram type=ram_space size=4 default;`
    Space(SpaceDef),
    /// `define register offset=0 size=4 [r0 r1];`
    Varnode(VarnodeDef),
    /// `define bitrange zf=flags[0,1];`
    Bitrange(BitrangeDef),
    /// `define pcodeop name;`
    PcodeOp(PcodeOpDef),
    /// `attach values [fields] [1 2 3];`
    AttachValues(AttachValues),
    /// `attach names [fields] ["a" b _];`
    AttachNames(AttachNames),
    /// `attach variables [fields] [r0 r1 _];`
    AttachVariables(AttachVariables),
}

impl Definition {
    /// The extent of the statement, up to but not including its `;`.
    pub fn span(&self) -> Span {
        match self {
            Definition::Alignment(d) => d.span,
            Definition::Token(d) => d.span,
            Definition::Context(d) => d.span,
            Definition::Space(d) => d.span,
            Definition::Varnode(d) => d.span,
            Definition::Bitrange(d) => d.span,
            Definition::PcodeOp(d) => d.span,
            Definition::AttachValues(d) => d.span,
            Definition::AttachNames(d) => d.span,
            Definition::AttachVariables(d) => d.span,
        }
    }
}

/// `define alignment = n;`
#[derive(Clone, Debug)]
pub struct AlignmentDef {
    /// The instruction alignment in bytes.
    pub value: IntLit,
    /// The whole statement.
    pub span: Span,
}

/// `define token name (size) [endian=...] field=(lo,hi) ...;`
#[derive(Clone, Debug)]
pub struct TokenDef {
    /// The token's name.
    pub name: Ident,
    /// Its size in bits.
    pub size: IntLit,
    /// Its byte order, if it overrides the specification's.
    pub endian: Option<Endian>,
    /// Its fields.
    pub fields: Vec<FieldDef>,
    /// The whole statement.
    pub span: Span,
}

/// How a field's value is displayed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FieldDisplay {
    /// `hex`.
    Hex,
    /// `dec`.
    Dec,
}

/// One field of a token or of the context register: `name = (lo, hi) mods`.
#[derive(Clone, Debug)]
pub struct FieldDef {
    /// The field's name.
    pub name: Ident,
    /// The first of the two bit positions.
    pub low: IntLit,
    /// The second of the two bit positions.
    pub high: IntLit,
    /// The `signed` modifier was given.
    pub signed: bool,
    /// The `noflow` modifier was given (context fields only).
    pub noflow: bool,
    /// The last `hex` or `dec` modifier given, if any.
    pub display: Option<FieldDisplay>,
    /// The whole field definition.
    pub span: Span,
}

/// `define context reg field=(lo,hi) ...;`
#[derive(Clone, Debug)]
pub struct ContextDef {
    /// The register that holds the context.
    pub varnode: Ident,
    /// The context fields.
    pub fields: Vec<FieldDef>,
    /// The whole statement.
    pub span: Span,
}

/// `define space name mods...;`
#[derive(Clone, Debug)]
pub struct SpaceDef {
    /// The space's name.
    pub name: Ident,
    /// Its modifiers, in source order (a later one overrides an earlier).
    pub mods: Vec<SpaceMod>,
    /// The whole statement.
    pub span: Span,
}

/// One modifier of a `define space`.
#[derive(Clone, Debug)]
pub enum SpaceMod {
    /// `type = ram_space`.
    Type(Ident),
    /// `size = 4`: address size in bytes.
    Size(IntLit),
    /// `wordsize = 1`: bytes per addressable unit.
    WordSize(IntLit),
    /// `default`.
    Default(Span),
}

/// An identifier or the `_` placeholder.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IdentOrWild {
    /// A name.
    Ident(Ident),
    /// `_`.
    Wildcard(Span),
}

impl IdentOrWild {
    /// The extent of the entry.
    pub fn span(&self) -> Span {
        match self {
            IdentOrWild::Ident(i) => i.span,
            IdentOrWild::Wildcard(s) => *s,
        }
    }
}

/// `define space offset=o size=s [names];`
#[derive(Clone, Debug)]
pub struct VarnodeDef {
    /// The address space the varnodes live in.
    pub space: Ident,
    /// Offset of the first varnode.
    pub offset: IntLit,
    /// Size of each varnode in bytes.
    pub size: IntLit,
    /// The names, consecutive in the space; `_` skips a slot.
    pub names: Vec<IdentOrWild>,
    /// The whole statement.
    pub span: Span,
}

/// `define bitrange a=reg[lo,width] ...;`
#[derive(Clone, Debug)]
pub struct BitrangeDef {
    /// The ranges defined.
    pub entries: Vec<BitrangeEntry>,
    /// The whole statement.
    pub span: Span,
}

/// One entry of a `define bitrange`: `name = varnode[lo, width]`.
#[derive(Clone, Debug)]
pub struct BitrangeEntry {
    /// The new name.
    pub name: Ident,
    /// The varnode it is a part of.
    pub varnode: Ident,
    /// The least significant bit.
    pub low: IntLit,
    /// The number of bits.
    pub width: IntLit,
    /// The whole entry.
    pub span: Span,
}

/// `define pcodeop name;` or `define pcodeop [a b];`
#[derive(Clone, Debug)]
pub struct PcodeOpDef {
    /// The operation names.
    pub names: Vec<IdentOrWild>,
    /// The whole statement.
    pub span: Span,
}

/// An integer (possibly negated) or the `_` placeholder.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum IntOrWild {
    /// An integer, written with a leading `-` if `negative`.
    Int {
        /// A `-` precedes the literal.
        negative: bool,
        /// The literal.
        value: IntLit,
    },
    /// `_`.
    Wildcard(Span),
}

/// `attach values [fields] [values];`
#[derive(Clone, Debug)]
pub struct AttachValues {
    /// The fields the values are attached to.
    pub fields: Vec<IdentOrWild>,
    /// The value for each encoding of the field; `_` marks an invalid one.
    pub values: Vec<IntOrWild>,
    /// The whole statement.
    pub span: Span,
}

/// A name, a quoted name or the `_` placeholder.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum NameOrWild {
    /// A bare name.
    Ident(Ident),
    /// A quoted name.
    Str(StrLit),
    /// `_`.
    Wildcard(Span),
}

/// `attach names [fields] [names];`
#[derive(Clone, Debug)]
pub struct AttachNames {
    /// The fields the names are attached to.
    pub fields: Vec<IdentOrWild>,
    /// The name printed for each encoding; `_` marks an invalid one.
    pub names: Vec<NameOrWild>,
    /// The whole statement.
    pub span: Span,
}

/// `attach variables [fields] [varnodes];`
#[derive(Clone, Debug)]
pub struct AttachVariables {
    /// The fields the varnodes are attached to.
    pub fields: Vec<IdentOrWild>,
    /// The varnode selected by each encoding; `_` marks an invalid one.
    pub varnodes: Vec<IdentOrWild>,
    /// The whole statement.
    pub span: Span,
}
