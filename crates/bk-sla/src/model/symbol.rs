//! The header, address spaces, scopes and symbols of a compiled language.

use super::handles::{ConstructorId, DecisionId, ExprId, ScopeId, Span, StrId, SymbolId};

/// The attributes of the `<sleigh>` element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Whether the language is big endian.
    pub big_endian: bool,
    /// Instruction alignment in bytes (1 = none).
    pub align: i32,
    /// First offset in the `unique` space not used by the specification's
    /// own temporaries.
    pub unique_base: u32,
    /// The largest number of delay-slot bytes any constructor asks for; 0 if
    /// none (the attribute is written only when it is not 0).
    pub max_delay: u32,
    /// Address bits folded into temporaries' offsets for `crossbuild`; 0 if
    /// the language does not use it (written only when not 0).
    pub unique_mask: u32,
    /// The number of named p-code sections (written only when not 0).
    pub num_sections: u32,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            big_endian: false,
            align: 1,
            unique_base: 0,
            max_delay: 0,
            unique_mask: 0,
            num_sections: 0,
        }
    }
}

/// Which element declared an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpaceKind {
    /// `<space>`: a processor space.
    Processor,
    /// `<space_unique>`: the temporary-register space.
    Unique,
    /// `<space_other>`: the `OTHER` space.
    Other,
}

impl SpaceKind {
    /// The element name.
    pub const fn element_name(self) -> &'static str {
        match self {
            Self::Processor => "space",
            Self::Unique => "space_unique",
            Self::Other => "space_other",
        }
    }
}

/// One address space as the file declares it.
///
/// Every attribute is kept as written so that the writer reproduces it, even
/// those Ghidra's loader ignores (the name, delay, size and physical flag of
/// the unique and other spaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceRecord {
    /// The element that declared the space.
    pub kind: SpaceKind,
    /// The space's name.
    pub name: StrId,
    /// The space's index; 0 is the constant space, which is not in the file.
    pub index: u32,
    /// The `bigendian` attribute (the compiler writes the language's
    /// endianness on every space).
    pub big_endian: bool,
    /// Heritage delay.
    pub delay: i32,
    /// Size of an offset in bytes.
    pub size: i32,
    /// Bytes per addressable unit (written only when above 1).
    pub word_size: i32,
    /// Whether the space is backed by physical memory.
    pub physical: bool,
}

/// One scope of the symbol table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// The enclosing scope; `None` for a root scope (the global scope, whose
    /// file record names itself as its parent).
    pub parent: Option<ScopeId>,
}

/// A symbol: its name, scope and content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// The name; read it with [`Sla::text`](crate::Sla::text).
    pub name: StrId,
    /// The scope the symbol belongs to.
    pub scope: ScopeId,
    /// What the symbol is.
    pub kind: SymbolKind,
}

/// What a symbol is, with its content (inventory section 1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolKind {
    /// `userop`: a `define pcodeop` name and its index.
    UserOp {
        /// The index `CALLOTHER` refers to it by.
        index: i32,
    },
    /// `value_sym`: a field used as a number.
    Value {
        /// The field.
        expr: ExprId,
    },
    /// `valuemap_sym`: a field with `attach values`.
    ValueMap {
        /// The field.
        expr: ExprId,
        /// The values, a run of [`Sla::value_table`](crate::Sla::value_table).
        table: Span,
    },
    /// `name_sym`: a field with `attach names`.
    Name {
        /// The field.
        expr: ExprId,
        /// The names, a run of [`Sla::name_table`](crate::Sla::name_table).
        table: Span,
    },
    /// `varnode_sym`: a register or other fixed varnode.
    Varnode {
        /// The space index.
        space: u32,
        /// The offset.
        offset: u64,
        /// The size in bytes.
        size: i32,
    },
    /// `context_sym`: a context field.
    Context {
        /// The context register's varnode symbol.
        varnode: SymbolId,
        /// Low bit of the field within the register.
        low: i32,
        /// High bit of the field within the register.
        high: i32,
        /// Whether changes flow to following instructions.
        flow: bool,
        /// The field expression.
        expr: ExprId,
    },
    /// `varlist_sym`: a field with `attach variables`.
    VarnodeList {
        /// The field.
        expr: ExprId,
        /// The registers, a run of
        /// [`Sla::varnode_table`](crate::Sla::varnode_table).
        table: Span,
    },
    /// `operand_sym`: one operand of one constructor.
    Operand(Operand),
    /// `start_sym`: `inst_start`.
    Start,
    /// `end_sym`: `inst_next`.
    End,
    /// `next2_sym`: `inst_next2`.
    Next2,
    /// `epsilon_sym`: the constant-0 symbol (never in a compiled file).
    Epsilon,
    /// `subtable_sym`: a table of constructors with its decision tree.
    Subtable(Subtable),
}

impl SymbolKind {
    /// The name of the symbol's body element.
    pub const fn element_name(&self) -> &'static str {
        match self {
            Self::UserOp { .. } => "userop",
            Self::Value { .. } => "value_sym",
            Self::ValueMap { .. } => "valuemap_sym",
            Self::Name { .. } => "name_sym",
            Self::Varnode { .. } => "varnode_sym",
            Self::Context { .. } => "context_sym",
            Self::VarnodeList { .. } => "varlist_sym",
            Self::Operand(_) => "operand_sym",
            Self::Start => "start_sym",
            Self::End => "end_sym",
            Self::Next2 => "next2_sym",
            Self::Epsilon => "epsilon_sym",
            Self::Subtable(_) => "subtable_sym",
        }
    }

    /// The field expression of a value-like symbol (value, value map, name,
    /// context, varnode list).
    pub const fn value_expr(&self) -> Option<ExprId> {
        match *self {
            Self::Value { expr }
            | Self::ValueMap { expr, .. }
            | Self::Name { expr, .. }
            | Self::Context { expr, .. }
            | Self::VarnodeList { expr, .. } => Some(expr),
            _ => None,
        }
    }

    /// Whether a symbol of this kind resolves to a fixed handle, so that a
    /// `commit` may name it (every kind except subtable and user op).
    pub const fn has_fixed_handle(&self) -> bool {
        !matches!(self, Self::Subtable(_) | Self::UserOp { .. })
    }
}

/// An operand symbol's content (inventory section 1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operand {
    /// Position in the constructor's operand list; also its handle index.
    pub index: i32,
    /// Byte offset of the operand's bytes from the constructor's start
    /// (`base == -1`) or from the end of operand `base`.
    pub offset: i32,
    /// The operand the offset is relative to, or −1.
    pub base: i32,
    /// Minimum length of the operand's own pattern in bytes.
    pub min_length: i32,
    /// Whether the operand is used as a code address.
    pub code: bool,
    /// The defining symbol, if the operand has one.
    pub defining_symbol: Option<SymbolId>,
    /// The `operand_exp` naming the operand itself.
    pub local_expr: ExprId,
    /// The defining expression, if the operand has one.
    pub defining_expr: Option<ExprId>,
}

/// A subtable's constructors and decision tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subtable {
    /// The constructors, in index order: constructor `i` is `first + i`.
    pub constructors: Span,
    /// The root of the decision tree.
    pub decision: DecisionId,
}

impl Subtable {
    /// The id of the subtable's constructor `index`, if it has one.
    pub fn constructor(&self, index: u32) -> Option<ConstructorId> {
        (index < self.constructors.len())
            .then(|| ConstructorId::new(self.constructors.start().wrapping_add(index)))
    }

    /// The number of constructors.
    pub const fn num_constructors(&self) -> u32 {
        self.constructors.len()
    }
}
