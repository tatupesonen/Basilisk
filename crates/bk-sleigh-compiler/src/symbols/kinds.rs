//! What a symbol is (`SleighSymbol::symbol_type` and the data of each
//! subclass, `slghsymbol.hh`).

use bk_sleigh_syntax::Symbol as Name;

use crate::ids::{CtorId, MacroId, OperandId, PExprId, SymbolId, TableId};
use crate::pattern::PatValue;

/// A fixed varnode: space index, offset and size (`VarnodeData`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarnodeData {
    /// The space's index.
    pub space: u32,
    /// The offset.
    pub offset: u64,
    /// The size in bytes.
    pub size: i32,
}

/// What a symbol is, with its data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolKind {
    /// A table of constructors.
    Subtable(TableId),
    /// An address space, by index.
    Space(u32),
    /// A token (index into the compiler's token table).
    Token(u32),
    /// A user-defined p-code op and its index.
    UserOp(u32),
    /// A field used as a number.
    Value(PatValue),
    /// A field with `attach values`.
    ValueMap(PatValue, Vec<i64>),
    /// A field with `attach names`; `None` marks an unusable entry (`_`).
    Name(PatValue, Vec<Option<String>>),
    /// A field with `attach variables`; `None` marks an unusable entry.
    VarnodeList(PatValue, Vec<Option<SymbolId>>),
    /// A fixed varnode (register or temporary).
    Varnode(VarnodeData),
    /// A context field.
    Context {
        /// The context register's varnode symbol.
        varnode: SymbolId,
        /// Low bit within the register as written.
        low: u32,
        /// High bit within the register as written.
        high: u32,
        /// Whether changes flow to following instructions.
        flow: bool,
        /// The packed field.
        field: PatValue,
    },
    /// A bit range of a varnode that is not byte aligned.
    Bitrange {
        /// The varnode it is part of.
        varnode: SymbolId,
        /// The least significant bit.
        offset: u32,
        /// The number of bits.
        bits: u32,
    },
    /// An operand of a constructor, or a macro parameter.
    Operand(OperandId),
    /// `inst_start`.
    Start,
    /// `inst_next`.
    End,
    /// `inst_next2`.
    Next2,
    /// `epsilon`.
    Epsilon,
    /// A macro.
    Macro(MacroId),
    /// A label of a p-code section.
    Label {
        /// Its number within the section.
        index: u32,
        /// Whether it has been placed.
        placed: bool,
        /// How many branches refer to it.
        refs: u32,
    },
    /// A named p-code section and its number.
    Section(u32),
}

impl SymbolKind {
    /// The field of a value-like symbol (`FamilySymbol::getPatternValue`).
    pub fn pattern_value(&self) -> Option<PatValue> {
        match self {
            Self::Value(v)
            | Self::ValueMap(v, _)
            | Self::Name(v, _)
            | Self::VarnodeList(v, _)
            | Self::Context { field: v, .. } => Some(*v),
            _ => None,
        }
    }

    /// Whether the symbol is a family symbol (value, value map, context,
    /// name, varnode list).
    pub fn is_family(&self) -> bool {
        self.pattern_value().is_some()
    }

    /// Whether the symbol is a specific symbol in the grammar's sense
    /// (`specificsymbol`: varnode, epsilon, operand, start/end/next2).
    pub fn is_specific(&self) -> bool {
        matches!(
            self,
            Self::Varnode(_)
                | Self::Epsilon
                | Self::Operand(_)
                | Self::Start
                | Self::End
                | Self::Next2
        )
    }
}

/// One symbol.
#[derive(Clone, Debug)]
pub struct SymbolData {
    /// The name.
    pub name: Name,
    /// The scope it was added to.
    pub scope: crate::ids::ScopeId,
    /// What it is.
    pub kind: SymbolKind,
    /// Where it was defined (Ghidra's `symbolLocationMap`), if known.
    pub defined_at: Option<bk_sleigh_syntax::Span>,
}

/// An operand symbol's data (`OperandSymbol`).
#[derive(Clone, Debug)]
pub struct OperandData {
    /// The symbol.
    pub symbol: SymbolId,
    /// Its index in the constructor (parse order) or macro.
    pub index: u32,
    /// The constructor it belongs to (`None` for a macro parameter).
    pub ctor: Option<CtorId>,
    /// The defining expression (`defexp`), if any.
    pub def_expr: Option<PExprId>,
    /// The defining symbol (`triple`), if any.
    pub def_symbol: Option<SymbolId>,
    /// Used as a code address (a branch destination).
    pub code: bool,
    /// Defined in the context block (`setOffsetIrrelevant`).
    pub offset_irrelevant: bool,
    /// Its own value (`localexp`): an [`crate::pattern::PExpr::Operand`].
    pub local_expr: PExprId,
}

impl OperandData {
    /// Whether the operand is defined by a symbol or an expression.
    pub fn is_defined(&self) -> bool {
        self.def_expr.is_some() || self.def_symbol.is_some()
    }
}
