//! The result of elaboration: everything a compiled language holds except
//! what is derived from bit patterns (operand offsets and order, minimum
//! lengths, decision trees), with the symbol ids of the `.sla` file.

use bk_sleigh_syntax::{Interner, Span};

use crate::diag::Diagnostic;
use crate::ids::{CtorId, EquationId, OperandId, ScopeId, SymbolId, TableId};
use crate::pattern::PatternArena;
use crate::spaces::SpaceInfo;
use crate::symbols::{OperandData, SymbolData};
use crate::template::Tpl;

pub use crate::compiler::{ContextChange, Piece as PrintPiece};

/// What [`crate::elaborate`] returns.
#[derive(Debug)]
pub struct Outcome {
    /// Every diagnostic, in the order found.
    pub diagnostics: Vec<Diagnostic>,
    /// The elaborated specification, if there was no error.
    pub spec: Option<Elaborated>,
}

/// A table of constructors (`SubtableSymbol`).
#[derive(Clone, Debug)]
pub struct Table {
    /// The table's symbol.
    pub symbol: SymbolId,
    /// Its constructors, in index order.
    pub constructors: Vec<CtorId>,
}

/// A constructor.
#[derive(Clone, Debug)]
pub struct Constructor {
    /// The table it belongs to.
    pub table: TableId,
    /// Index of its source file in [`Elaborated::source_files`].
    pub source: u32,
    /// Line of its `:`.
    pub line: u32,
    /// Where its `:` is in the preprocessed text.
    pub at: Span,
    /// Its operands in parse order (display operands, then invisible ones).
    pub operands: Vec<OperandId>,
    /// Its print pieces; an operand piece holds a parse-order index.
    pub print: Vec<PrintPiece>,
    /// Index of the first white-space print piece, or −1.
    pub first: i32,
    /// Its pattern equation, with the enclosing `with` patterns.
    pub equation: Option<EquationId>,
    /// Its context changes, the enclosing `with` blocks' first.
    pub context: Vec<ContextChange>,
    /// The main template, unless the body is `unimpl`.
    pub main: Option<Tpl>,
    /// Named-section templates by section number.
    pub sections: Vec<Option<Tpl>>,
}

/// A specification after elaboration.
#[derive(Clone, Debug)]
pub struct Elaborated {
    /// Byte order of the language.
    pub big_endian: bool,
    /// Instruction alignment.
    pub align: i32,
    /// First unique offset not used by the specification's temporaries.
    pub unique_base: u32,
    /// Largest delay-slot byte count.
    pub max_delay: u32,
    /// Address bits folded into temporaries (0xff with `crossbuild`).
    pub unique_mask: u32,
    /// Number of named sections.
    pub num_sections: u32,
    /// The spaces, by index (0 is the constant space).
    pub spaces: Vec<SpaceInfo>,
    /// The default code space.
    pub default_space: u32,
    /// Source files, by index.
    pub source_files: Vec<String>,
    /// The parent of each scope (`None` for the global scope).
    pub scopes: Vec<Option<ScopeId>>,
    /// The symbols, by final id. Operand symbols refer to
    /// [`Self::operands`]; ids inside kinds are final ids.
    pub symbols: Vec<SymbolData>,
    /// The names of symbols.
    pub names: Interner,
    /// Operand data, by [`OperandId`] (including operands whose symbol was
    /// purged: their `symbol` is `SymbolId(u32::MAX)`).
    pub operands: Vec<OperandData>,
    /// The tables written to the file (reachable from `instruction`),
    /// root first, by [`TableId`].
    pub tables: Vec<Table>,
    /// The constructors of those tables, by [`CtorId`].
    pub constructors: Vec<Constructor>,
    /// Pattern expressions and equations.
    pub patterns: PatternArena,
}

impl Elaborated {
    /// A symbol's name.
    pub fn symbol_name(&self, id: SymbolId) -> &str {
        self.symbols
            .get(id.slot())
            .map_or("", |s| self.names.resolve(s.name))
    }

    /// The root table's symbol (`instruction`).
    pub fn root(&self) -> Option<SymbolId> {
        self.tables.first().map(|t| t.symbol)
    }
}
