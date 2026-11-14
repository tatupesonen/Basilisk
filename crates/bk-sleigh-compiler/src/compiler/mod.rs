//! The elaborator's state (`SleighCompile`) and the walk over the syntax
//! tree in Ghidra's order (spec 4.1).

mod context_layout;
mod ctor;
mod define;
mod display;
mod finalize;
mod macros;
mod pattern_atoms;
mod pexpr;
mod resolver;
mod sections;
mod with;

use std::sync::Arc;

use bk_sleigh_syntax::ast::Item;
use bk_sleigh_syntax::{Interner, Parsed, SourceFileIndexer, Span, Symbol as Name};

use crate::diag::Diagnostics;
use crate::ids::{CtorId, EquationId, MacroId, OperandId, PExprId, ScopeId, SymbolId, TableId};
use crate::options::Options;
use crate::pattern::{PExpr, PatternArena};
use crate::pcode::BuildEnv;
use crate::spaces::SpaceInfo;
use crate::symbols::{AddError, OperandData, SymbolKind, SymbolTable};
use crate::template::Tpl;

/// A print piece while constructors are built: text, or an operand by
/// index (`Constructor::printpiece`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Literal text.
    Text(String),
    /// Operand `n` (parse order).
    Operand(u32),
}

/// A context change (`ContextOp`, `ContextCommit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextChange {
    /// Set bits of the local context.
    Op {
        /// The context word.
        word: i32,
        /// Left shift of the value.
        shift: i32,
        /// The bits written.
        mask: u32,
        /// The value.
        expr: PExprId,
    },
    /// `globalset`: commit bits to the context database.
    Commit {
        /// The symbol giving the address.
        symbol: SymbolId,
        /// The context word.
        word: i32,
        /// The bits committed.
        mask: u32,
        /// Whether the change flows.
        flow: bool,
    },
}

/// A constructor while the specification is elaborated.
#[derive(Clone, Debug)]
pub(crate) struct CtorData {
    pub(crate) table: TableId,
    pub(crate) line: u32,
    pub(crate) source: u32,
    pub(crate) at: Span,
    pub(crate) operands: Vec<OperandId>,
    pub(crate) print: Vec<Piece>,
    pub(crate) first: i32,
    pub(crate) equation: Option<EquationId>,
    pub(crate) context: Vec<ContextChange>,
    pub(crate) main: Option<Tpl>,
    pub(crate) named: Vec<Option<Tpl>>,
}

/// A table (`SubtableSymbol`).
#[derive(Clone, Debug)]
pub(crate) struct TableData {
    pub(crate) symbol: SymbolId,
    pub(crate) ctors: Vec<CtorId>,
    pub(crate) at: Option<Span>,
}

/// A token (`Token`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct TokenData {
    pub(crate) size: u32,
    pub(crate) big_endian: bool,
}

/// A context field waiting for the layout (`FieldContext`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingField {
    pub(crate) varnode: SymbolId,
    pub(crate) name: Name,
    pub(crate) low: u64,
    pub(crate) high: u64,
    pub(crate) signed: bool,
    pub(crate) flow: bool,
}

/// A macro (`MacroSymbol`).
#[derive(Clone, Debug)]
pub(crate) struct MacroData {
    pub(crate) symbol: SymbolId,
    /// The index the macro is called by: the size of the macro table when
    /// it was defined (`MacroSymbol::index`).
    pub(crate) index: u32,
    pub(crate) params: Vec<OperandId>,
}

/// An enclosing `with` block (`WithBlock`).
#[derive(Clone, Debug)]
pub(crate) struct WithFrame {
    pub(crate) table: Option<SymbolId>,
    pub(crate) pattern: Option<EquationId>,
    pub(crate) context: Vec<ContextChange>,
}

/// The elaborator.
pub(crate) struct Compiler<'a> {
    pub(crate) parsed: &'a Parsed,
    pub(crate) names: Interner,
    pub(crate) options: Options,
    pub(crate) diags: Diagnostics,
    pub(crate) symbols: SymbolTable,
    pub(crate) spaces: Vec<SpaceInfo>,
    pub(crate) default_space: Option<u32>,
    pub(crate) big_endian: bool,
    pub(crate) align: i32,
    pub(crate) tokens: Vec<TokenData>,
    pub(crate) pending_context: Vec<PendingField>,
    pub(crate) context_locked: bool,
    pub(crate) userop_count: u32,
    pub(crate) unique_base: u32,
    pub(crate) crossbuild: bool,
    pub(crate) tables: Vec<TableData>,
    pub(crate) ctors: Vec<CtorData>,
    pub(crate) operands: Vec<OperandData>,
    pub(crate) patterns: PatternArena,
    pub(crate) macros: Vec<MacroData>,
    /// The macro table: templates of the macros that compiled, by index.
    pub(crate) macro_templates: Vec<Tpl>,
    pub(crate) sections: Vec<SymbolId>,
    pub(crate) with_stack: Vec<WithFrame>,
    pub(crate) nops: Vec<Span>,
    pub(crate) max_delay: u32,
    pub(crate) indexer: SourceFileIndexer,
    pub(crate) cur_ctor: Option<CtorId>,
    pub(crate) cur_macro: Option<MacroId>,
    /// Set by an error that aborts Ghidra's whole compile.
    pub(crate) fatal: bool,
    env: Option<Arc<BuildEnv>>,
}

/// The elaboration was stopped by an unrecoverable error.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fatal;

impl<'a> Compiler<'a> {
    pub(crate) fn new(parsed: &'a Parsed, options: Options) -> Self {
        Self {
            parsed,
            names: parsed.names.clone(),
            options,
            diags: Diagnostics::default(),
            symbols: SymbolTable::default(),
            spaces: Vec::new(),
            default_space: None,
            big_endian: false,
            align: 1,
            tokens: Vec::new(),
            pending_context: Vec::new(),
            context_locked: false,
            userop_count: 0,
            unique_base: 0,
            crossbuild: false,
            tables: Vec::new(),
            ctors: Vec::new(),
            operands: Vec::new(),
            patterns: PatternArena::default(),
            macros: Vec::new(),
            macro_templates: Vec::new(),
            sections: Vec::new(),
            with_stack: Vec::new(),
            nops: Vec::new(),
            max_delay: 0,
            indexer: SourceFileIndexer::new(),
            cur_ctor: None,
            cur_macro: None,
            fatal: false,
            env: None,
        }
    }

    /// Walks the whole specification.
    pub(crate) fn run(&mut self) {
        let parsed = self.parsed;
        let big = parsed
            .spec
            .endian
            .is_some_and(|e| e.endian == bk_sleigh_syntax::ast::Endian::Big);
        self.predefined_symbols(big, parsed.spec.endian.map(|e| e.span));
        if self.items(&parsed.spec.items).is_err() {
            self.fatal = true;
        }
    }

    /// Walks items in source order.
    pub(crate) fn items(&mut self, items: &'a [Item]) -> Result<(), Fatal> {
        for item in items {
            match item {
                Item::Definition(def) => self.definition(def),
                Item::Macro(m) => self.macro_def(m)?,
                Item::With(w) => self.with_block(w)?,
                Item::Constructor(c) => self.constructor(c)?,
            }
        }
        Ok(())
    }

    /// `setEndian` / `predefinedSymbols`.
    fn predefined_symbols(&mut self, big_endian: bool, at: Option<Span>) {
        self.big_endian = big_endian;
        let _ = self.symbols.add_scope();
        self.spaces.push(SpaceInfo::constant());
        self.spaces.push(SpaceInfo::other());
        self.spaces.push(SpaceInfo::unique(big_endian));
        let instruction = self.intern("instruction");
        let root = self.raw_add(instruction, SymbolKind::Subtable(TableId(0)), None);
        self.tables.push(TableData {
            symbol: root,
            ctors: Vec::new(),
            at: None,
        });
        for (name, kind) in [
            ("const", SymbolKind::Space(0)),
            ("OTHER", SymbolKind::Space(1)),
            ("unique", SymbolKind::Space(2)),
            ("inst_start", SymbolKind::Start),
            ("inst_next", SymbolKind::End),
            ("inst_next2", SymbolKind::Next2),
            ("epsilon", SymbolKind::Epsilon),
        ] {
            let name = self.intern(name);
            self.raw_add(name, kind, at);
        }
    }

    /// Adds a symbol without reporting a duplicate (`symtab.addSymbol`).
    fn raw_add(&mut self, name: Name, kind: SymbolKind, at: Option<Span>) -> SymbolId {
        match self.symbols.add(name, kind, at) {
            Ok(id) | Err(AddError::Duplicate(id)) => id,
            Err(AddError::Full) => SymbolId(u32::MAX),
        }
    }

    /// `SleighCompile::addSymbol`: a duplicate name is reported, and the
    /// symbol keeps its id without being visible.
    pub(crate) fn add_symbol(&mut self, name: Name, kind: SymbolKind, at: Span) -> SymbolId {
        match self.symbols.add(name, kind, Some(at)) {
            Ok(id) => id,
            Err(AddError::Duplicate(id)) => {
                let message = format!("Duplicate symbol name: {}", self.names.resolve(name));
                self.diags.error(Some(at), message);
                id
            }
            Err(AddError::Full) => {
                self.diags.error(Some(at), "Too many symbols");
                self.fatal = true;
                SymbolId(u32::MAX)
            }
        }
    }

    /// Interns a name.
    pub(crate) fn intern(&mut self, text: &str) -> Name {
        self.names.intern(text)
    }

    /// The text of a name.
    pub(crate) fn text(&self, name: Name) -> &str {
        self.names.resolve(name)
    }

    /// The kind of a symbol.
    pub(crate) fn kind(&self, id: SymbolId) -> Option<&SymbolKind> {
        self.symbols.kind(id)
    }

    /// The symbol a name refers to here.
    pub(crate) fn lookup(&self, name: Name) -> Option<SymbolId> {
        self.symbols.lookup(name)
    }

    /// The kind of what a name refers to here.
    pub(crate) fn lookup_kind(&self, name: Name) -> Option<&SymbolKind> {
        self.lookup(name).and_then(|id| self.kind(id))
    }

    /// Reports a parse error the C++ grammar raises because of a name's
    /// token class.
    pub(crate) fn syntax_error(&mut self, at: Span) {
        self.diags.error(Some(at), "syntax error");
    }

    /// `getUniqueAddr`: a temporary's offset; the counter advances by 256
    /// (`MAX_UNIQUE_SIZE`) and wraps as Ghidra's 32-bit counter does.
    pub(crate) fn unique_addr(&mut self) -> u64 {
        let base = self.unique_base;
        self.unique_base = base.wrapping_add(256);
        u64::from(base)
    }

    /// Adds an expression node.
    pub(crate) fn pexpr(&mut self, expr: PExpr) -> PExprId {
        self.patterns.expr(expr)
    }

    /// Creates an operand symbol in the current scope (`newOperand`,
    /// `defineInvisibleOperand`, macro parameters).
    pub(crate) fn new_operand(&mut self, name: Name, index: u32, ctor: Option<CtorId>, at: Span) -> OperandId {
        let id = OperandId::next(self.operands.len());
        let local_expr = self.pexpr(PExpr::Operand(id));
        let symbol = self.add_symbol(name, SymbolKind::Operand(id), at);
        self.operands.push(OperandData {
            symbol,
            index,
            ctor,
            def_expr: None,
            def_symbol: None,
            code: false,
            offset_irrelevant: false,
            local_expr,
        });
        id
    }

    /// The location of a constructor (`getLocation(ct)`).
    pub(crate) fn ctor_at(&self, ctor: CtorId) -> Span {
        self.ctors.get(ctor.slot()).map_or_else(Span::default, |c| c.at)
    }

    /// `Constructor::printInfo`.
    pub(crate) fn ctor_info(&self, ctor: CtorId) -> String {
        let Some(c) = self.ctors.get(ctor.slot()) else {
            return String::new();
        };
        let table = self
            .tables
            .get(c.table.slot())
            .and_then(|t| self.symbols.get(t.symbol))
            .map_or("", |s| self.names.resolve(s.name));
        format!("table \"{table}\" constructor starting at line {}", c.line)
    }

    /// The current scope.
    pub(crate) fn scope(&self) -> ScopeId {
        self.symbols.current()
    }

    /// The language facts the p-code builder needs, shared until a space
    /// is defined.
    pub(crate) fn build_env(&mut self) -> Arc<BuildEnv> {
        if let Some(env) = &self.env
            && env.spaces.len() == self.spaces.len()
            && env.default_space == self.default_space
        {
            return Arc::clone(env);
        }
        let env = Arc::new(BuildEnv {
            spaces: self.spaces.clone(),
            default_space: self.default_space,
            enforce_local_key: self.options.enforce_local_key,
        });
        self.env = Some(Arc::clone(&env));
        env
    }
}
