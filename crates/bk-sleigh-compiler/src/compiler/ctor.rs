//! Constructors (inventory 9.5; `SleighCompile::createConstructor`,
//! `newTable`, `buildConstructor`, `resetConstructors`).

use bk_sleigh_syntax::Span;
use bk_sleigh_syntax::ast::{Constructor, ConstructorBody, Ident};

use super::display::remove_trailing_space;
use super::{Compiler, CtorData, Fatal, TableData};
use crate::ids::{CtorId, EquationId, ScopeId, SymbolId, TableId};
use crate::pattern::Equation;
use crate::symbols::SymbolKind;

impl<'a> Compiler<'a> {
    /// `newTable`: a new subtable symbol and table.
    pub(crate) fn new_table(&mut self, ident: Ident) -> SymbolId {
        let table = TableId::next(self.tables.len());
        let symbol = self.add_symbol(ident.name, SymbolKind::Subtable(table), ident.span);
        self.tables.push(TableData {
            symbol,
            ctors: Vec::new(),
            at: Some(ident.span),
        });
        symbol
    }

    /// The table a `TABLE:` names: an existing table or a new one; `None`
    /// (after a syntax error) for any other symbol.
    pub(crate) fn table_named(&mut self, ident: Ident) -> Option<SymbolId> {
        match self.lookup(ident.name) {
            None => Some(self.new_table(ident)),
            Some(id) if matches!(self.kind(id), Some(SymbolKind::Subtable(_))) => Some(id),
            Some(_) => {
                self.syntax_error(ident.span);
                None
            }
        }
    }

    /// The table of a table symbol.
    pub(crate) fn table_of(&self, symbol: SymbolId) -> Option<TableId> {
        match self.kind(symbol) {
            Some(SymbolKind::Subtable(t)) => Some(*t),
            _ => None,
        }
    }

    /// One constructor, from `:` to the end of its body.
    pub(crate) fn constructor(&mut self, c: &'a Constructor) -> Result<(), Fatal> {
        self.lock_context_at(c.colon);
        let table_symbol = match c.table {
            Some(ident) => match self.table_named(ident) {
                Some(t) => t,
                None => return Ok(()),
            },
            None => self
                .with_stack
                .iter()
                .find_map(|w| w.table)
                .or_else(|| self.tables.first().map(|t| t.symbol))
                .unwrap_or(SymbolId(0)),
        };
        let table = self.table_of(table_symbol).unwrap_or(TableId(0));
        let ctor = self.create_constructor(table, c.colon);
        let in_root = table == TableId(0);
        let built = self.constructor_parts(ctor, c, in_root);
        if self.fatal {
            return Err(Fatal);
        }
        if built.is_err() {
            // `error '}'`: Ghidra's parser recovers at the end of the body
            // and returns to the global scope.
            self.symbols.set_current(ScopeId::GLOBAL);
        }
        self.cur_ctor = None;
        Ok(())
    }

    /// `createConstructor`.
    fn create_constructor(&mut self, table: TableId, colon: Span) -> CtorId {
        let (line, file) = match self.parsed.sources.locate(colon.start) {
            Some(loc) => (
                loc.line,
                self.parsed
                    .sources
                    .file(loc.file)
                    .map_or_else(String::new, |f| f.name().to_owned()),
            ),
            None => (0, String::new()),
        };
        let source = self.indexer.index(&file);
        let id = CtorId::next(self.ctors.len());
        self.ctors.push(CtorData {
            table,
            line,
            source,
            at: colon,
            operands: Vec::new(),
            print: Vec::new(),
            first: -1,
            equation: None,
            context: Vec::new(),
            main: None,
            named: Vec::new(),
        });
        if let Some(t) = self.tables.get_mut(table.slot()) {
            t.ctors.push(id);
        }
        self.cur_macro = None;
        self.cur_ctor = Some(id);
        if self.symbols.add_scope().is_err() {
            self.diags.error(Some(colon), "Too many scopes");
            self.fatal = true;
        }
        id
    }

    /// Display, pattern, context block and body of a constructor, then
    /// `buildConstructor`. `Err` means the parser abandoned it.
    fn constructor_parts(&mut self, ctor: CtorId, c: &'a Constructor, in_root: bool) -> Result<(), ()> {
        if !self.display(ctor, &c.display, in_root) {
            return Err(());
        }
        let equation = self.equation(c.pattern).map_err(|_| ())?;
        let context = match &c.context {
            Some(block) => self.context_block(block).map_err(|_| ())?,
            None => Vec::new(),
        };
        let sections = match &c.body {
            ConstructorBody::Unimpl(_) => None,
            ConstructorBody::Semantic(body) => Some(self.sections(body).map_err(|_| ())?),
        };
        self.build_constructor(ctor, equation, context, sections);
        Ok(())
    }

    /// `buildConstructor`.
    fn build_constructor(&mut self, ctor: CtorId, equation: EquationId, context: Vec<super::ContextChange>, sections: Option<super::sections::Sections>) {
        let mut ok = true;
        if let Some(sections) = sections {
            match self.finalize_sections(ctor, sections) {
                Some((main, named)) => {
                    if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                        c.main = Some(main);
                        c.named = named;
                    }
                }
                None => ok = false,
            }
        }
        if ok {
            let mut equation = equation;
            let frames: Vec<Option<EquationId>> = self.with_stack.iter().map(|w| w.pattern).collect();
            for pattern in frames.into_iter().flatten() {
                equation = self.patterns.equation(Equation::And(pattern, equation));
            }
            let mut changes: Vec<super::ContextChange> = self
                .with_stack
                .iter()
                .flat_map(|w| w.context.iter().copied())
                .collect();
            changes.extend(context);
            if let Some(c) = self.ctors.get_mut(ctor.slot()) {
                c.equation = Some(equation);
                remove_trailing_space(c);
                c.context = changes;
            }
        }
        self.symbols.pop_scope();
    }
}
