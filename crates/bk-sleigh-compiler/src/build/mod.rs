//! `buildPatterns` (inventory 10 c.1–c.4): the pattern of every table
//! reachable from `instruction`, depth first in constructor and operand
//! order, with each constructor's operand offsets and operand order, and
//! the diagnostics Ghidra gives for them.

mod constructor;
mod reorder;
mod trees;

use rustc_hash::FxHashMap;

use crate::compiler::Compiler;
use crate::equation::EqError;
use crate::ids::{CtorId, TableId};
use crate::pattern::{Tok, TokenPattern};
use crate::symbols::SymbolKind;

/// Deepest chain of tables built inside one another; deeper is an error
/// (specifications are untrusted input).
const MAX_TABLE_DEPTH: u32 = 256;

/// An operand's place after the reordering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperandLayout {
    /// The operand (new index) its offset is relative to, or −1.
    pub base: i32,
    /// Byte offset after the end of `base`, or from the constructor's start.
    pub offset: i32,
    /// Minimum length of the operand's own pattern in bytes.
    pub min_length: i32,
}

/// The results of the back half's passes, by the compiler's table and
/// constructor ids.
#[derive(Clone, Debug)]
pub(crate) struct BackHalf {
    pub(crate) state: BuildState,
    pub(crate) trees: Vec<Option<crate::decision::DecisionTree>>,
}

/// What a successfully built constructor yields.
#[derive(Clone, Debug)]
pub(crate) struct CtorResult {
    pub(crate) pattern: TokenPattern,
    pub(crate) min_length: i32,
    /// Per operand, by parse index.
    pub(crate) layout: Vec<OperandLayout>,
    /// New index of each operand, by parse index.
    pub(crate) handmap: Vec<u32>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TableState {
    pub(crate) pattern: Option<TokenPattern>,
    pub(crate) being_built: bool,
    pub(crate) error: bool,
}

/// The state of `buildPatterns`.
#[derive(Clone, Debug, Default)]
pub(crate) struct BuildState {
    pub(crate) tables: Vec<TableState>,
    /// Every constructor's pattern as its table sees it (true until built).
    pub(crate) ctor_patterns: Vec<TokenPattern>,
    pub(crate) ctors: Vec<Option<CtorResult>>,
    token_names: FxHashMap<u32, String>,
}

impl Compiler<'_> {
    /// `SubtableSymbol::buildPattern`. An error escaping it (from the
    /// common pattern of its constructors) belongs to the constructor
    /// that referred to the table.
    fn build_table(
        &self,
        table: TableId,
        state: &mut BuildState,
        msg: &mut String,
        depth: u32,
    ) -> Result<TokenPattern, EqError> {
        if let Some(p) = state.tables.get(table.slot()).and_then(|t| t.pattern.clone()) {
            return Ok(p);
        }
        if depth > MAX_TABLE_DEPTH {
            return Err(EqError::new("Tables nested too deeply"));
        }
        let Some(data) = self.tables.get(table.slot()) else {
            return Ok(TokenPattern::constant(true));
        };
        let name = self.symbol_text(data.symbol);
        if let Some(t) = state.tables.get_mut(table.slot()) {
            *t = TableState {
                pattern: Some(TokenPattern::constant(true)),
                being_built: true,
                error: false,
            };
        }
        if data.ctors.is_empty() {
            msg.push_str(&format!("Error: There are no constructors in table: {name}\n"));
            if let Some(t) = state.tables.get_mut(table.slot()) {
                t.error = true;
            }
            return Ok(TokenPattern::constant(true));
        }
        let mut common: Option<TokenPattern> = None;
        for &ctor in &data.ctors {
            if let Err(e) = self.build_constructor_pattern(ctor, state, msg, depth) {
                self.explain(ctor, &e, &name, state, msg);
                if let Some(t) = state.tables.get_mut(table.slot()) {
                    t.error = true;
                }
            }
            let mine = state
                .ctor_patterns
                .get(ctor.slot())
                .cloned()
                .unwrap_or_default();
            let next = match &common {
                None => mine,
                Some(acc) => mine.common(acc).map_err(EqError::combine)?,
            };
            if let Some(t) = state.tables.get_mut(table.slot()) {
                t.pattern = Some(next.clone());
            }
            common = Some(next);
        }
        if let Some(t) = state.tables.get_mut(table.slot()) {
            t.being_built = false;
        }
        Ok(common.unwrap_or_default())
    }

    /// Appends Ghidra's explanation of a constructor's failure to `msg`.
    fn explain(
        &self,
        ctor: CtorId,
        error: &EqError,
        table: &str,
        state: &BuildState,
        msg: &mut String,
    ) {
        let line = self.ctors.get(ctor.slot()).map_or(0, |c| c.line);
        let text = match error {
            EqError::Text(t) => t.clone(),
            EqError::Combine(c) => c.message(|tok: Tok| {
                state
                    .token_names
                    .get(&tok.index)
                    .cloned()
                    .unwrap_or_else(|| format!("#{}", tok.index))
            }),
        };
        msg.push_str(&format!(
            "Error: {text}: for table \"{table}\" constructor starting at line {line}\n"
        ));
    }

    /// `buildPatterns`. Returns the state, or `None` if an error was
    /// reported.
    pub(crate) fn build_patterns(&mut self) -> Option<BuildState> {
        let mut state = BuildState {
            tables: vec![TableState::default(); self.tables.len()],
            ctor_patterns: vec![TokenPattern::constant(true); self.ctors.len()],
            ctors: vec![None; self.ctors.len()],
            token_names: self
                .symbols
                .iter()
                .filter_map(|(_, s)| match s.kind {
                    SymbolKind::Token(i) => Some((i, self.text(s.name).to_owned())),
                    _ => None,
                })
                .collect(),
        };
        let mut msg = String::new();
        let before = self.diags.errors();
        if let Err(e) = self.build_table(TableId(0), &mut state, &mut msg, 0) {
            // Ghidra's unrecoverable error; an ordinary error here.
            let text = match e {
                EqError::Text(t) => t,
                EqError::Combine(c) => c.message(|t| format!("#{}", t.index)),
            };
            self.diags.error(None, text);
        }
        if state.tables.first().is_some_and(|t| t.error) {
            self.diags.error(None, msg.clone());
        }
        for (i, table) in self.tables.iter().enumerate().skip(1) {
            let name = self.symbol_text(table.symbol);
            let Some(t) = state.tables.get(i) else {
                continue;
            };
            if t.error {
                let text = format!("Problem in table '{name}':{msg}");
                match table.at {
                    Some(at) => self.diags.error_at(at, text),
                    None => self.diags.error(None, text),
                }
            }
            if t.pattern.is_none() {
                let text = format!("Unreferenced table '{name}'");
                match table.at {
                    Some(at) => self.diags.warning_at(at, text),
                    None => self.diags.warning(None, text),
                }
            }
        }
        (self.diags.errors() == before).then_some(state)
    }
}
