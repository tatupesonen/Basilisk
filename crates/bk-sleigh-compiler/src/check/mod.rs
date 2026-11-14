//! The checks after parsing (`SleighCompile::process`, inventory 9.1, 10 d):
//! NOP constructors, case-insensitive register names, the consistency
//! checker (sizes, truncations, optimisation, temporaries), operand
//! collisions, unreferenced tables, register cross references and the
//! crossbuild shift of unique offsets.

mod collisions;
mod optimize;
mod sizes;
mod truncation;
mod unique;

use rustc_hash::FxHashMap;

use crate::compiler::Compiler;
use crate::ids::{CtorId, ScopeId, SymbolId, TableId};
use crate::spaces::SpaceKind;
use crate::symbols::{SymbolKind, VarnodeData};
use crate::template::Tpl;

/// Unrecoverable error of the checker (Ghidra's uncaught `SleighError`).
#[derive(Clone, Debug)]
pub(crate) struct CheckFatal(pub(crate) String);

impl Compiler<'_> {
    /// Runs the post-parse passes of this half in Ghidra's order. The back
    /// half's `buildPatterns` and `buildDecisionTrees` belong between the
    /// collision check and the register cross references; basilisk's own
    /// reachability stands in for "has a pattern" here.
    pub(crate) fn post_parse(&mut self) {
        self.mark_crossbuild();
        self.check_nops();
        self.check_case_sensitivity();
        if self.default_space.is_none() {
            self.diags.error(None, "No default space specified");
        }
        if self.diags.errors() > 0 {
            return;
        }
        if let Err(CheckFatal(message)) = self.check_consistency() {
            self.diags.error(None, message);
            self.fatal = true;
            return;
        }
        if self.diags.errors() > 0 {
            return;
        }
        self.check_local_collisions();
        if self.diags.errors() > 0 {
            return;
        }
        self.warn_unreferenced_tables();
        if self.diags.errors() > 0 {
            return;
        }
        if !self.check_xrefs() {
            return;
        }
        self.shift_unique_offsets();
    }

    /// Ghidra sets its crossbuild flag while parsing any `crossbuild`.
    fn mark_crossbuild(&mut self) {
        let uses = |tpl: &Tpl| {
            tpl.ops
                .iter()
                .any(|op| op.opcode == crate::template::CROSSBUILD)
        };
        self.crossbuild = self.macro_templates.iter().any(uses)
            || self
                .ctors
                .iter()
                .any(|c| c.main.as_ref().is_some_and(uses) || c.named.iter().flatten().any(uses));
    }

    /// `checkNops`.
    fn check_nops(&mut self) {
        if self.nops.is_empty() {
            return;
        }
        if self.options.warn_all_nops {
            for at in self.nops.clone() {
                self.diags.warning_at(at, "NOP detected");
            }
        }
        let count = self.nops.len();
        self.diags
            .warning(None, format!("{count} NOP constructors found"));
        if !self.options.warn_all_nops {
            self.diags
                .warning(None, "Use -n switch to list each individually");
        }
    }

    /// Ghidra's `Location::format` of a span: `FILE:LINE`.
    pub(crate) fn format_location(&self, at: bk_sleigh_syntax::Span) -> String {
        match self.parsed.sources.locate(at.start) {
            Some(loc) => {
                let file = self.parsed.sources.file(loc.file).map_or("", |f| f.name());
                format!("{file}:{}", loc.line)
            }
            None => String::new(),
        }
    }

    /// `checkCaseSensitivity`.
    fn check_case_sensitivity(&mut self) {
        if !self.options.case_insensitive_duplicates {
            return;
        }
        let mut seen: FxHashMap<String, SymbolId> = FxHashMap::default();
        for id in self
            .symbols
            .scope_symbols_by_name(ScopeId::GLOBAL, &self.names)
        {
            let Some(symbol) = self.symbols.get(id) else {
                continue;
            };
            let SymbolKind::Varnode(vn) = &symbol.kind else {
                continue;
            };
            let processor = self
                .spaces
                .get(vn.space as usize)
                .is_some_and(|s| s.kind == SpaceKind::Processor);
            if !processor {
                continue;
            }
            let name = self.text(symbol.name).to_owned();
            let upper = name.to_ascii_uppercase();
            if let Some(&old) = seen.get(&upper) {
                let old_symbol = self.symbols.get(old);
                let old_name = old_symbol.map_or("", |s| self.text(s.name)).to_owned();
                let mut message = format!("Name collision: {name} --- Duplicate symbol {old_name}");
                if let Some(at) = old_symbol.and_then(|s| s.defined_at) {
                    message.push_str(" defined at ");
                    message.push_str(&self.format_location(at));
                }
                let at = symbol.defined_at;
                match at {
                    Some(at) => self.diags.error_at(at, message),
                    None => self.diags.error(None, message),
                }
            } else {
                seen.insert(upper, id);
            }
        }
    }

    /// The tables reachable from `instruction` through operands defined by
    /// tables: exactly the tables Ghidra's `buildPatterns` gives a pattern
    /// when it succeeds.
    pub(crate) fn reachable_tables(&self) -> Vec<bool> {
        let mut reached = vec![false; self.tables.len()];
        let mut work = vec![TableId(0)];
        if let Some(r) = reached.first_mut() {
            *r = true;
        }
        while let Some(table) = work.pop() {
            let Some(t) = self.tables.get(table.slot()) else {
                continue;
            };
            for &ctor in &t.ctors {
                for sub in self.subtable_operands_of(ctor) {
                    if let Some(r) = reached.get_mut(sub.slot())
                        && !*r
                    {
                        *r = true;
                        work.push(sub);
                    }
                }
            }
        }
        reached
    }

    /// The tables defining the operands of a constructor, in operand order.
    pub(crate) fn subtable_operands_of(&self, ctor: CtorId) -> Vec<TableId> {
        let Some(c) = self.ctors.get(ctor.slot()) else {
            return Vec::new();
        };
        c.operands
            .iter()
            .filter_map(|op| self.operands.get(op.slot())?.def_symbol)
            .filter_map(|s| match self.kind(s) {
                Some(SymbolKind::Subtable(t)) => Some(*t),
                _ => None,
            })
            .collect()
    }

    /// The "Unreferenced table" warnings of `buildPatterns`.
    fn warn_unreferenced_tables(&mut self) {
        let reached = self.reachable_tables();
        for (i, table) in self.tables.iter().enumerate().skip(1) {
            if reached.get(i).copied().unwrap_or(false) {
                continue;
            }
            let name = self
                .symbols
                .get(table.symbol)
                .map_or("", |s| self.names.resolve(s.name));
            let message = format!("Unreferenced table '{name}'");
            match table.at {
                Some(at) => self.diags.warning_at(at, message),
                None => self.diags.warning(None, message),
            }
        }
    }

    /// `buildXrefs`: two registers may not share (space, offset, size).
    fn check_xrefs(&mut self) -> bool {
        let mut seen: FxHashMap<VarnodeData, SymbolId> = FxHashMap::default();
        let mut pairs = Vec::new();
        for id in self
            .symbols
            .scope_symbols_by_name(ScopeId::GLOBAL, &self.names)
        {
            let Some(symbol) = self.symbols.get(id) else {
                continue;
            };
            if let SymbolKind::Varnode(vn) = symbol.kind {
                match seen.get(&vn) {
                    Some(&old) => pairs.push((id, old)),
                    None => {
                        seen.insert(vn, id);
                    }
                }
            }
        }
        if pairs.is_empty() {
            return true;
        }
        for (a, b) in pairs {
            let name = |id: SymbolId| {
                self.symbols
                    .get(id)
                    .map_or("", |s| self.names.resolve(s.name))
                    .to_owned()
            };
            let message = format!(
                "Duplicate (offset,size) pair for registers: {} and {}\n",
                name(a),
                name(b)
            );
            self.diags.error(None, message);
        }
        false
    }
}
